#!/bin/bash
set -e

# ====== Key File Paths ======
SITES_FILE="/etc/bind/zones/sites.list"
ZONES_FILE="/etc/bind/zones/blocklist.zones"
NAMED_OPTIONS="/etc/bind/named.conf.options"
NAMED_CONF="/etc/bind/named.conf"
NAMED_CONF_LOCAL="/etc/bind/named.conf.local"
ZONES_DIR="/etc/bind/zones"
DOH_CONF="/etc/dns-over-https/doh-server.conf"

if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'; MAGENTA='\033[0;35m'; CYAN='\033[0;36m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''; MAGENTA=''; CYAN='';
fi

print_error() { echo -e "${RED}ERROR: $1${NC}"; }
print_info()  { echo -e "${GREEN}INFO: $1${NC}"; }
print_warn()  { echo -e "${YELLOW}WARNING: $1${NC}"; }

# ====== Go Version Check and Install ======
check_and_install_go() {
  REQUIRED_MAJOR=1
  REQUIRED_MINOR=24
  REQUIRED_PATCH=0

  if ! command -v go >/dev/null 2>&1; then
    print_warn "Go is not installed. Installing Go 1.24.0 ..."
    install_go
    return
  fi

  GOVERSION=$(go version 2>/dev/null | awk '{print $3}') # e.g. go1.23.5
  GOVERSION=${GOVERSION#go}
  IFS='.' read -r MAJOR MINOR PATCH <<<"$GOVERSION"
  PATCH=${PATCH:-0}

  if [ "$MAJOR" -lt "$REQUIRED_MAJOR" ] || { [ "$MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$MINOR" -lt "$REQUIRED_MINOR" ]; } || { [ "$MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$MINOR" -eq "$REQUIRED_MINOR" ] && [ "$PATCH" -lt "$REQUIRED_PATCH" ]; }; then
    print_warn "Go version is $GOVERSION, but >=1.24.0 is required. Installing latest Go ..."
    install_go
  else
    print_info "Go version $GOVERSION is sufficient."
  fi
}

install_go() {
  ARCH=$(uname -m)
  if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
    GOARCH="amd64"
  elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    GOARCH="arm64"
  else
    print_error "Unsupported architecture: $ARCH"
    exit 1
  fi

  GO_VERSION="1.24.0"
  GO_TARBALL="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
  GO_URL="https://go.dev/dl/${GO_TARBALL}"

  TMPDIR=$(mktemp -d)
  print_info "Downloading $GO_URL ..."
  wget -qO "$TMPDIR/$GO_TARBALL" "$GO_URL"

  print_info "Removing any previous Go installation ..."
  sudo rm -rf /usr/local/go

  print_info "Extracting Go $GO_VERSION ..."
  sudo tar -C /usr/local -xzf "$TMPDIR/$GO_TARBALL"

  export PATH="/usr/local/go/bin:$PATH"
  if ! grep -q '/usr/local/go/bin' ~/.profile 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
  fi

  rm -rf "$TMPDIR"

  print_info "Go $(go version) installed and ready."
}

# ====== Disk Space Check ======
check_disk_space() {
  for mount in / /etc /var; do
    local avail=$(df "$mount" | tail -1 | awk '{print $4}')
    if [ "$avail" -lt 100000 ]; then
      print_error "Not enough disk space on $mount. At least 100MB required."
      exit 1
    fi
  done
}

# ====== Input Validation Functions ======
validate_domain() {
  [[ "$1" =~ ^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$ ]]
}
validate_email() {
  [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

# ====== BIND Service Detection and Status ======
detect_bind_service() {
  if systemctl list-unit-files | grep -q "named.service"; then
    SERVICE_BIND="named"
  elif systemctl list-unit-files | grep -q "bind9.service"; then
    SERVICE_BIND="bind9"
  else
    print_error "Could not detect BIND service. Make sure BIND is installed."
    exit 1
  fi
}
service_exists() {
  systemctl list-units --full -all | grep -Fq "$1.service"
}
service_status() {
  local name="$1"
  if ! service_exists "$name"; then
    echo -e "${YELLOW}Not Installed${NC}"
    return
  fi
  local active=$(systemctl is-active "$name" 2>/dev/null)
  local enabled=$(systemctl is-enabled "$name" 2>/dev/null)
  echo -e "${CYAN}$name:${NC} Status: $active | Enabled: $enabled"
}
check_service_running() {
  local name="$1"
  if ! service_exists "$name"; then
    print_error "Service $name is not installed."
    return 1
  fi
  if ! systemctl is-active --quiet "$name"; then
    print_error "Service $name is not running."
    return 1
  fi
  return 0
}
check_internet() {
  print_info "Checking internet connectivity..."
  if ! ping -c 1 1.1.1.1 >/dev/null 2>&1 && ! ping6 -c 1 2606:4700:4700::1111 >/dev/null 2>&1; then
    print_error "No internet connection detected. Please check your network."
    exit 1
  fi
  print_info "Internet connectivity OK."
}
detect_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    echo "ufw"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewalld"
  elif command -v iptables >/dev/null 2>&1; then
    echo "iptables"
  else
    echo "none"
  fi
}
open_ports() {
  local ports=("22" "53" "80" "443" "8053")
  local fw=$(detect_firewall)
  if [ "$fw" = "ufw" ]; then
    if ! sudo ufw status | grep -q "active"; then
      echo "ufw is installed but not active. Please enable it manually if you want firewall rules managed automatically."
    fi
    for port in "${ports[@]}"; do
      if ! ss -tuln | grep -q ":$port "; then
        sudo ufw allow "$port"
      fi
    done
  elif [ "$fw" = "firewalld" ]; then
    print_info "Detected firewalld. Please open required ports (22,53,80,443,8053) manually."
  elif [ "$fw" = "iptables" ]; then
    print_info "Detected iptables. Please open required ports (22,53,80,443,8053) manually."
  else
    print_info "No firewall detected. Please ensure required ports (22,53,80,443,8053) are open."
  fi
}

prompt_backup() {
  read -p "Would you like to back up important configuration files before proceeding? (y/n) " choice
  case "$choice" in
    y|Y ) backup_configs;;
    * ) ;;
  esac
}
backup_configs() {
  sudo cp "$NAMED_CONF_LOCAL" "$NAMED_CONF_LOCAL.bak" 2>/dev/null || true
  sudo cp "$NAMED_OPTIONS" "$NAMED_OPTIONS.bak" 2>/dev/null || true
}

reset_everything() {
  prompt_backup
  print_info "Resetting: Only files created by this script will be removed."

  sudo systemctl stop nginx doh-server bind9 named 2>/dev/null || true
  sudo systemctl disable bind9 named 2>/dev/null || true

  sudo rm -f /etc/nginx/sites-available/doh_dns_* /etc/nginx/sites-enabled/doh_dns_*
  sudo rm -f /etc/nginx/sites-enabled/default
  for f in /etc/nginx/sites-enabled/*; do
    [ -f "$f" ] || continue
    if grep -q "listen 443" "$f"; then
      sudo rm -f "$f"
    fi
  done
  for f in /etc/nginx/conf.d/*.conf /etc/nginx/conf.d/*.conf.bak; do
    [ -f "$f" ] || continue
    if grep -q "listen 443" "$f"; then
      sudo rm -f "$f"
    fi
  done

  sudo rm -rf "$ZONES_DIR"
  sudo rm -f /usr/local/bin/doh-server /etc/systemd/system/doh-server.service
  sudo rm -rf /etc/dns-over-https

  if [ -f "$SITES_FILE" ]; then
    mapfile -t domains < "$SITES_FILE"
    for d in "${domains[@]}"; do
      sudo rm -rf "/etc/letsencrypt/live/$d" "/etc/letsencrypt/archive/$d" "/etc/letsencrypt/renewal/$d.conf"
    done
  fi
  sudo rm -rf /var/log/letsencrypt
  sudo rm -f "$SITES_FILE"

  if [ -f "$NAMED_CONF_LOCAL" ]; then
    sudo sed -i '/blocklist\.zones/d' "$NAMED_CONF_LOCAL"
    sudo sed -i '/zone.*{/,/};/d' "$NAMED_CONF_LOCAL"
  fi

  sudo mkdir -p "$ZONES_DIR"
  sudo touch "$ZONES_FILE"

  sudo systemctl daemon-reload
  sudo systemctl restart networking 2>/dev/null || true
  sudo systemctl start nginx 2>/dev/null || true

  print_info "Full reset complete. All configs, services, certs, and server blocks for DoH/BIND/nginx are removed."
}

# ====== Website List Management ======
read_sites() {
  if [ -f "$SITES_FILE" ]; then
    mapfile -t sites < "$SITES_FILE"
  else
    sites=("${DEFAULT_SITES[@]}")
  fi
}
show_sites() {
  read_sites
  if [ ${#sites[@]} -eq 0 ]; then
    echo -e "${YELLOW}No sites found.${NC}"
  else
    echo -e "${CYAN}Blocked Sites:${NC}"
    for s in "${sites[@]}"; do
      echo " - $s"
    done
  fi
}
add_site() {
  while true; do
    read -rp "Enter domain to add: " domain
    if validate_domain "$domain"; then break; else print_error "Invalid domain format."; fi
  done
  read_sites
  if [[ " ${sites[*]} " == *" $domain "* ]]; then
    echo -e "${YELLOW}Domain already exists.${NC}"
  else
    sudo mkdir -p "$ZONES_DIR"
    local lock="$SITES_FILE.lock"
    TMPFILES+=("$lock")
    (
      flock -x 200
      echo "$domain" >> "$SITES_FILE"
    ) 200>"$lock"
    sites+=("$domain")
    update_zones
    echo -e "${GREEN}Domain added.${NC}"
  fi
}
remove_site() {
  while true; do
    read -rp "Enter domain to remove: " domain
    if validate_domain "$domain"; then break; else print_error "Invalid domain format."; fi
  done
  read_sites
  if [[ ! " ${sites[*]} " == *" $domain "* ]]; then
    echo -e "${YELLOW}Domain not found.${NC}"
  else
    local lock="$SITES_FILE.lock"
    TMPFILES+=("$lock")
    (
      flock -x 200
      grep -vxF "$domain" "$SITES_FILE" > "${SITES_FILE}.tmp" && mv "${SITES_FILE}.tmp" "$SITES_FILE"
    ) 200>"$lock"
    read_sites
    update_zones
    echo -e "${GREEN}Domain removed.${NC}"
  fi
}

install_prerequisites() {
  print_info "Installing prerequisite tools..."
  apt update || { print_error "Failed to update package lists."; exit 1; }
  apt install -y curl wget dnsutils iproute2 net-tools || {
    print_error "Failed to install prerequisite tools."; exit 1;
  }
  for cmd in curl wget dig ip; do
    if ! command -v $cmd &> /dev/null; then
      print_error "$cmd failed to install. Please check your repositories and internet connection."
      exit 1
    fi
  done
  if ! command -v ufw &> /dev/null; then
    apt install -y ufw || { print_error "Failed to install ufw."; exit 1; }
    if ! command -v ufw &> /dev/null; then
      print_error "ufw failed to install."
      exit 1
    fi
  fi
  print_info "Prerequisite tools installed."
}
check_make() {
  if ! command -v make &> /dev/null; then
    print_info "make not found. Installing make..."
    apt update || { print_error "Failed to update package lists."; exit 1; }
    apt install -y make || { print_error "Failed to install make."; exit 1; }
    if ! command -v make &> /dev/null; then
      print_error "make failed to install."
      exit 1
    fi
    print_info "make installed successfully."
  fi
}
install_dependencies() {
  print_info "Updating and installing dependencies..."
  apt update || { print_error "Failed to update package lists."; exit 1; }
  apt install -y bind9 bind9utils bind9-doc nginx certbot python3-certbot-nginx wget jq unzip dnsutils ufw || {
    print_error "Failed to install dependencies."; exit 1;
  }
  for pkg in bind9 nginx certbot ufw; do
    if ! dpkg -l | grep -qw "$pkg"; then
      print_error "$pkg failed to install."
      exit 1
    fi
  done
  print_info "All dependencies installed and verified."
}

check_zone_conflict() {
  local domain="$1"
  local found=$(grep -r "zone \"$domain\"" /etc/bind/ 2>/dev/null | grep -v blocklist.zones || true)
  if [ -n "$found" ]; then
    print_error "Zone for $domain already exists in BIND configuration:"
    echo "$found"
    return 1
  fi
  return 0
}
install_bind() {
  read_sites
  for domain in "${sites[@]}"; do
    if ! check_zone_conflict "$domain"; then
      print_error "Zone conflict detected for $domain. Please remove conflicting zones from BIND configs before proceeding."
      exit 1
    fi
  done
  install_dependencies
  detect_bind_service
  if ! command -v named-checkconf &> /dev/null; then
    print_error "named-checkconf failed to install."
    exit 1
  fi
  sudo mkdir -p "$ZONES_DIR"
  sudo touch "$ZONES_FILE"
  if ! sudo named-checkconf "$NAMED_CONF"; then
    print_error "BIND configuration syntax error. Please fix your configs."
    exit 1
  fi
  print_info "Restarting BIND service..."
  restart_bind
  check_service_running "$SERVICE_BIND" || exit 1
}
uninstall_bind() {
  print_info "Removing BIND..."
  systemctl stop "$SERVICE_BIND" || true
  apt purge -y bind9 bind9utils bind9-doc
  print_info "BIND removed."
}

install_nginx() {
  print_info "Checking for existing Nginx configuration conflicts..."
  apt install -y nginx certbot python3-certbot-nginx
  for pkg in nginx certbot; do
    if ! dpkg -l | grep -qw "$pkg"; then
      print_error "$pkg failed to install."
      exit 1
    fi
  done
  systemctl enable nginx
  check_service_running nginx || exit 1
}

# ====== SSL Certificate Logic (Smart) ======
obtain_ssl_certificate() {
  local DOMAIN="$1"
  local EMAIL="$2"
  local CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  local KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

  # Always use port 443, forcibly free it if needed
  if ss -tuln | grep -q ":443 "; then
    print_warn "Port 443 is in use. Attempting to stop possible conflicting services..."
    for svc in nginx apache2 httpd lighttpd caddy haproxy; do
      if systemctl is-active --quiet $svc; then
        print_warn "Stopping $svc to free port 443."
        systemctl stop $svc || true
      fi
    done
    sleep 1
    if ss -tuln | grep -q ":443 "; then
      print_error "Port 443 is still in use after stopping common web servers. Please free port 443 and re-run the script."
      exit 1
    fi
  fi

  # Step 1: Create temporary HTTP server block for certbot
  local TEMP_CONF="/etc/nginx/sites-available/doh_dns_$DOMAIN"
  sudo tee "$TEMP_CONF" > /dev/null << EOF
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        return 404;
    }
}
EOF
  sudo ln -sf "$TEMP_CONF" /etc/nginx/sites-enabled/doh_dns_$DOMAIN
  sudo nginx -t
  sudo systemctl reload nginx

  # Step 2: Obtain certificate
  print_info "Obtaining SSL certificate on port 80 with certbot nginx plugin."
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" > /tmp/certbot.log 2>&1 || {
    print_error "Failed to obtain SSL certificate using nginx plugin. See /tmp/certbot.log"
    exit 1
  }

  if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    print_error "SSL certificate was not created."
    exit 1
  fi
}

setup_nginx_ssl() {
  local DOMAIN="$1"
  local EMAIL="$2"
  local NGINX_CONF="/etc/nginx/sites-available/doh_dns_$DOMAIN"
  local NGINX_LINK="/etc/nginx/sites-enabled/doh_dns_$DOMAIN"
  local PORT=443

  print_info "Checking if domain $DOMAIN resolves to this server's IP..."
  SERVER_IP=$(curl -s -4 ifconfig.me || wget -qO- -4 ipinfo.io/ip)
  [ -z "$SERVER_IP" ] && SERVER_IP=$(curl -s -6 ifconfig.me || wget -qO- -6 ipinfo.io/ip)
  if [ -z "$SERVER_IP" ]; then
    print_error "Could not determine server IP (IPv4/IPv6)."
    exit 1
  fi
  DOMAIN_IP=$(dig +short "$DOMAIN" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -1)
  [ -z "$DOMAIN_IP" ] && DOMAIN_IP=$(dig +short AAAA "$DOMAIN" | head -1)
  if [ "$DOMAIN_IP" != "$SERVER_IP" ]; then
    print_warn "Domain $DOMAIN resolves to $DOMAIN_IP, but server IP is $SERVER_IP."
    read -p "Continue anyway? [y/N]: " cont
    [[ "$cont" =~ ^[Yy]$ ]] || exit 1
  fi

  # ====== Remove ALL conflicting nginx server blocks on port 443 ======
  print_info "Removing all conflicting nginx server blocks on port 443..."
  sudo rm -f /etc/nginx/sites-enabled/default
  for f in /etc/nginx/sites-enabled/*; do
    [ -f "$f" ] || continue
    if grep -q "listen 443" "$f"; then
      sudo rm -f "$f"
    fi
  done
  for f in /etc/nginx/conf.d/*.conf /etc/nginx/conf.d/*.conf.bak; do
    [ -f "$f" ] || continue
    if grep -q "listen 443" "$f"; then
      sudo rm -f "$f"
    fi
  done

  # ====== Disable include conf.d in nginx.conf (to prevent conflicts) ======
  if grep -q "include /etc/nginx/conf.d/\*.conf;" /etc/nginx/nginx.conf; then
    sudo sed -i 's|include /etc/nginx/conf.d/\*.conf;|# include /etc/nginx/conf.d/*.conf;|g' /etc/nginx/nginx.conf
  fi

  # ====== Create temporary HTTP server block for certbot ======
  sudo tee "$NGINX_CONF" > /dev/null << EOF
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        return 404;
    }
}
EOF
  sudo ln -sf "$NGINX_CONF" "$NGINX_LINK"
  sudo nginx -t
  sudo systemctl reload nginx

  # ====== Run certbot to obtain SSL certificate ======
  print_info "Obtaining SSL certificate on port 80 with certbot nginx plugin."
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" > /tmp/certbot.log 2>&1 || {
    print_error "Failed to obtain SSL certificate using nginx plugin. See /tmp/certbot.log"
    exit 1
  }

  # ====== Now check for existence of SSL certificate files ======
  if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] || [ ! -f "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ]; then
    print_error "SSL certificate or key missing for $DOMAIN after certbot. Something went wrong!"
    exit 1
  fi

  # ====== Write final SSL server block ======
  sudo tee "$NGINX_CONF" > /dev/null << EOF
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    location /dns-query {
        proxy_pass http://127.0.0.1:8053/dns-query;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass_request_headers on;
        autoindex off;
    }
}
EOF
  sudo ln -sf "$NGINX_CONF" "$NGINX_LINK"
  sudo nginx -t
  sudo systemctl reload nginx
  print_info "Nginx SSL config for $DOMAIN is ready and active."
}


uninstall_nginx() {
  print_info "Removing Nginx and DoH configs..."
  systemctl stop nginx || true
  rm -f /etc/nginx/sites-available/doh_dns_* /etc/nginx/sites-enabled/doh_dns_*
  apt purge -y nginx certbot python3-certbot-nginx
  print_info "Nginx removed."
}

install_doh_server() {
  check_make
  check_and_install_go
  if ! command -v git &> /dev/null; then
    print_info "git not found. Installing git..."
    apt update
    apt install -y git || { print_error "Failed to install git."; exit 1; }
    if ! command -v git &> /dev/null; then
      print_error "git failed to install."
      exit 1
    fi
  fi
  TMPDIR=$(mktemp -d)
  TMPFILES+=("$TMPDIR")
  git clone --depth=1 https://github.com/m13253/dns-over-https.git "$TMPDIR/dns-over-https"
  cd "$TMPDIR/dns-over-https"
  make doh-server/doh-server
  if [ ! -f doh-server/doh-server ]; then
    print_error "doh-server binary build failed."
    exit 1
  fi
  sudo cp doh-server/doh-server /usr/local/bin/doh-server
  sudo chmod +x /usr/local/bin/doh-server
  if ! command -v doh-server &> /dev/null; then
    print_error "doh-server binary copy failed."
    exit 1
  fi
  cd /
  print_info "doh-server installed."
}

uninstall_doh_server() {
  print_info "Removing DoH server..."
  systemctl stop doh-server || true
  rm -f /usr/local/bin/doh-server /etc/systemd/system/doh-server.service
  sudo rm -rf /etc/dns-over-https
  print_info "DoH server removed."
}

setup_doh_service() {
  local DOMAIN="$1"
  sudo mkdir -p /etc/dns-over-https
  sudo tee /etc/dns-over-https/doh-server.conf > /dev/null <<EOF
listen = [ "127.0.0.1:8053" ]
cert = "/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
key = "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
path = "/dns-query"
upstream = [ "udp:127.0.0.1:53" ]
timeout = 10
tries = 3
verbose = false
EOF

  sudo tee /etc/systemd/system/doh-server.service > /dev/null << EOF
[Unit]
Description=DNS over HTTPS server (m13253)
After=network.target

[Service]
ExecStart=/usr/local/bin/doh-server -conf /etc/dns-over-https/doh-server.conf
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl restart doh-server
  sleep 2

  if ! ss -tuln | grep -q "127.0.0.1:8053"; then
    print_error "doh-server is NOT listening on 127.0.0.1:8053. Check doh-server logs with: journalctl -u doh-server -n 30"
    exit 1
  fi
  print_info "doh-server is running and listening on 127.0.0.1:8053"
}

setup_bind_forwarders() {
  sudo mkdir -p "$ZONES_DIR"
  sudo sed -i '/listen-on port/d' "$NAMED_OPTIONS"
  sudo sed -i '/listen-on-v6 port/d' "$NAMED_OPTIONS"
  if ! grep -q "forwarders {" "$NAMED_OPTIONS"; then
    cat >> "$NAMED_OPTIONS" << EOF
options {
  directory "/var/cache/bind";
  forwarders { 1.1.1.1; 8.8.8.8; };
  forward only;
  dnssec-validation auto;
  auth-nxdomain no;
  listen-on port 53 { any; };
  listen-on-v6 port 53 { any; };
  allow-query { any; };
};
EOF
  else
    sed -i "/listen-on {/a\    listen-on port 53 { any; };" "$NAMED_OPTIONS"
    sed -i "/listen-on-v6 {/a\    listen-on-v6 port 53 { any; };" "$NAMED_OPTIONS"
  fi
}
setup_bind_zones() {
  sudo mkdir -p "$ZONES_DIR"
  sudo touch "$ZONES_FILE"
  echo "// Zones for forwarding blocked domains" | sudo tee "$ZONES_FILE" > /dev/null
  read_sites
  local lock="$ZONES_FILE.lock"
  TMPFILES+=("$lock")
  (
    flock -x 200
    for domain in "${sites[@]}"; do
      cat << EOF | sudo tee -a "$ZONES_FILE" > /dev/null

zone "$domain" {
  type forward;
  forward only;
  forwarders { 1.1.1.1; 8.8.8.8; };
};
EOF
    done
  ) 200>"$lock"
}
update_zones() {
  sudo mkdir -p "$ZONES_DIR"
  sudo touch "$ZONES_FILE"
  echo "// Zones for forwarding blocked domains" | sudo tee "$ZONES_FILE" > /dev/null
  read_sites
  local lock="$ZONES_FILE.lock"
  TMPFILES+=("$lock")
  (
    flock -x 200
    for domain in "${sites[@]}"; do
      cat << EOF | sudo tee -a "$ZONES_FILE" > /dev/null

zone "$domain" {
  type forward;
  forward only;
  forwarders { 1.1.1.1; 8.8.8.8; };
};
EOF
    done
  ) 200>"$lock"
  check_bind_config
  restart_bind
}
update_named_conf() {
  if ! grep -q "include \"$ZONES_FILE\";" "$NAMED_CONF_LOCAL"; then
    echo "include \"$ZONES_FILE\";" | sudo tee -a "$NAMED_CONF_LOCAL"
  fi
}
check_bind_config() {
  if ! named-checkconf "$NAMED_CONF"; then
    print_error "BIND configuration syntax error."
    exit 1
  fi
}
restart_bind() {
  if systemctl list-unit-files | grep -q "named.service"; then
    systemctl restart named || { print_error "Failed to restart named."; exit 1; }
    systemctl enable named || print_warn "Could not enable named.service (may already be enabled)."
    SERVICE_BIND="named"
  elif systemctl list-unit-files | grep -q "bind9.service"; then
    systemctl restart bind9 || { print_error "Failed to restart bind9."; exit 1; }
    systemctl enable named || print_warn "Could not enable named.service (may already be enabled)."
    SERVICE_BIND="bind9"
  else
    print_error "Neither named.service nor bind9.service found."
    exit 1
  fi
}

test_dns_forwarding() {
  print_info "Testing DNS forwarding for a sample domain..."
  if ! command -v dig &> /dev/null; then
    print_error "dig not found. Skipping DNS test."
    return
  fi
  read_sites
  test_domain="${sites[0]}"
  if [ -z "$test_domain" ]; then
    print_error "No domains available for testing. Skipping DNS test."
    return
  fi
  if dig @"127.0.0.1" -p 53 "$test_domain" A +short | grep -q .; then
    print_info "DNS forwarding test passed for $test_domain."
  else
    print_error "DNS forwarding test failed for $test_domain."
    exit 1
  fi
}
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
  fi
}

install_service() {
  check_root
  check_disk_space
  check_internet
  detect_bind_service
  while true; do
    read -rp "Enter your domain (e.g. dns.example.com): " DOMAIN
    if validate_domain "$DOMAIN"; then break; else print_error "Invalid domain format."; fi
  done
  while true; do
    read -rp "Enter your email for Let's Encrypt SSL cert: " EMAIL
    if validate_email "$EMAIL"; then break; else print_error "Invalid email format."; fi
  done
  if [ ! -f "$SITES_FILE" ]; then
    sudo mkdir -p "$ZONES_DIR"
    for s in "${DEFAULT_SITES[@]}"; do
      echo "$s" | sudo tee -a "$SITES_FILE" > /dev/null
    done
  fi
  install_prerequisites
  open_ports
  install_bind
  setup_bind_forwarders
  setup_bind_zones
  update_named_conf
  check_bind_config
  restart_bind
  install_nginx
  setup_nginx_ssl "$DOMAIN" "$EMAIL"
  install_doh_server
  setup_doh_service "$DOMAIN"
  test_dns_forwarding
  echo
  echo -e "${GREEN}=============================================="
  echo -e "  Your DNS-over-HTTPS (DoH) URL for clients:"
  echo -e "${CYAN}  https://$DOMAIN/dns-query"
  echo -e "${GREEN}==============================================${NC}"
  echo "Add this link in your browser, Secure DNS Client, Android Private DNS, or any DoH-compatible app."
  echo
}
uninstall_service() {
  check_root
  detect_bind_service
  uninstall_bind
  uninstall_nginx
  uninstall_doh_server
  print_info "All services uninstalled. Some configuration files may remain; remove them manually if needed."
}
check_if_installed() {
  if [ -f "$SITES_FILE" ] && \
     systemctl is-active --quiet "$SERVICE_BIND" && \
     systemctl is-active --quiet nginx && \
     systemctl is-active --quiet doh-server; then
    return 0
  else
    return 1
  fi
}

TMPFILES=()
cleanup() {
  for f in "${TMPFILES[@]}"; do
    [ -e "$f" ] && rm -rf "$f"
  done
}
trap cleanup EXIT

DEFAULT_SITES=("youtube.com" "instagram.com" "facebook.com" "telegram.org" "twitter.com" "t.me" "discord.com" "spotify.com")
SERVICE_BIND=""
SERVICE_DOH="doh-server"

main_menu() {
  while true; do
    clear
    echo -e "${MAGENTA}[Service Status]${NC}"
    service_status "$SERVICE_BIND"
    service_status "nginx"
    service_status "$SERVICE_DOH"
    echo -e "${MAGENTA}*****************************"
    echo -e "*     SMART DNS PROXY       *"
    echo -e "*****************************${NC}"
    echo -e "${YELLOW} 1)${NC} Install"
    echo -e "${YELLOW} 2)${NC} Uninstall"
    echo -e "${YELLOW} 3)${NC} Show Websites"
    echo -e "${YELLOW} 4)${NC} Add Sites"
    echo -e "${YELLOW} 5)${NC} Remove Sites"
    echo -e "${YELLOW} 9)${NC} Full Reset (Danger!)"
    echo -e "${YELLOW} 0)${NC} Exit"
    echo -e "${MAGENTA}*****************************${NC}"
    read -rp "$(echo -e "${CYAN}Enter your choice: ${NC}")" choice
    case "$choice" in
      1) install_service; read -n1 -r -p "Press any key to continue..." ;;
      2) uninstall_service; read -n1 -r -p "Press any key to continue..." ;;
      3) show_sites; read -n1 -r -p "Press any key to continue..." ;;
      4) add_site; read -n1 -r -p "Press any key to continue..." ;;
      5) remove_site; read -n1 -r -p "Press any key to continue..." ;;
      9) echo -e "${RED}WARNING: This will delete all configs, zones, certs, and services!${NC}"; read -rp "Are you sure? (yes/no): " ans; if [ "$ans" == "yes" ]; then reset_everything; read -n1 -r -p "Press any key to continue..."; fi ;;
      0) echo "Bye!"; exit 0 ;;
      *) echo -e "${RED}Invalid choice!${NC}"; sleep 1 ;;
    esac
  done
}

detect_bind_service
if check_if_installed; then
  main_menu
else
  install_service
  main_menu
fi