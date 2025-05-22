#!/bin/bash
set -e

# ====== Output colors ======
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'; MAGENTA='\033[0;35m'; CYAN='\033[0;36m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''; MAGENTA=''; CYAN='';
fi

# ====== Utility Functions ======
print_error() { echo -e "${RED}ERROR: $1${NC}"; }
print_info()  { echo -e "${GREEN}INFO: $1${NC}"; }
print_warn()  { echo -e "${YELLOW}WARNING: $1${NC}"; }

# ====== Non-interactive shell check ======
if ! [ -t 0 ]; then
  print_error "This script must be run in an interactive shell."
  exit 1
fi

# ====== Check for apt ======
if ! command -v apt &> /dev/null; then
  print_error "This script only supports Debian/Ubuntu systems with apt package manager."
  exit 1
fi

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

# ====== Validation Functions ======
validate_domain() {
  [[ "$1" =~ ^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$ ]]
}
validate_email() {
  [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

# ====== Service Detection & Status ======
detect_bind_service() {
  if systemctl list-unit-files | grep -q "bind9.service"; then
    SERVICE_BIND="bind9"
  elif systemctl list-unit-files | grep -q "named.service"; then
    SERVICE_BIND="named"
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

# ====== Internet Connectivity Check ======
check_internet() {
  print_info "Checking internet connectivity..."
  if ! ping -c 1 1.1.1.1 >/dev/null 2>&1 && ! ping6 -c 1 2606:4700:4700::1111 >/dev/null 2>&1; then
    print_error "No internet connection detected. Please check your network."
    exit 1
  fi
  print_info "Internet connectivity OK."
}

# ====== Port Checking & Firewall ======
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
check_port_usage() {
  local port=$1
  if ss -tuln | grep -q ":${port} "; then
    print_error "Port $port is already in use. Please resolve the conflict before proceeding."
    exit 1
  fi
}

check_all_ports() {
  for port in 53 80 443 8053; do
    check_port_usage "$port"
  done
}

# ====== Backup & Reset ======
prompt_backup() {
  read -p "Would you like to back up important configuration files before proceeding? (y/n) " choice
  case "$choice" in
    y|Y ) backup_configs;;
    * ) ;;
  esac
}
backup_configs() {
  sudo cp /etc/bind/named.conf.local /etc/bind/named.conf.local.bak 2>/dev/null || true
  sudo cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak 2>/dev/null || true
}
reset_everything() {
  prompt_backup
  print_info "Resetting: Only files created by this script will be removed."
  sudo systemctl stop nginx doh-server "$SERVICE_BIND" 2>/dev/null || true
  sudo rm -f /etc/nginx/sites-available/doh_dns_* /etc/nginx/sites-enabled/doh_dns_*
  sudo rm -rf /etc/bind/zones
  sudo rm -f /usr/local/bin/doh-server /etc/systemd/system/doh-server.service
  if [ -f "$SITES_FILE" ]; then
    mapfile -t domains < "$SITES_FILE"
    for d in "${domains[@]}"; do
      sudo rm -rf "/etc/letsencrypt/live/$d" "/etc/letsencrypt/archive/$d" "/etc/letsencrypt/renewal/$d.conf"
    done
  fi
  sudo rm -rf /var/log/letsencrypt
  sudo rm -f "$SITES_FILE"
  sudo systemctl daemon-reload
  sudo systemctl restart networking 2>/dev/null || true
  sudo systemctl start nginx 2>/dev/null || true
  print_info "Reset complete. Main system files are not deleted."
}

# ====== Site Management ======
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

# ====== Dependency Installation with Verification ======
install_prerequisites() {
  print_info "Installing prerequisite tools..."
  apt update || { print_error "Failed to update package lists."; exit 1; }
  apt install -y curl wget dnsutils iproute2 net-tools || {
    print_error "Failed to install prerequisite tools."; exit 1;
  }
  for cmd in curl wget dig ip addr; do
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

# ====== BIND Management ======
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
  print_info "Restarting BIND service..."
  systemctl restart "$SERVICE_BIND" || { print_error "Failed to restart BIND."; exit 1; }
  systemctl enable "$SERVICE_BIND"
  check_service_running "$SERVICE_BIND" || exit 1
}
uninstall_bind() {
  print_info "Removing BIND..."
  systemctl stop "$SERVICE_BIND" || true
  apt purge -y bind9 bind9utils bind9-doc
  print_info "BIND removed."
}

# ====== Nginx & SSL Management ======
nginx_domain_conflict() {
  local domain="$1"
  local port="$2"
  for conf in /etc/nginx/sites-enabled/*; do
    [ -f "$conf" ] || continue
    if grep -q "server_name.*$domain" "$conf" && grep -q "listen $port" "$conf"; then
      echo "$conf"
      return 0
    fi
  done
  return 1
}
nginx_port_conflict() {
  local port="$1"
  for conf in /etc/nginx/sites-enabled/*; do
    [ -f "$conf" ] || continue
    if grep -q "listen $port" "$conf"; then
      echo "$conf"
      return 0
    fi
  done
  return 1
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
setup_nginx_ssl() {
  local DOMAIN="$1"
  local EMAIL="$2"
  local NGINX_CONF="/etc/nginx/sites-available/doh_dns_$DOMAIN"
  local NGINX_LINK="/etc/nginx/sites-enabled/doh_dns_$DOMAIN"
  local PORT=443

  local conflict_file
  conflict_file=$(nginx_domain_conflict "$DOMAIN" "$PORT") && {
    print_error "A virtual host for $DOMAIN on port $PORT already exists in nginx: $conflict_file"
    exit 1
  }
  conflict_file=$(nginx_port_conflict "$PORT") && {
    print_warn "Port $PORT is already used by another nginx site: $conflict_file"
    read -p "Do you want to use an alternative port (e.g. 8443)? [y/N]: " use_alt
    if [[ "$use_alt" =~ ^[Yy]$ ]]; then
      read -p "Enter alternative port number: " PORT
      conflict_file=$(nginx_port_conflict "$PORT") && {
        print_error "Selected port $PORT is also in use: $conflict_file"
        exit 1
      }
    else
      print_error "Cannot continue with port conflict."
      exit 1
    fi
  }

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

  if [ ! -f "$NGINX_CONF" ]; then
    cat > "$NGINX_CONF" << EOF
server {
    listen $PORT ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    location /dns-query {
        proxy_pass http://127.0.0.1:8053/dns-query;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        autoindex off;
    }
}
EOF
    ln -sf "$NGINX_CONF" "$NGINX_LINK"
  fi

  if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    print_info "Obtaining SSL certificate with Certbot..."
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" > /tmp/certbot.log 2>&1 || {
      print_error "Failed to obtain SSL certificate. See /tmp/certbot.log"
      rm -f "$NGINX_CONF" "$NGINX_LINK"
      exit 1
    }
    if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
      print_error "SSL certificate was not created."
      rm -f "$NGINX_CONF" "$NGINX_LINK"
      exit 1
    fi
  fi

  if ! nginx -t 2>&1 | tee /tmp/nginx_test.log | grep -q "successful"; then
    print_error "nginx configuration test failed. See /tmp/nginx_test.log"
    rm -f "$NGINX_CONF" "$NGINX_LINK"
    exit 1
  fi
  systemctl reload nginx || { print_error "Failed to reload Nginx."; exit 1; }
  print_info "Nginx configured for $DOMAIN on port $PORT"
}

uninstall_nginx() {
  print_info "Removing Nginx and DoH configs..."
  systemctl stop nginx || true
  rm -f /etc/nginx/sites-available/doh_dns_* /etc/nginx/sites-enabled/doh_dns_*
  apt purge -y nginx certbot python3-certbot-nginx
  print_info "Nginx removed."
}

# ====== DoH Server Management ======
install_doh_server() {
  check_make
  if ! command -v git &> /dev/null; then
    print_info "git not found. Installing git..."
    apt update
    apt install -y git || { print_error "Failed to install git."; exit 1; }
    if ! command -v git &> /dev/null; then
      print_error "git failed to install."
      exit 1
    fi
  fi
  if ! command -v go &> /dev/null; then
    print_info "Installing Go..."
    apt update
    apt install -y golang
    if ! command -v go &> /dev/null; then
      print_error "Go failed to install."
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
  print_info "DoH server removed."
}
setup_doh_service() {
  local DOMAIN="$1"
  cat > /etc/systemd/system/doh-server.service << EOF
[Unit]
Description=DNS over HTTPS server (m13253)
After=network.target

[Service]
ExecStart=/usr/local/bin/doh-server -listen :8053 -cert /etc/letsencrypt/live/$DOMAIN/fullchain.pem -key /etc/letsencrypt/live/$DOMAIN/privkey.pem -upstream https://1.1.1.1/dns-query
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now doh-server || { print_error "Failed to start doh-server."; exit 1; }
  check_service_running doh-server || exit 1
}

# ====== Zone Management ======
setup_bind_forwarders() {
  NAMED_OPTIONS="/etc/bind/named.conf.options"
  if ! grep -q "forwarders {" "$NAMED_OPTIONS"; then
    cat >> "$NAMED_OPTIONS" << EOF
options {
  directory "/var/cache/bind";
  forwarders { 1.1.1.1; 8.8.8.8; };
  forward only;
  dnssec-validation auto;
  auth-nxdomain no;
  listen-on { any; };
  listen-on-v6 { any; };
  allow-query { any; };
};
EOF
  fi
}
setup_bind_zones() {
  mkdir -p /etc/bind/zones
  touch "$ZONES_FILE"
  echo "// Zones for forwarding blocked domains" > "$ZONES_FILE"
  read_sites
  local lock="$ZONES_FILE.lock"
  TMPFILES+=("$lock")
  (
    flock -x 200
    for domain in "${sites[@]}"; do
      cat >> "$ZONES_FILE" << EOF

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
  echo "// Zones for forwarding blocked domains" > "$ZONES_FILE"
  read_sites
  local lock="$ZONES_FILE.lock"
  TMPFILES+=("$lock")
  (
    flock -x 200
    for domain in "${sites[@]}"; do
      cat >> "$ZONES_FILE" << EOF

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
  NAMED_CONF="/etc/bind/named.conf.local"
  if ! grep -q "include \"/etc/bind/zones/blocklist.zones\";" "$NAMED_CONF"; then
    echo 'include "/etc/bind/zones/blocklist.zones";' >> "$NAMED_CONF"
  fi
}
check_bind_config() {
  if ! named-checkconf /etc/bind/named.conf; then
    print_error "BIND configuration syntax error."
    exit 1
  fi
}
restart_bind() {
  systemctl restart "$SERVICE_BIND" || { print_error "Failed to restart BIND."; exit 1; }
  systemctl enable "$SERVICE_BIND"
}

# ====== DNS Test ======
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
  if dig @"127.0.0.1" "$test_domain" A +short | grep -q .; then
    print_info "DNS forwarding test passed for $test_domain."
  else
    print_error "DNS forwarding test failed for $test_domain."
    exit 1
  fi
}

# ====== Main Install/Uninstall Logic ======
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
  check_all_ports
  while true; do
    read -rp "Enter your domain (e.g. dns.example.com): " DOMAIN
    if validate_domain "$DOMAIN"; then break; else print_error "Invalid domain format."; fi
  done
  while true; do
    read -rp "Enter your email for Let's Encrypt SSL cert: " EMAIL
    if validate_email "$EMAIL"; then break; else print_error "Invalid email format."; fi
  done
  if [ ! -f "$SITES_FILE" ]; then
    mkdir -p /etc/bind/zones
    for s in "${DEFAULT_SITES[@]}"; do
      echo "$s" >> "$SITES_FILE"
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
  echo "Setup complete!"
  echo "You can now configure your clients to use DNS-over-HTTPS via:"
  echo "https://$DOMAIN/dns-query"
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
  if [ -f "$SITES_FILE" ] || systemctl is-active --quiet "$SERVICE_BIND"; then
    return 0
  else
    return 1
  fi
}

# ====== Trap for cleaning temp files ======
TMPFILES=()
cleanup() {
  for f in "${TMPFILES[@]}"; do
    [ -e "$f" ] && rm -f "$f"
  done
}
trap cleanup EXIT

# ====== Default blocked sites list ======
DEFAULT_SITES=("youtube.com" "instagram.com" "facebook.com" "telegram.org" "twitter.com" "t.me" "discord.com" "spotify.com")

SITES_FILE="/etc/bind/zones/sites.list"
ZONES_FILE="/etc/bind/zones/blocklist.zones"
SERVICE_BIND=""
SERVICE_DOH="doh-server"

# ====== Main Menu ======
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