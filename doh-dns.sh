#!/bin/bash
set -e

# Default blocked sites list (can add/remove later)
DEFAULT_SITES=("youtube.com" "instagram.com" "facebook.com" "telegram.org" "twitter.com" "t.me" "discord.com" "spotify.com")

# Paths and service names
SITES_FILE="/etc/bind/zones/sites.list"
ZONES_FILE="/etc/bind/zones/blocklist.zones"
SERVICE_BIND=""  # Will be set dynamically by detect_bind_service
SERVICE_DOH="doh-server"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'

# Functions for UI and status
print_error() {
  echo -e "${RED}ERROR: $1${NC}"
}

print_info() {
  echo -e "${GREEN}INFO: $1${NC}"
}

service_status() {
  local bind_status=$(systemctl is-active --quiet "$SERVICE_BIND" && echo -e "${GREEN}Active${NC}" || echo -e "${RED}Inactive${NC}")
  local doh_status=$(systemctl is-active --quiet "$SERVICE_DOH" && echo -e "${GREEN}Active${NC}" || echo -e "${RED}Inactive${NC}")
  echo -e "BIND: $bind_status | DoH: $doh_status"
}

detect_bind_service() {
  print_info "Detecting BIND service name..."
  if systemctl list-unit-files | grep -q "bind9.service"; then
    SERVICE_BIND="bind9"
    print_info "BIND service detected as 'bind9'."
  elif systemctl list-unit-files | grep -q "named.service"; then
    SERVICE_BIND="named"
    print_info "BIND service detected as 'named'."
  else
    print_error "Could not detect BIND service (neither bind9 nor named found). Ensure BIND is installed."
    exit 1
  fi
}

open_required_ports() {
  print_info "Opening required ports (22, 53, 80, 443, 8053)..."
  local ports=("22/tcp" "53/tcp" "53/udp" "80/tcp" "443/tcp" "8053/tcp")
  if command -v ufw &> /dev/null; then
    # Ensure ufw is enabled
    if ! ufw status | grep -q "active"; then
      print_info "ufw is not active. Enabling ufw..."
      ufw enable || print_error "Failed to enable ufw. Check manually."
    fi
    for port in "${ports[@]}"; do
      if ! ufw status | grep -q "$port"; then
        ufw allow "$port" || print_error "Failed to open port $port with ufw. Open it manually."
        print_info "Port $port opened with ufw."
      else
        print_info "Port $port is already open."
      fi
    done
  elif command -v iptables &> /dev/null; then
    print_info "ufw not found. Using iptables to open ports..."
    for port in "${ports[@]}"; do
      if [[ "$port" == *"udp"* ]]; then
        proto="udp"
        port_num="${port%%/*}"
      else
        proto="tcp"
        port_num="${port%%/*}"
      fi
      iptables -A INPUT -p "$proto" --dport "$port_num" -j ACCEPT || print_error "Failed to open port $port with iptables. Open it manually."
      print_info "Port $port opened with iptables."
    done
    # Save iptables rules if possible
    if command -v iptables-save &> /dev/null; then
      iptables-save > /etc/iptables/rules.v4 2>/dev/null || print_info "Could not save iptables rules. They may reset on reboot."
    fi
  else
    print_error "Neither ufw nor iptables found. Please open ports 22, 53 (TCP/UDP), 80, 443, and 8053 manually using your firewall tool."
    exit 1
  fi
  print_info "All required ports are opened or checked."
}

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
  read -rp "Enter domain to add: " domain
  while [ -z "$domain" ]; do
    print_error "Domain cannot be empty. Please enter a domain."
    read -rp "Enter domain to add: " domain
  done
  read_sites
  if [[ " ${sites[*]} " == *" $domain "* ]]; then
    echo -e "${YELLOW}Domain already exists.${NC}"
  else
    echo "$domain" >> "$SITES_FILE"
    sites+=("$domain")
    update_zones
    echo -e "${GREEN}Domain added.${NC}"
  fi
}

remove_site() {
  read -rp "Enter domain to remove: " domain
  while [ -z "$domain" ]; do
    print_error "Domain cannot be empty. Please enter a domain."
    read -rp "Enter domain to remove: " domain
  done
  read_sites
  if [[ ! " ${sites[*]} " == *" $domain "* ]]; then
    echo -e "${YELLOW}Domain not found.${NC}"
  else
    grep -vxF "$domain" "$SITES_FILE" > "${SITES_FILE}.tmp" && mv "${SITES_FILE}.tmp" "$SITES_FILE"
    read_sites
    update_zones
    echo -e "${GREEN}Domain removed.${NC}"
  fi
}

# Functions for setup
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
  fi
}

install_prerequisites() {
  print_info "Installing prerequisite tools..."
  apt update || { print_error "Failed to update package lists. Check your internet connection."; exit 1; }
  # Install basic tools that might be missing on a fresh server
  apt install -y curl wget dnsutils iproute2 net-tools || {
    print_error "Failed to install prerequisite tools. Check your package manager or internet connection."
    exit 1
  }
  # Install ufw if not present
  if ! command -v ufw &> /dev/null; then
    apt install -y ufw || {
      print_error "Failed to install ufw. Install it manually or use another firewall tool."
      exit 1
    }
  fi
  print_info "Prerequisite tools installed."
}

install_dependencies() {
  print_info "Updating and installing dependencies..."
  apt update || { print_error "Failed to update package lists. Check your internet connection."; exit 1; }
  apt install -y bind9 bind9utils bind9-doc nginx certbot python3-certbot-nginx wget jq unzip dnsutils ufw || {
    print_error "Failed to install dependencies. Check your package manager or internet connection."
    exit 1
  }
}

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
  else
    print_info "Forwarders already configured in $NAMED_OPTIONS."
  fi
}

setup_bind_zones() {
  mkdir -p /etc/bind/zones
  touch "$ZONES_FILE"
  echo "// Zones for forwarding blocked domains" > "$ZONES_FILE"
  read_sites
  for domain in "${sites[@]}"; do
    cat >> "$ZONES_FILE" << EOF

zone "$domain" {
  type forward;
  forward only;
  forwarders { 1.1.1.1; 8.8.8.8; };
};
EOF
  done
  print_info "Zone file $ZONES_FILE created with domains."
}

update_zones() {
  echo "// Zones for forwarding blocked domains" > "$ZONES_FILE"
  read_sites
  for domain in "${sites[@]}"; do
    cat >> "$ZONES_FILE" << EOF

zone "$domain" {
  type forward;
  forward only;
  forwarders { 1.1.1.1; 8.8.8.8; };
};
EOF
  done
  check_bind_config
  restart_bind
  print_info "Zones updated and BIND restarted."
}

update_named_conf() {
  NAMED_CONF="/etc/bind/named.conf.local"
  if ! grep -q "include \"/etc/bind/zones/blocklist.zones\";" "$NAMED_CONF"; then
    echo 'include "/etc/bind/zones/blocklist.zones";' >> "$NAMED_CONF"
  fi
  print_info "Included blocklist zones in named.conf.local"
}

check_bind_config() {
  if ! named-checkconf /etc/bind/named.conf; then
    print_error "BIND configuration syntax error. Check /etc/bind/named.conf and related files."
    exit 1
  fi
  print_info "BIND configuration syntax check passed."
}

restart_bind() {
  systemctl restart "$SERVICE_BIND" || { print_error "Failed to restart BIND. Check logs with 'journalctl -u $SERVICE_BIND'."; exit 1; }
  systemctl enable "$SERVICE_BIND"
  print_info "BIND restarted and enabled."
}

setup_nginx_ssl() {
  DOMAIN="$1"
  EMAIL="$2"
  
  # Check if domain resolves to server IP
  print_info "Checking if domain $DOMAIN resolves to this server's IP..."
  SERVER_IP=$(curl -s ifconfig.me || wget -qO- ipinfo.io/ip)
  if [ -z "$SERVER_IP" ]; then
    print_error "Could not determine server IP. Check internet connection."
    exit 1
  fi
  DOMAIN_IP=$(dig +short "$DOMAIN" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -1)
  if [ -z "$DOMAIN_IP" ]; then
    print_error "Could not resolve domain $DOMAIN. Ensure DNS is configured correctly."
    exit 1
  fi
  if [ "$DOMAIN_IP" != "$SERVER_IP" ]; then
    print_error "Domain $DOMAIN resolves to $DOMAIN_IP, but server IP is $SERVER_IP. Ensure DNS points to this server."
    exit 1
  fi
  print_info "Domain resolves correctly to server IP ($SERVER_IP)."

  # Check if ports 80 and 443 are open
  print_info "Checking if ports 80 and 443 are open..."
  if ! ss -tuln | grep -q ":80 "; then
    print_info "Port 80 is not open. Attempting to open it with ufw..."
    sudo ufw allow 80/tcp || print_error "Failed to open port 80. Open it manually."
  fi
  if ! ss -tuln | grep -q ":443 "; then
    print_info "Port 443 is not open. Attempting to open it with ufw..."
    sudo ufw allow 443/tcp || print_error "Failed to open port 443. Open it manually."
  fi

  # Nginx config for DoH (create config without assuming cert exists)
  NGINX_CONF="/etc/nginx/sites-available/doh_dns"
  if [ -f "$NGINX_CONF" ]; then
    print_info "Nginx config already exists. Skipping creation."
  else
    cat > "$NGINX_CONF" << EOF
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location /dns-query {
        proxy_pass http://127.0.0.1:8053/dns-query;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/doh_dns || print_error "Failed to create symlink for Nginx config."
    print_info "Nginx config created."
  fi

  # Check if certificate already exists
  if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    print_info "SSL certificate for $DOMAIN already exists. Skipping Certbot."
  else
    # Obtain SSL cert with certbot (try nginx plugin first, fallback to standalone)
    print_info "Obtaining SSL certificate with Certbot (nginx plugin)..."
    if ! certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"; then
      print_info "Nginx plugin failed. Falling back to standalone mode for Certbot."
      if ! certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"; then
        print_error "Failed to get SSL certificate for $DOMAIN. Ensure the domain points to this server, ports 80 and 443 are open, and try again."
        print_error "You can also run Certbot manually with: sudo certbot certonly --standalone -d $DOMAIN"
        exit 1
      fi
    fi
    print_info "SSL certificate obtained successfully."
  fi

  # Check if certificate files exist before reloading Nginx
  if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    print_error "Certificate file not found at /etc/letsencrypt/live/$DOMAIN/fullchain.pem. Check Certbot output or issue certificate manually."
    exit 1
  fi

  # Reload Nginx to apply changes
  if systemctl is-active --quiet nginx; then
    systemctl reload nginx || { print_error "Failed to reload Nginx. Check logs with 'journalctl -u nginx'."; exit 1; }
  else
    print_info "Nginx is not active. Starting Nginx..."
    systemctl start nginx || { print_error "Failed to start Nginx. Check logs with 'journalctl -u nginx'."; exit 1; }
  fi
  print_info "Nginx configured with SSL for $DOMAIN"
}

install_doh_server() {
  print_info "Installing DNS-over-HTTPS server (DNSCrypt/doh-server)..."
  if command -v doh-server &> /dev/null; then
    print_info "doh-server already installed."
    return
  fi
  if ! wget https://github.com/DNSCrypt/doh-server/releases/download/0.9.11/doh-server-0.9.11-linux-x86_64.tar.gz -O /tmp/doh-server.tar.gz; then
    print_error "Failed to download doh-server. Check your internet connection or try a different source."
    print_error "You can download manually from https://github.com/DNSCrypt/doh-server/releases and install with:"
    print_error "sudo tar -xzf /tmp/doh-server.tar.gz -C /usr/local/bin/ --strip-components=1 && sudo chmod +x /usr/local/bin/doh-server"
    exit 1
  fi
  tar -xzf /tmp/doh-server.tar.gz -C /usr/local/bin/ --strip-components=1 || { print_error "Failed to extract doh-server."; exit 1; }
  chmod +x /usr/local/bin/doh-server
  print_info "doh-server installed successfully."
}

setup_doh_service() {
  DOMAIN="$1"
  cat > /etc/systemd/system/doh-server.service << EOF
[Unit]
Description=DNS over HTTPS server (DNSCrypt)
After=network.target

[Service]
ExecStart=/usr/local/bin/doh-server -addr :8053 -cert /etc/letsencrypt/live/$DOMAIN/fullchain.pem -key /etc/letsencrypt/live/$DOMAIN/privkey.pem -upstream 1.1.1.1:53
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now doh-server || { print_error "Failed to start doh-server. Check logs with 'journalctl -u doh-server'."; exit 1; }
  print_info "DoH server started and enabled."
}

check_firewall_ports() {
  local missing_ports=()
  for port in 53 80 443 8053 22; do
    if ! ss -tuln | grep -q ":$port "; then
      missing_ports+=("$port")
    fi
  done
  if [ ${#missing_ports[@]} -gt 0 ]; then
    print_error "Ports ${missing_ports[*]} are not listening."
    open_required_ports
    # Recheck after attempting to open ports
    for port in "${missing_ports[@]}"; do
      if ! ss -tuln | grep -q ":$port "; then
        print_error "Port $port is still not listening. Open it manually or check firewall settings."
        exit 1
      fi
    done
  fi
  print_info "All required ports are open."
}

test_dns_forwarding() {
  print_info "Testing DNS forwarding for a sample domain..."
  if ! command -v dig &> /dev/null; then
    print_error "dig not found. Skipping DNS test."
    return
  fi
  read_sites
  test_domain="${sites[0]}"  # Fixed index to select first domain
  if [ -z "$test_domain" ]; then
    print_error "No domains available for testing. Skipping DNS test."
    return
  fi
  if dig @"127.0.0.1" "$test_domain" A +short | grep -q .; then
    print_info "DNS forwarding test passed for $test_domain."
  else
    print_error "DNS forwarding test failed for $test_domain. Check BIND logs with 'journalctl -u $SERVICE_BIND'."
    exit 1
  fi
}

install_service() {
  check_root
  detect_bind_service  # Detect BIND service name
  read -rp "Enter your domain (e.g. dns.example.com): " DOMAIN
  while [ -z "$DOMAIN" ]; do
    print_error "Domain cannot be empty. Please enter a domain."
    read -rp "Enter your domain (e.g. dns.example.com): " DOMAIN
  done
  read -rp "Enter your email for Let's Encrypt SSL cert: " EMAIL
  while [ -z "$EMAIL" ]; do
    print_error "Email cannot be empty. Please enter an email."
    read -rp "Enter your email for Let's Encrypt SSL cert: " EMAIL
  done

  # Save default sites if file doesn't exist
  if [ ! -f "$SITES_FILE" ]; then
    mkdir -p /etc/bind/zones
    for s in "${DEFAULT_SITES[@]}"; do
      echo "$s" >> "$SITES_FILE"
    done
  fi

  install_prerequisites  # Install basic tools for a fresh server
  install_dependencies
  open_required_ports  # Open all required ports
  setup_bind_forwarders
  setup_bind_zones
  update_named_conf
  check_bind_config
  restart_bind
  setup_nginx_ssl "$DOMAIN" "$EMAIL"
  install_doh_server
  setup_doh_service "$DOMAIN"
  check_firewall_ports
  test_dns_forwarding

  echo
  echo "Setup complete!"
  echo "You can now configure your clients to use DNS-over-HTTPS via:"
  echo "https://$DOMAIN/dns-query"
}

uninstall_service() {
  check_root
  detect_bind_service  # Detect BIND service name
  print_info "Uninstalling services..."
  systemctl stop "$SERVICE_BIND" "$SERVICE_DOH" || true
  systemctl disable "$SERVICE_BIND" "$SERVICE_DOH" || true
  apt purge -y bind9 bind9utils bind9-doc nginx certbot python3-certbot-nginx || {
    print_error "Failed to uninstall packages. Check manually."
  }
  rm -rf /etc/bind/zones /etc/nginx/sites-available/doh_dns /etc/nginx/sites-enabled/doh_dns /etc/systemd/system/doh-server.service /usr/local/bin/doh-server
  systemctl daemon-reload
  print_info "Services uninstalled. Some configuration files may remain; remove them manually if needed."
}

# Main UI loop
check_if_installed() {
  if [ -f "$SITES_FILE" ] || ( [ -n "$SERVICE_BIND" ] && systemctl is-active --quiet "$SERVICE_BIND" ); then
    return 0 # Installed
  else
    return 1 # Not installed
  fi
}

main_menu() {
  while true; do
    clear
    echo -e "${MAGENTA}[Service Status: $(service_status)]${NC}"
    echo -e "${MAGENTA}*****************************"
    echo -e "*     SMART DNS PROXY       *"
    echo -e "*****************************${NC}"
    echo -e "${YELLOW} 1)${NC} Install"
    echo -