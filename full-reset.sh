#!/bin/bash
set -e

# ====== Key File Paths ======
SITES_FILE="/etc/bind/zones/sites.list"
ZONES_FILE="/etc/bind/zones/blocklist.zones"
NAMED_OPTIONS="/etc/bind/named.conf.options"
NAMED_CONF_LOCAL="/etc/bind/named.conf.local"
ZONES_DIR="/etc/bind/zones"

# ====== Output Colors ======
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
print_error() { echo -e "${RED}ERROR: $1${NC}"; }
print_info()  { echo -e "${GREEN}INFO: $1${NC}"; }

# ====== Optional: Backup configs ======
read -p "Would you like to backup BIND configs before reset? (y/n): " bkup
if [[ "$bkup" =~ ^[Yy]$ ]]; then
  sudo cp "$NAMED_CONF_LOCAL" "$NAMED_CONF_LOCAL.bak" 2>/dev/null || true
  sudo cp "$NAMED_OPTIONS" "$NAMED_OPTIONS.bak" 2>/dev/null || true
  print_info "Backup done."
fi

print_info "Stopping and disabling DNS and DoH related services..."
sudo systemctl stop nginx doh-server bind9 named 2>/dev/null || true
sudo systemctl disable bind9 named 2>/dev/null || true

print_info "Removing listen-on port lines from $NAMED_OPTIONS (if exists)..."
if [ -f "$NAMED_OPTIONS" ]; then
  sudo sed -i '/listen-on port/d' "$NAMED_OPTIONS"
  sudo sed -i '/listen-on-v6 port/d' "$NAMED_OPTIONS"
fi

print_info "Removing DoH nginx configs..."
sudo rm -f /etc/nginx/sites-available/doh_dns_* /etc/nginx/sites-enabled/doh_dns_*

print_info "Removing BIND zones and DoH server..."
sudo rm -rf "$ZONES_DIR"
sudo rm -f /usr/local/bin/doh-server /etc/systemd/system/doh-server.service

print_info "Removing Let's Encrypt certs for all domains in $SITES_FILE..."
if [ -f "$SITES_FILE" ]; then
  mapfile -t domains < "$SITES_FILE"
  for d in "${domains[@]}"; do
    sudo rm -rf "/etc/letsencrypt/live/$d" "/etc/letsencrypt/archive/$d" "/etc/letsencrypt/renewal/$d.conf"
  done
fi
sudo rm -rf /var/log/letsencrypt
sudo rm -f "$SITES_FILE"

print_info "Cleaning up named.conf.local from broken includes/zones..."
if [ -f "$NAMED_CONF_LOCAL" ]; then
  sudo sed -i '/blocklist\.zones/d' "$NAMED_CONF_LOCAL"
  sudo sed -i '/zone.*{/,/};/d' "$NAMED_CONF_LOCAL"
fi

print_info "Ensuring empty zone file exists to avoid BIND errors..."
sudo mkdir -p "$ZONES_DIR"
sudo touch "$ZONES_FILE"

print_info "Reloading systemd and restarting networking/nginx..."
sudo systemctl daemon-reload
sudo systemctl restart networking 2>/dev/null || true
sudo systemctl start nginx 2>/dev/null || true

print_info "Full reset complete. All previous DNS ports are now free and configs/services removed."
