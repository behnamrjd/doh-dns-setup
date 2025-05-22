#!/bin/bash
set -e

# رنگ‌ها برای پیام‌ها
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
print_error() { echo -e "${RED}ERROR: $1${NC}"; }
print_info()  { echo -e "${GREEN}INFO: $1${NC}"; }

# مسیر فایل سایت‌ها (در صورت نیاز تغییر بده)
SITES_FILE="/etc/bind/zones/sites.list"

# بکاپ کانفیگ‌ها (اختیاری)
read -p "Do you want to backup BIND configs before reset? (y/n): " bkup
if [[ "$bkup" =~ ^[Yy]$ ]]; then
  sudo cp /etc/bind/named.conf.local /etc/bind/named.conf.local.bak 2>/dev/null || true
  sudo cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak 2>/dev/null || true
  print_info "Backup done."
fi

print_info "Stopping and disabling DNS and DoH related services..."
sudo systemctl stop nginx doh-server bind9 named 2>/dev/null || true
sudo systemctl disable bind9 named 2>/dev/null || true

print_info "Removing listen-on port lines from /etc/bind/named.conf.options (if exists)..."
if [ -f /etc/bind/named.conf.options ]; then
  sudo sed -i '/listen-on port/d' /etc/bind/named.conf.options
  sudo sed -i '/listen-on-v6 port/d' /etc/bind/named.conf.options
fi

print_info "Removing DoH nginx configs..."
sudo rm -f /etc/nginx/sites-available/doh_dns_* /etc/nginx/sites-enabled/doh_dns_*

print_info "Removing BIND zones and DoH server..."
sudo rm -rf /etc/bind/zones
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

print_info "Reloading systemd and restarting networking/nginx..."
sudo systemctl daemon-reload
sudo systemctl restart networking 2>/dev/null || true
sudo systemctl start nginx 2>/dev/null || true

print_info "Full reset complete. All previous DNS ports are now free and configs/services removed."
