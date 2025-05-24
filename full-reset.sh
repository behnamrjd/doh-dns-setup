#!/bin/bash
set -e

SITES_FILE="/etc/bind/zones/sites.list"
ZONES_FILE="/etc/bind/zones/blocklist.zones"
NAMED_OPTIONS="/etc/bind/named.conf.options"
NAMED_CONF_LOCAL="/etc/bind/named.conf.local"
ZONES_DIR="/etc/bind/zones"

echo "===== FULL RESET: Remove all DoH, BIND, nginx, certbot configs ====="

# Optional: backup configs
read -p "Would you like to back up BIND configs before reset? (y/n): " bkup
if [[ "$bkup" =~ ^[Yy]$ ]]; then
  sudo cp "$NAMED_CONF_LOCAL" "$NAMED_CONF_LOCAL.bak" 2>/dev/null || true
  sudo cp "$NAMED_OPTIONS" "$NAMED_OPTIONS.bak" 2>/dev/null || true
  echo "Backup done."
fi

echo "Stopping and disabling DNS/DoH/nginx services..."
sudo systemctl stop nginx doh-server bind9 named 2>/dev/null || true
sudo systemctl disable bind9 named 2>/dev/null || true

echo "Cleaning BIND listen-on lines..."
if [ -f "$NAMED_OPTIONS" ]; then
  sudo sed -i '/listen-on port/d' "$NAMED_OPTIONS"
  sudo sed -i '/listen-on-v6 port/d' "$NAMED_OPTIONS"
fi

echo "Removing all DoH nginx server blocks and 443 conflicts..."
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

echo "Removing BIND zones and DoH server..."
sudo rm -rf "$ZONES_DIR"
sudo rm -f /usr/local/bin/doh-server /etc/systemd/system/doh-server.service
sudo rm -rf /etc/dns-over-https

echo "Removing Let's Encrypt certs for all domains in $SITES_FILE..."
if [ -f "$SITES_FILE" ]; then
  mapfile -t domains < "$SITES_FILE"
  for d in "${domains[@]}"; do
    sudo rm -rf "/etc/letsencrypt/live/$d" "/etc/letsencrypt/archive/$d" "/etc/letsencrypt/renewal/$d.conf"
  done
fi
sudo rm -rf /var/log/letsencrypt
sudo rm -f "$SITES_FILE"

echo "Cleaning named.conf.local from includes/zones..."
if [ -f "$NAMED_CONF_LOCAL" ]; then
  sudo sed -i '/blocklist\.zones/d' "$NAMED_CONF_LOCAL"
  sudo sed -i '/zone.*{/,/};/d' "$NAMED_CONF_LOCAL"
fi

echo "Ensuring empty zone file exists to avoid BIND errors..."
sudo mkdir -p "$ZONES_DIR"
sudo touch "$ZONES_FILE"

echo "Reloading systemd and restarting networking/nginx..."
sudo systemctl daemon-reload
sudo systemctl restart networking 2>/dev/null || true
sudo systemctl start nginx 2>/dev/null || true

echo "Full reset complete. All configs, services, certs, and server blocks for DoH/BIND/nginx are removed."