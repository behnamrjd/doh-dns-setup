#!/bin/bash

DOMAIN="dns.dnsly.fun"
DNS_PORT=1053
DOH_PORT=8443
DOH_PATH="/dns-query"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

echo -e "${YELLOW}Checking service status...${NC}"
for srv in named nginx doh-server; do
  if systemctl is-active --quiet $srv; then
    ok "Service $srv is active"
  else
    fail "Service $srv is NOT active"
  fi
done

echo -e "${YELLOW}Checking processes...${NC}"
for srv in named nginx doh-server; do
  if pgrep -x "$srv" >/dev/null; then
    ok "Process $srv is running"
  else
    fail "Process $srv is NOT running"
  fi
done

echo -e "${YELLOW}Checking SSL certificate files...${NC}"
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ]; then
  ok "SSL certificate and key exist for $DOMAIN"
else
  fail "SSL certificate or key missing for $DOMAIN"
fi

echo -e "${YELLOW}Testing local DNS (BIND) with dig...${NC}"
if dig @$DOMAIN -p $DNS_PORT $DOMAIN +short | grep -q .; then
  ok "BIND DNS responds to queries"
else
  fail "BIND DNS does NOT respond to queries"
fi

echo -e "${YELLOW}Testing nginx HTTPS response...${NC}"
if curl -skI https://$DOMAIN:$DOH_PORT | grep -q "200\|301\|302\|404"; then
  ok "nginx HTTPS responds on port $DOH_PORT"
else
  fail "nginx HTTPS does NOT respond on port $DOH_PORT"
fi

echo -e "${YELLOW}Testing DoH server with curl...${NC}"
# نمونه query: google.com (base64url encoded DNS query)
DNS_QUERY="AAABAAABAAAAAAAAB2dvb2dsZQNjb20AAAEAAQ"
if curl -sk "https://$DOMAIN:$DOH_PORT$DOH_PATH?dns=$DNS_QUERY" -H 'accept: application/dns-message' | grep -q .; then
  ok "DoH server responds to DNS-over-HTTPS queries"
else
  fail "DoH server does NOT respond to DNS-over-HTTPS queries"
fi

echo -e "${YELLOW}Test finished.${NC}"
