#!/bin/bash

DOMAIN="dns.dnsly.fun"
DNS_PORT=53
DOH_PORT=443
DOH_PATH="/dns-query"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

echo -e "${YELLOW}Checking doh-server backend directly...${NC}"
BACKEND=$(curl -sk http://127.0.0.1:8053/dns-query?dns=AAABAAABAAAAAAAAB2dvb2dsZQNjb20AAAEAAQ -H 'accept: application/dns-message')
if [[ "$BACKEND" =~ . ]]; then
  ok "doh-server backend responds to DNS-over-HTTPS queries"
else
  fail "doh-server backend does NOT respond (check service and config!)"
fi

echo -e "${YELLOW}Testing nginx HTTPS DoH endpoint...${NC}"
CURL_OUT=$(curl -sk "https://$DOMAIN:$DOH_PORT$DOH_PATH?dns=AAABAAABAAAAAAAAB2dvb2dsZQNjb20AAAEAAQ" -H 'accept: application/dns-message')
if [[ "$CURL_OUT" =~ "Client sent an HTTP request to an HTTPS server." ]] || [[ "$CURL_OUT" =~ "400" ]]; then
  fail "nginx returns HTTP 400 or protocol error. Check for conflicting nginx server blocks, proxy_pass config, and doh-server status!"
elif [[ "$CURL_OUT" =~ . ]]; then
  ok "nginx DoH endpoint responds correctly"
else
  fail "nginx DoH endpoint does NOT respond"
fi
