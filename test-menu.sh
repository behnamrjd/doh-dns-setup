#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'

service_status() {
  echo -e "${GREEN}Active${NC}"
}

install_service()   { echo -e "${GREEN}Install called${NC}"; }
uninstall_service() { echo -e "${GREEN}Uninstall called${NC}"; }
show_sites()        { echo -e "${GREEN}Show sites called${NC}"; }
add_site()          { echo -e "${GREEN}Add site called${NC}"; }
remove_site()       { echo -e "${GREEN}Remove site called${NC}"; }
check_if_installed() { return 0; }
detect_bind_service() { return 0; }

main_menu() {
  while true; do
    clear
    echo -e "${MAGENTA}[Service Status: $(service_status)]${NC}"
    echo -e "${MAGENTA}*****************************"
    echo -e "*     SMART DNS PROXY       *"
    echo -e "*****************************${NC}"
    echo -e "${YELLOW} 1)${NC} Install"
    echo -e "${YELLOW} 2)${NC} Uninstall"
    echo -e "${YELLOW} 3)${NC} Show Websites"
    echo -e "${YELLOW} 4)${NC} Add Sites"
    echo -e "${YELLOW} 5)${NC} Remove Sites"
    echo -e "${YELLOW} 0)${NC} Exit"
    echo -e "${MAGENTA}*****************************${NC}"
    read -rp "$(echo -e "${CYAN}Enter your choice: ${NC}")" choice
    case "$choice" in
      1) install_service; read -n1 -r -p "Press any key to continue..." ;;
      2) uninstall_service; read -n1 -r -p "Press any key to continue..." ;;
      3) show_sites; read -n1 -r -p "Press any key to continue..." ;;
      4) add_site; read -n1 -r -p "Press any key to continue..." ;;
      5) remove_site; read -n1 -r -p "Press any key to continue..." ;;
      0) echo "Bye!"; exit 0 ;;
      *) echo -e "${RED}Invalid choice!${NC}"; sleep 1 ;;
    esac
  done
}

if check_if_installed; then
  detect_bind_service
  main_menu
else
  install_service
  main_menu
fi
