#!/bin/bash

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "\033[0;31m[ERROR] Required tool '$1' is not installed. Please install it and try again.\033[0m"
        exit 1
    fi
}

check_command ip
check_command arp
check_command nc
check_command awk

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PORTS=(1 5 7 18 20 21 22 23 25 29 37 42 43 49 53 69 70 79 80 81 82 83 84 85 88 89 90 99 100 106 109 110 111 113 119 135 139 143 179 199 211 212 220 389 427 443 444 445 464 465 497 500 514 515 524 541 548 554 563 587 593 631 636 646 873 990 993 995 1025 1026 1027 1028 1029 1030 1720 1723 1755 1900 2000 2001 2049 2121 2717 3000 3128 3306 3389 3986 4899 5000 5009 5050 5060 5101 5190 5222 5432 5900 6000 6667 8000 8008 8080 8443 8888 10000 32768 49152 49153 49154 49155 49156 49157)

echo -e "${GREEN}[+] Network interfaces and associated IP addresses:${NC}"
ip -o addr show | awk '/inet / {print $2 ": " $4}'

echo -e "\n${GREEN}[+] Hosts available via ARP:${NC}"
arp -n | awk '/ether/ {print $1 " (" $3 ")"}'

ARP_HOSTS=$(arp -n | awk '/ether/ {print $1}')

LOCAL_IPS=$(ip -o addr show | awk '/inet / {print $4}')
echo -e "\n${GREEN}[+] Scanning for open ports on discovered hosts (excluding local IPs):${NC}"

scan_ports() {
    host=$1
    port=$2
    nc -z -w 1 $host $port 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${RED}[*] Open port found on $host: $port${NC}"
    fi
}

for host in $ARP_HOSTS; do
    if ! echo "$LOCAL_IPS" | grep -q "$host"; then
        echo -e "${GREEN}[+] Scanning $host for common open ports...${NC}"
        for port in "${PORTS[@]}"; do
            scan_ports $host $port &
        done
        wait
    fi
done

echo -e "${GREEN}[+] Scan completed.${NC}"
