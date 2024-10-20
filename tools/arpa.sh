#!/bin/bash

check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

check_command ip || { echo -e "\033[0;31m[ERROR] Required tool 'ip' is not installed. Please install it and try again.\033[0m"; exit 1; }
check_command awk || { echo -e "\033[0;31m[ERROR] Required tool 'awk' is not installed. Please install it and try again.\033[0m"; exit 1; }

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PORTS=(1 5 7 18 20 21 22 23 25 29 37 42 43 49 53 69 70 79 80 81 82 83 84 85 88 89 90 99 100 106 109 110 111 113 119 135 139 143 179 199 211 212 220 389 427 443 444 445 464 465 497 500 514 515 524 541 548 554 563 587 593 631 636 646 873 990 993 995 1025 1026 1027 1028 1029 1030 1720 1723 1755 1900 2000 2001 2049 2121 2717 3000 3128 3306 3389 3986 4899 5000 5009 5050 5060 5101 5190 5222 5432 5900 6000 6667 8000 8008 8080 8443 8888 10000 32768 49152 49153 49154 49155 49156 49157)

NC_ENABLED=true
TELNET_ENABLED=false
TCP_DEV_ENABLED=false

if ! check_command nc; then
    echo -e "\033[0;33m[WARNING] 'nc' (netcat) is not available.\033[0m"
    NC_ENABLED=false
    
    if check_command telnet; then
        echo -e "\033[0;33m[INFO] Using 'telnet' for port scanning.\033[0m"
        TELNET_ENABLED=true
    elif [[ -e /dev/tcp ]]; then
        echo -e "\033[0;33m[INFO] Using /dev/tcp for port scanning.\033[0m"
        TCP_DEV_ENABLED=true
    else
        echo -e "\033[0;31m[ERROR] Neither 'nc', 'telnet', nor /dev/tcp is available. Cannot proceed with port scanning.\033[0m"
        exit 1
    fi
fi

ip_to_dec() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo "$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
}

dec_to_ip() {
    local ip dec="$1"
    for e in {3..0}; do
        ip=$((dec / (256 ** e)))
        printf "%s" "${ip}"
        [ "$e" -gt 0 ] && printf "."
        dec=$((dec % (256 ** e)))
    done
}

cidr_to_range() {
    local ip="$1"
    local cidr="$2"
    
    local ip_dec
    ip_dec=$(ip_to_dec "$ip")
    
    local mask=$(( 0xFFFFFFFF << (32 - cidr) ))
    
    local network=$(( ip_dec & mask ))
    local broadcast=$(( network | ~mask & 0xFFFFFFFF ))
    
    echo "$network" "$broadcast"
}

scan_ports() {
    host=$1
    port=$2

    if $NC_ENABLED; then
        nc -z -w 1 $host $port 2>/dev/null
    elif $TELNET_ENABLED; then
        (echo > /dev/null | telnet $host $port 2>/dev/null | grep -q 'Escape') && return 0 || return 1
    elif $TCP_DEV_ENABLED; then
        (echo > /dev/tcp/$host/$port) >/dev/null 2>&1
    fi

    if [ $? -eq 0 ]; then
        echo -e "${RED}[*] Open port found on $host: $port${NC}"
    fi
}

scan_arp_hosts() {
    echo -e "${GREEN}[+] Hosts available via ARP:${NC}"
    arp -n | awk '/ether/ {print $1 " (" $3 ")"}'

    ARP_HOSTS=$(arp -n | awk '/ether/ {print $1}')
    LOCAL_IPS=$(ip -o addr show | awk '/inet / {print $4}')

    for host in $ARP_HOSTS; do
        if ! echo "$LOCAL_IPS" | grep -q "$host"; then
            echo -e "${GREEN}[+] Scanning $host for common open ports...${NC}"
            for port in "${PORTS[@]}"; do
                scan_ports "$host" $port &
            done
            wait
        fi
    done
}

if [ $# -gt 0 ]; then
    TARGET=$1

    if [[ "$TARGET" =~ / ]]; then
        IP=$(echo "$TARGET" | cut -d'/' -f1)
        CIDR=$(echo "$TARGET" | cut -d'/' -f2)

        read start_ip end_ip <<< "$(cidr_to_range "$IP" "$CIDR")"

        echo -e "${GREEN}[+] Scanning range: $(dec_to_ip $start_ip) - $(dec_to_ip $end_ip)${NC}"
        
        for ((ip_dec=start_ip; ip_dec<=end_ip; ip_dec++)); do
            ip=$(dec_to_ip $ip_dec)
            echo -e "${GREEN}[+] Scanning IP: $ip${NC}"
            for port in "${PORTS[@]}"; do
                scan_ports "$ip" $port &
            done
            wait
        done
    else
        echo -e "${GREEN}[+] Scanning provided IP: $TARGET${NC}"
        for port in "${PORTS[@]}"; do
            scan_ports "$TARGET" $port &
        done
        wait
    fi
    echo -e "${GREEN}[+] Scan of $TARGET completed.${NC}"

else
    echo -e "${GREEN}[+] Scanning localhost for common open ports...${NC}"
    for port in "${PORTS[@]}"; do
        scan_ports "localhost" $port &
    done
    wait

    ARP_ENABLED=true
    if ! check_command arp; then
        echo -e "\033[0;33m[WARNING] 'arp' command is not available. Defaulting to localhost scanning only.\033[0m"
        ARP_ENABLED=false
    else
        scan_arp_hosts
    fi

    echo -e "${GREEN}[+] Localhost and ARP-based scan completed.${NC}"
fi
