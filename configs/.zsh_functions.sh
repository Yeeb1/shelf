function customs() {
    echo -e "\033[1;36mALIASES:\033[0m"
    echo "-----------------------------"
    grep '^alias ' ~/.zsh_alias.sh | sort | while read -r line; do
        alias_name=$(echo "$line" | awk -F'=' '{print $1}' | sed 's/alias //')
        description=$(echo "$line" | grep -o '#.*' | sed 's/# //')
        if [ -z "$description" ]; then
            description="No description available"
        fi
        echo -e "[+] \033[1;32m$alias_name\033[0m - $description"
    done

    echo ''
    echo -e "\033[1;36mFUNCTIONS:\033[0m"
    echo "-----------------------------"
    grep '^function ' ~/.zsh_functions.sh | awk '{print $2}' | sed 's/()//' | sort | while read -r func_name; do
        description=$(awk "/^function $func_name\(\)/,/^}/" ~/.zsh_functions.sh | grep -m 1 '# Description:' | sed 's/# Description: //' | sed 's/} //g')
        
        if [ -z "$description" ]; then
            description="No description available"
        fi
        
        echo -e "[+] \033[1;34m$func_name\033[0m - $description"
    done
} # Description: Print all user defined alias and functions

mcd() {
   mkdir -p "$1" && cd "$1"
} # Description: Create and navigate to a directory

function dockershellshhere() {
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/sh -v `pwd`:/${dirname} -w /${dirname} "$@"
} # Description: Run docker shell with /bin/sh in the current directory

function dockershellhere() {
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/bash -v `pwd`:/${dirname} -w /${dirname} "$@"
} # Description: Run docker shell with /bin/bash in the current directory

function ffuf_vhost() {
    if [ "$#" -ne 3 ]; then
        echo "[i] Usage: ffuf_vhost <http|https> <domain> <fs>"
        return 1
    fi
    protocol=$1
    domain=$2
    fs_value=$3
    if [ "$protocol" != "http" ] && [ "$protocol" != "https" ]; then
        echo "[i] Invalid protocol. Use 'http' or 'https'."
        return 1
    fi
    ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -H "Host: FUZZ.$domain" -u $protocol://$domain -fs $fs_value
} # Description: FFUF for VHost fuzzing with the Jhaddix wordlist

function ffuf_vhost_quick() {
    if [ "$#" -ne 3 ]; then
        echo "[i] Usage: ffuf_vhost_fast <http|https> <domain> <fs>"
        return 1
    fi
    protocol=$1
    domain=$2
    fs_value=$3
    if [ "$protocol" != "http" ] && [ "$protocol" != "https" ]; then
        echo "[i] Invalid protocol. Use 'http' or 'https'."
        return 1
    fi
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$domain" -u $protocol://$domain -fs $fs_value
} # Description: Quick FFUF for VHost fuzzing with a smaller wordlist

function rock_john() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: rock_john [hash] (options)"
    else
      john "${@}" --wordlist=/usr/share/wordlists/rockyou.txt
  fi
} # Description: Run John the Ripper using the RockYou wordlist

function ips() {
  ip a show scope global | awk '/^[0-9]+:/ { sub(/:/,"",$2); iface=$2 } /^[[:space:]]*inet / { split($2, a, "/"); print "[\033[96m" iface"\033[0m] "a[1] }'
} # Description: Show global scope IP addresses for all interfaces

function nmap_default() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: nmap_default ip (options)"
    else
      [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
      sudo nmap -sCV -T4 --min-rate 10000 "${@}" -v -oA nmap/tcp_default
  fi
} # Description: Run a default TCP Nmap scan and save results in ./nmap

function nmap_udp() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: nmap_udp ip (options)"
    else
      [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
      sudo nmap -sUCV -T4 --min-rate 10000 "${@}" -v -oA nmap/udp_default
  fi
} # Description: Run a default UDP Nmap scan and save results in ./nmap

function nmap_list() {
  if [ $# -eq 0 ]; then
    echo "[i] Usage: nmap_list input_file (options)"
  else
    input_file="$1"
    shift
    [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
    sudo nmap -T4 -sV -p- -vv --min-rate 10000 -oA nmap/scan-tcp -iL "${input_file}" "${@}"
  fi
} # Description: Run a full Nmap scan on a list of IPs from a file

function crawl() {
    if [[ -z "$1" ]]; then
        echo "[i] Usage: crawl <URL>"
        return 1
    fi
    echo "[i] Crawling subdomains for: $1"
    gospider -s $1 -d 5 -t 10 --include-subs -o files | awk '/^\[subdomains\]/ { print "\033[1;31m" $0 "\033[0m" } !/^\[subdomains\]/ { print }'
} # Description: Crawl subdomains for a given URL using gospider

function export-krbcc() {
  export KRB5CCNAME=$(realpath "$1")
} # Description: Set the KRB5CCNAME environment variable to a Kerberos ticket file

function rdp() {
    usage() {
        echo "[i] Usage: rdp -i '10.129.16.128' -u 'Administrator' -p 'P@s\$w0rd!' [-H 'NTLMHash']" >&2
    }

    if [ $# -eq 0 ]; then
        usage
        return
    fi

    local OPTIND host user pass hash

    while getopts ':i:u:p:H:' OPTION; do
        case "$OPTION" in
            i) host="$OPTARG" ;;
            u) user="$OPTARG" ;;
            p)
                pass="$OPTARG"
                xfreerdp /v:$host /u:$user /p:$pass /cert:ignore /dynamic-resolution +clipboard
                ;;
            H)
                hash="$OPTARG"
                xfreerdp /v:$host /u:$user /pth:$hash /cert:ignore /dynamic-resolution +clipboard
                ;;
            ?)
                usage
                ;;
        esac
    done

    shift "$(($OPTIND -1))"
} # Description: Run RDP with credentials or NTLM hash

function rdp_noauth() {
    if [ $# -eq 0 ]; then
        echo "[i] Usage: rdp_noauth <IP Address>"
        return
    fi

    local ip=$1

    xfreerdp /v:$ip /size:1920x1080 /tls-seclevel:0 -sec-nla
} # Description: Connect to RDP without authentication (for unauthenticated access)

function ligolo-server() {
    if ! ip link show ligolo &>/dev/null; then
        sudo ip tuntap add user kali mode tun ligolo
        sudo ip link set ligolo up
    fi

    /opt/ligolo-ng/proxy -selfcert
} # Description: Set up the Ligolo tunneling server

function datesync() {
  [ -z "$1" ] && echo "[i] Usage: datesync <URL>" && return 1
  echo "$(date)"
  new_time=$(curl -sI "$1" | grep -i '^Date:' | cut -d' ' -f2-)
  [ -z "$new_time" ] && return 1
  sudo date -s "$new_time"
  echo "$(date)"
} # Description: Sync the local date with the time from a remote server

function ntlmsum() {
  if [ $# -eq 0 ]; then
    echo "[i] Usage: compute_ntlm_hash password"
  else
    password="$1"
    ntlm_hash=$(echo -n "$password" | iconv -t utf-16le | openssl dgst -md4 | awk '{print $2}')
    echo "NTLM Hash: $ntlm_hash"
  fi
} # Description: Compute the NTLM hash of a given password

function bloodhound_import() {
  if [ -z "$BH_PW" ]; then
    echo "[!] Error: BH_PW environment variable is not set."
    return 1
  fi

  if [ $# -eq 0 ]; then
    echo "[i] Usage: bloodhound_import [bloodhound_file1.zip or bloodhound_file1.json] ..."
    return 1
  fi

  for file in "$@"; do
    if [ ! -f "$file" ]; then
      echo "[!] Error: File not found - $file"
      continue
    fi

    if [[ "$file" == *.zip ]]; then
      echo "[i] Processing zip file: $file"
    elif [[ "$file" == *.json ]]; then
      echo "[i] Processing JSON file: $file"
    else
      echo "[!] Error: Unsupported file format. Please provide a zip or JSON file."
      continue
    fi

    echo "[i] Creating a new database with knowsmore"
    knowsmore_output=$(knowsmore --create-db --force 2>&1)
    if [[ ! "$knowsmore_output" =~ "Database created" ]]; then
      echo "[!] Error: Failed to create a new database with knowsmore"
      echo "$knowsmore_output"
      return 1
    fi

    echo "[i] Importing data from $file"
    knowsmore_output=$(knowsmore --bloodhound --import-data "$file" 2>&1)
    if [[ "$knowsmore_output" =~ "Error" ]]; then
      echo "[!] Error: Failed to import data from $file"
      echo "$knowsmore_output"
      return 1
    fi

    echo "[i] Syncing data to BloodHound"
    knowsmore_output=$(knowsmore --bloodhound --sync 127.0.0.1:7687 -d neo4j -u neo4j -p "$BH_PW" 2>&1)
    if [[ "$knowsmore_output" =~ "Error" ]]; then
      echo "[!] Error: Failed to sync data to BloodHound"
      echo "$knowsmore_output"
      return 1
    fi

    echo "[i] Successfully imported and synced BloodHound data from $file"
  done
} # Description: Import BloodHound data using knowsmore and sync it with the BloodHound database

function responder_dump() {
  local default_log_dir="/usr/share/responder/logs"

  if [ $# -lt 1 ]; then
    echo "Usage: responder_dump <output_file> [<responder_log_file>]"
    return 1
  fi

  local output_file="$1"
  local log_file="$2"

  if [ -z "$log_file" ]; then
    log_file=$(find "$default_log_dir" -name "*.log" -print -quit)
    if [ -z "$log_file" ]; then
      echo "[!] Error: No log files found in $default_log_dir"
      return 1
    fi
  fi

  if [ ! -f "$log_file" ]; then
    echo "[!] Error: Log file not found - $log_file"
    return 1
  fi

  strings "$log_file" | \
    grep "NTLMv2-SSP Hash" | \
    cut -d ":" -f 4-10 | \
    awk '{$1=$1};1' | \
    sort -u -t ':' -k1,1 > "$output_file"

  if [ $? -eq 0 ]; then
    echo "[i] Unique hashes extracted to $output_file"
  else
    echo "[!] Error: Failed to extract hashes"
    return 1
  fi
} # Description: Extract NTLM hashes from Responder logs and save them to a file

function crt.sh() {
  if [ $# -ne 1 ]; then
    echo "Usage: crt.sh <domain>"
    return 1
  fi

  local domain="$1"

  curl -s "https://crt.sh/?q=${domain}&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*.//g' | \
  awk '{gsub(/\\n/,"\n")}1' | \
  sort -u
} # Description: Query crt.sh for certificates and list unique subdomains for a given domain
