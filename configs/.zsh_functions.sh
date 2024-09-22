function customs() {
    echo "Aliases defined:"
    echo "Name"
    echo "-----------------"
    grep '^alias ' ~/.zshrc | awk -F'=' '{print $1}' | sed 's/alias //'
    echo ''
    echo "Functions defined:"
    echo "Name"
    echo "-----------------"
    grep '^function ' ~/.zshrc | sed -n 's/function \(.*\)() {.*/\1/p'
}
mcd() {
   mkdir -p "$1" && cd "$1"
}
function dockershellshhere() {
    # Function to run docker shell in current directory with /bin/sh
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/sh -v `pwd`:/${dirname} -w /${dirname} "$@"
}

function dockershellhere() {
    # Function to run docker shell in current directory with /bin/bash
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/bash -v `pwd`:/${dirname} -w /${dirname} "$@"
}
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
}
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
}
function rock_john() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: rock_john [hash] (options)"
    else
      john "${@}" --wordlist=/usr/share/wordlists/rockyou.txt
  fi
}
function ips() {
  ip a show scope global | awk '/^[0-9]+:/ { sub(/:/,"",$2); iface=$2 } /^[[:space:]]*inet / { split($2, a, "/"); print "[\033[96m" iface"\033[0m] "a[1] }'
}
function nmap_default() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: nmap_default ip (options)"
    else
      [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
      sudo nmap -sCV -T4 --min-rate 10000 "${@}" -v -oA nmap/tcp_default
  fi
}
function nmap_udp() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: nmap_udp ip (options)"
    else
      [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
      sudo nmap -sUCV -T4 --min-rate 10000 "${@}" -v -oA nmap/udp_default
  fi
}
function nmap_list() {
  if [ $# -eq 0 ]; then
    echo "[i] Usage: nmap_list input_file (options)"
  else
    input_file="$1"
    shift
    [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
    sudo nmap -T4 -sV -p- -vv --min-rate 10000 -oA nmap/scan-tcp -iL "${input_file}" "${@}"
  fi
}
function crawl() {
    if [[ -z "$1" ]]; then
        echo "[i] Usage: crawl <URL>"
        return 1
    fi
    echo "[i] Crawling subdomains for: $1"
    gospider -s $1 -d 5 -t 10 --include-subs -o files | awk '/^\[subdomains\]/ { print "\033[1;31m" $0 "\033[0m" } !/^\[subdomains\]/ { print }'
}
function export-krbcc() {
  export KRB5CCNAME=$(realpath "$1")
}
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
}
function rdp_noauth() {
    if [ $# -eq 0 ]; then
        echo "[i] Usage: rdp_noauth <IP Address>"
        return
    fi

    local ip=$1

    xfreerdp /v:$ip /size:1920x1080 /tls-seclevel:0 -sec-nla
}
function ligolo-server() {
    if ! ip link show ligolo &>/dev/null; then
        sudo ip tuntap add user kali mode tun ligolo
        sudo ip link set ligolo up
    fi

    /opt/ligolo-ng/proxy -selfcert
}
function datesync() {
  [ -z "$1" ] && echo "[i] Usage: datesync <URL>" && return 1
  echo "$(date)"
  new_time=$(curl -sI "$1" | grep -i '^Date:' | cut -d' ' -f2-)
  [ -z "$new_time" ] && return 1
  sudo date -s "$new_time"
  echo "$(date)"
}
function ntlmsum() {
  if [ $# -eq 0 ]; then
    echo "[i] Usage: compute_ntlm_hash password"
  else
    password="$1"
    ntlm_hash=$(echo -n "$password" | iconv -t utf-16le | openssl dgst -md4 | awk '{print $2}')
    echo "NTLM Hash: $ntlm_hash"
  fi
}
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
}
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
}
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
}
