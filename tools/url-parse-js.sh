#!/bin/bash

COOKIE=''
DOMAINS_FILE=''
URLS_FILE=''

usage() {
    echo "Usage: $0 -d <domains_file> -u <urls_file> [-c <cookie>]"
    echo "  -d  Path to the file containing domains."
    echo "  -u  Path to the file containing URLs."
    echo "  -c  Cookie for session authentication (optional)."
    echo "  -h  Display this help message."
    exit 1
}

while getopts 'hd:u:c:' flag; do
    case "${flag}" in
        d) DOMAINS_FILE="${OPTARG}" ;;
        u) URLS_FILE="${OPTARG}" ;;
        c) COOKIE="Cookie: ${OPTARG}" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$DOMAINS_FILE" ] || [ -z "$URLS_FILE" ]; then
    echo "Error: Domains file and URLs file are required."
    usage
fi

JS_URLS_FILE='js_urls.txt'

if [ ! -f "$DOMAINS_FILE" ] || [ ! -f "$URLS_FILE" ]; then
    echo "Error: Specified file not found."
    exit 1
fi

while read -r domain; do
    echo "[+] Processing domain: $domain"

    grep "\.js" "$URLS_FILE" | grep "$domain" >> "$JS_URLS_FILE"
    sort -u "$URLS_FILE" "$JS_URLS_FILE" | getJS --timeout 3 --insecure --complete --nocolors -H "$COOKIE" | grep "^http" | grep "$domain" | sed "s/\?.*//" >> "$JS_URLS_FILE"

    httpx -silent -l "$JS_URLS_FILE" -H "$COOKIE" -fc 304,404 -srd source_code/ >> js.tmp
    mv js.tmp "$JS_URLS_FILE"
done < "$DOMAINS_FILE"

echo "JavaScript URL processing complete."
