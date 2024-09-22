#!/bin/bash

COOKIE=''
FILE_PATH=''
OUTPUT_FILE='urls.txt'

usage() {
    echo "Usage: $0 -f <domains_file> [-c <cookie>]"
    echo "  -f  Path to the file containing domains."
    echo "  -c  Cookie for session authentication (optional)."
    echo "  -h  Display this help message."
    exit 1
}

while getopts 'hf:c:' flag; do
    case "${flag}" in
        f) FILE_PATH="${OPTARG}" ;;
        c) COOKIE="Cookie: ${OPTARG}" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$FILE_PATH" ]; then
    echo "Error: Domains file path is required."
    usage
fi


if [ ! -f "$FILE_PATH" ]; then
    echo "Error: Domains file not found: $FILE_PATH"
    exit 1
fi


while read -r domain; do
    echo "[+] Processing domain: $domain"

    httpx_output=$(echo "$domain" | httpx -silent)
    if [ -z "$httpx_output" ]; then
        echo "[-] No output from httpx for domain: $domain"
        continue
    fi

    echo "$httpx_output" | gospider -c 10 -q -r -w -a --sitemap --robots --subs -H "$COOKIE" >> "$OUTPUT_FILE"

    paramspider -d "$domain" --output ./paramspider.txt --level high > /dev/null 2>&1
    if [ -f paramspider.txt ]; then
        grep http paramspider.txt 2>/dev/null | sort -u | grep "$domain" >> "$OUTPUT_FILE"
        rm paramspider.txt
    fi

    gau "$domain" >> "$OUTPUT_FILE"
    echo "$httpx_output" | hakrawler >> "$OUTPUT_FILE"
    echo "$httpx_output" | galer -s >> "$OUTPUT_FILE"

done < "$FILE_PATH"

cat "$OUTPUT_FILE" | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u | qsreplace -a > urls_clean.txt
echo "URL extraction complete."
