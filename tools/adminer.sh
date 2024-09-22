#!/bin/bash

show_help() {
  echo "Usage: adminer <domain>"
  echo "Run the AD-miner tool with a specified domain and secure password input."
  echo
  echo "Arguments:"
  echo "  <domain>    The domain or cache prefix to use with the AD-miner tool."
}

if [ $# -eq 0 ]; then
  echo "Error: No domain specified."
  show_help
  exit 1
fi

read -s -p "Enter password: " pass
echo
AD-miner -cf "$1" -u neo4j -p "$pass" -b bolt://127.0.0.1:7687 --rdp
unset pass
                 
