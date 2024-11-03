#!/bin/bash

# Description: Sync the local date with the time from a remote host via NTP, rdate, or HTTP(S).
# If "reset" is passed as the hostname, reset the time to the system's timezone and re-enable NTP synchronization.

# Function to disable NTP synchronization
disable_ntp_sync() {
    echo "[+] Disabling NTP synchronization..."
    sudo timedatectl set-ntp false
}

# Function to enable NTP synchronization
enable_ntp_sync() {
    echo "[+] Enabling NTP synchronization..."
    sudo timedatectl set-ntp true
}

# Check if hostname or IP is provided
if [ $# -eq 0 ]; then
    echo "[+] Usage: $0 <hostname_or_ip|reset>"
    exit 1
fi

HOST="$1"

echo "[+] Current system time: $(date)"

if [ "$HOST" = "reset" ]; then
    # Reset to the system's timezone and re-enable NTP sync
    echo "[+] Resetting time to the system's timezone..."

    # Get the system's timezone
    if [ -f /etc/timezone ]; then
        TIMEZONE=$(cat /etc/timezone)
    else
        echo "[+] /etc/timezone not found. Using UTC as default timezone."
        TIMEZONE="UTC"
    fi

    # Set the timezone
    echo "[+] Setting system timezone to $TIMEZONE"
    sudo timedatectl set-timezone "$TIMEZONE"

    # Enable NTP synchronization
    enable_ntp_sync

    echo "[+] Updated system time: $(date)"
    exit 0
fi

echo "[+] Attempting to sync time with $HOST..."

# Disable NTP synchronization before setting time
disable_ntp_sync

# Try to sync via NTP using ntpdate
if command -v ntpdate >/dev/null 2>&1; then
    echo "[+] NTP is available. Syncing time using ntpdate..."
    sudo ntpdate "$HOST"
    if [ $? -eq 0 ]; then
        echo "[+] Updated system time: $(date)"
        echo "[+] NTP synchronization remains disabled."
        exit 0
    else
        echo "[+] ntpdate failed to sync time."
    fi
else
    echo "[+] ntpdate not found."
fi

# Try to sync via rdate
if command -v rdate >/dev/null 2>&1; then
    echo "[+] rdate is available. Syncing time using rdate..."
    sudo rdate -s "$HOST"
    if [ $? -eq 0 ]; then
        echo "[+] Updated system time: $(date)"
        echo "[+] NTP synchronization remains disabled."
        exit 0
    else
        echo "[+] rdate failed to sync time."
    fi
else
    echo "[+] rdate not found."
fi

# If NTP and rdate fail, try to get date from HTTP(S) headers
echo "[+] ntpdate and rdate not successful or not found. Checking for HTTP(S) service..."

# Check if HTTP or HTTPS is available
if nc -z "$HOST" 80 >/dev/null 2>&1; then
    PROTOCOL="http"
elif nc -z "$HOST" 443 >/dev/null 2>&1; then
    PROTOCOL="https"
else
    echo "[+] No NTP, rdate, or HTTP(S) service available on $HOST."
    exit 1
fi

# Get date from HTTP headers
echo "[+] Fetching date from $PROTOCOL://$HOST..."
new_time=$(curl -sI "$PROTOCOL://$HOST" | grep -i '^Date:' | cut -d' ' -f2-)

if [ -z "$new_time" ]; then
    echo "[+] Failed to retrieve date from $PROTOCOL://$HOST."
    exit 1
fi

echo "[+] Retrieved date: $new_time"
echo "[+] Setting system time..."
# Use timedatectl to set the time
sudo timedatectl set-time "$new_time"
echo "[+] Updated system time: $(date)"
echo "[+] NTP synchronization remains disabled."

exit 0
