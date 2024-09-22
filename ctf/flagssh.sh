#!/bin/bash

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <username>@<hostname> [<password_or_ssh_key>]"
    exit 1
fi

USER_HOST=$1
USERNAME=${USER_HOST%@*}
HOSTNAME=${USER_HOST#*@}

if [ "$#" -eq 2 ]; then
    AUTH=$2
else
    read -s -p "Password: " AUTH
    echo
fi

if [ -f "$AUTH" ]; then
    AUTH_TYPE="key"
else
    AUTH_TYPE="password"
fi

REMOTE_SCRIPT=$(mktemp /tmp/remote_script.XXXXXX)
cat << 'EOF' > $REMOTE_SCRIPT
#!/bin/bash

function check_command {
    local output="$1"
    local message="$2"
    local fail_message="$3"
    local delimiter="\e[33m==================================================\e[0m"
    
    echo -e "$delimiter"
    if [ -n "$output" ]; then
        echo -e "\e[32m$message\e[0m"
        echo -e "\e[34m$output\e[0m"
    else
        echo -e "\e[31m$fail_message\e[0m"
    fi
    echo -e "$delimiter"
}

id_output=$(id)
check_command "$id_output" "User identity:" "Could not retrieve user identity"

user_txt=$(cat /home/*/user.txt 2>/dev/null)
check_command "$user_txt" "User file found:" "User file not found"

root_txt=$(cat /root/root.txt 2>/dev/null)
check_command "$root_txt" "Root file found:" "Root file not found or permission denied"

sudo_output=$(echo $AUTH | sudo -S -l 2>/dev/null)
check_command "$sudo_output" "Sudo privileges:" "No sudo privileges or permission denied"
EOF

chmod +x $REMOTE_SCRIPT

function execute_remote_script {
    scp_command=$1
    ssh_command=$2

    eval "$scp_command $REMOTE_SCRIPT $USERNAME@$HOSTNAME:/tmp/remote_script.sh"

    eval "$ssh_command 'AUTH=$AUTH bash /tmp/remote_script.sh'"

    eval "$ssh_command"
}

if [ "$AUTH_TYPE" == "password" ]; then
    SCP_COMMAND="sshpass -p '$AUTH' scp -o StrictHostKeyChecking=no"
    SSH_COMMAND="sshpass -p '$AUTH' ssh -tt -o StrictHostKeyChecking=no $USERNAME@$HOSTNAME"
    execute_remote_script "$SCP_COMMAND" "$SSH_COMMAND"

elif [ "$AUTH_TYPE" == "key" ]; then
    SCP_COMMAND="scp -i '$AUTH' -o StrictHostKeyChecking=no"
    SSH_COMMAND="ssh -i '$AUTH' -tt -o StrictHostKeyChecking=no $USERNAME@$HOSTNAME"
    execute_remote_script "$SCP_COMMAND" "$SSH_COMMAND"

else
    echo "Unknown authentication type."
    exit 1
fi

rm -f $REMOTE_SCRIPT
