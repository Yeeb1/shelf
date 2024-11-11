########### General Alias Configuration #############
alias ls='lsd' # lsd instead of ls
alias ll='lsd -la' # listing all files, including hidden ones, with detailed info
alias la='lsd -A' # listing all files except . and ..
alias l='lsd -CF' # compact listing of files in columns
alias f='find .' # search files and directories from the current directory
alias t='tree .' # display the directory structure in tree format
alias xc="xclip -selection clipboard" # Alias for copying to the clipboard
########### General Alias Configuration #############

########### General CTF Aliases #############
alias dockershell="sudo docker run --rm -i -t --entrypoint=/bin/bash" # Runs a Docker container with a bash shell
alias dockershellsh="sudo docker run --rm -i -t --entrypoint=/bin/sh" # Runs a Docker container with a sh shell
alias ntlm.pw='function _ntlm(){ curl https://ntlm.pw/$1; }; _ntlm' # Fetches NTLM hashes from ntlm.pw for a given value
alias bat="batcat" # Alias to use batcat instead of cat
alias peas='wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O p' # Downloads linpeas.sh
alias mkctf='mkdir files serve loot tools' # Creates commonly used directories for CTFs
alias mkserve='rm -rf s && ln -s /opt/arsenal/serve s' # Alias to reset and relink the 'serve' folder
alias noir='sudo docker run -it --rm -v "$(pwd):/workspace" --entrypoint "" ghcr.io/owasp-noir/noir:latest noir -b /workspace' # Runs a OWASP Noir in CWD
alias dl='dclog.py' # Alias for faster internaction with Discord webhook bot 
alias dm='dcmanage.py' # Alias to manage Webhooks and Threads for Discord bot
alias ds='dcsend.py' # Alias to send a file via Discord bot
alias dc='dcclip.py' # Alias to send the clipboard via Discord bot
########### General CTF Aliases #############


########### Vulnlab Aliases #############
alias vuln="cd /home/kali/ctf/vulnlab" # Navigate to Vulnlab directory
alias vmachines="cd /home/kali/ctf/vulnlab/machines" # Navigate to Vulnlab machines directory
alias chains="cd /home/kali/ctf/vulnlab/chains" # Navigate to Vulnlab chains directory
alias rtlabs="cd /home/kali/ctf/vulnlab/rtl" # Navigate to Vulnlab RTL directory
alias vlvpn="sudo openvpn /home/kali/ovpn/692063591469416498_aws.ovpn" # Start Vulnlab VPN
alias rtvpn="sudo openvpn /home/kali/ovpn/692063591469416498_rtl01.ovpn" # Start RTL VPN
########### Vulnlab Aliases #############

########### HTB Aliases #############
alias machines="cd /home/kali/ctf/htb/machines" # Navigate to the HTB machines directory
alias fort="cd /home/kali/ctf/htb/fortress" # Navigate to the HTB fortress directory
alias challenges="cd /home/kali/ctf/htb/challenges" # Navigate to the HTB challenges directory
alias ctf="cd /home/kali/ctf" # Navigate to the root CTF directory
alias htbvpn="sudo openvpn /home/kali/ovpn/lab_Yeeb.ovpn" # Start the HTB VPN
alias relvpn="sudo openvpn /home/kali/ovpn/competitive_Yeeb.ovpn" # Start the release VPN
alias fortvpn="sudo openvpn /home/kali/ovpn/fortresses_Yeeb.ovpn" # Start the fortress VPN
alias endvpn="sudo openvpn /home/kali/ovpn/endgames_Yeeb.ovpn" # Start the endgames VPN
alias prolabsvpn="sudo openvpn /home/kali/ovpn/pro_labs_Yeeb.ovpn" # Start the pro labs VPN
alias htb='cd /home/kali/ctf/htb' # Navigate to HTB directory
########### HTB Aliases #############
