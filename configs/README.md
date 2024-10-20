# Configs

## [.tmux.conf.local](./.tmux.conf.local) - Custom Configuration for tmux Sessions

The `.tmux.conf.local` is left pretty default with minor tweaks on the appearance.

## [.zsh_alias](./.zsh_alias.sh) - Handy Shortcuts for Faster Terminal Commands

`.zsh_alias` contains a collection of useful aliases to streamline common terminal tasks and commands, helping me operate more efficiently. 

## [.zsh_functions](./.zsh_functions.sh) - Custom Functions for Enhanced Shell Automation

`.zsh_functions` contains custom shell functions that automate complex or repetitive tasks, making it easier to perform advanced operations in the terminal. 


## [.zshrc](./.zshrc) - Main Configuration File for Zsh Environment

The `.zshrc` is left pretty default with minor tweaks to ensure a smooth workflow. 

## [customs Function](https://github.com/Yeeb1/shelf/blob/ebf6a7a7120cd97a49036cb7013ff817892ad6a0/configs/.zsh_functions.sh#L1) - List All Custom Aliases and Functions with Descriptions

The `customs` function is designed to display all the custom aliases and functions defined in the zsh configuration. It reads from the `.zsh_alias.sh` and `.zsh_functions.sh` files, and outputs the name and a brief description of each alias or function, making it easier to remember and manage these shortcuts.

```
ALIASES:
-----------------------------
[+] bat - Alias to use batcat instead of cat
[+] chains - Navigate to Vulnlab chains directory
[+] challenges - Navigate to the HTB challenges directory
[+] ctf - Navigate to the root CTF directory
[+] dockershellsh - Runs a Docker container with a sh shell
[+] dockershell - Runs a Docker container with a bash shell
[+] endvpn - Start the endgames VPN
[+] f - search files and directories from the current directory
[+] fort - Navigate to the HTB fortress directory
[+] fortvpn - Start the fortress VPN
[+] htb - Navigate to HTB directory
[+] htbvpn - Start the HTB VPN
[+] la - listing all files except . and ..
[+] ll - listing all files, including hidden ones, with detailed info
[+] l - compact listing of files in columns
[+] ls - lsd instead of ls
[+] machines - Navigate to the HTB machines directory
[+] mkctf - Creates commonly used directories for CTFs
[+] mkserve - Alias to reset and relink the 'serve' folder
[+] ntlm.pw - Fetches NTLM hashes from ntlm.pw for a given value
[+] peas - Downloads linpeas.sh
[+] prolabsvpn - Start the pro labs VPN
[+] relvpn - Start the release VPN
[+] rtlabs - Navigate to Vulnlab RTL directory
[+] rtvpn - Start RTL VPN
[+] t - display the directory structure in tree format
[+] vlvpn - Start Vulnlab VPN
[+] vmachines - Navigate to Vulnlab machines directory
[+] vuln - Navigate to Vulnlab directory
[+] xc - Alias for copying to the clipboard

FUNCTIONS:
-----------------------------
[+] bloodhound_import - Import BloodHound data using knowsmore and sync it with the BloodHound database
[+] crawl - Crawl subdomains for a given URL using gospider
[+] crt.sh - Query crt.sh for certificates and list unique subdomains for a given domain
[+] customs -         description=$(awk "/^function $func_name\(\)/,/^}/" ~/.zsh_functions.sh | grep -m 1 '# Description:' | sed 's///' | sed 's///g')
[+] datesync - Sync the local date with the time from a remote server
[+] dockershellhere - Run docker shell with /bin/bash in the current directory
[+] dockershellshhere - Run docker shell with /bin/sh in the current directory
[+] export-krbcc - Set the KRB5CCNAME environment variable to a Kerberos ticket file
[+] ffuf_vhost - FFUF for VHost fuzzing with the Jhaddix wordlist
[+] ffuf_vhost_quick - Quick FFUF for VHost fuzzing with a smaller wordlist
[+] ips - Show global scope IP addresses for all interfaces
[+] ligolo-server - Set up the Ligolo tunneling server
[+] nmap_default - Run a default TCP Nmap scan and save results in ./nmap
[+] nmap_list - Run a full Nmap scan on a list of IPs from a file
[+] nmap_udp - Run a default UDP Nmap scan and save results in ./nmap
[+] ntlmsum - Compute the NTLM hash of a given password
[+] rdp - Run RDP with credentials or NTLM hash
[+] rdp_noauth - Connect to RDP without authentication (for unauthenticated access)
[+] responder_dump - Extract NTLM hashes from Responder logs and save them to a file
[+] rock_john - Run John the Ripper using the RockYou wordlist
[+] sshportfwd - Print information about SSH port forwarding (local, remote, and dynamic)                                                                         
```
