#!/usr/bin/python3

import requests
import argparse
import subprocess
from colorama import Fore, Style, init

init(autoreset=True)

def fetch_url(url, headers=None, max_redirects=3):
    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        response = session.get(url, headers=headers, allow_redirects=True)
        content_length = response.headers.get('Content-Length', len(response.content))
        return response.status_code, content_length, response
    except requests.exceptions.TooManyRedirects as e:
        return 0, f"Too many redirects: {e}", None
    except requests.exceptions.RequestException as e:
        return 0, f"Error: {e}", None

def process_subdomains(domain, baseline_size, subdomains, invalid_size=None, verbose=False, use_tls=False, port=None, max_redirects=3):
    protocol = 'https' if use_tls else 'http'
    port_part = f":{port}" if port else ""
    valid_domains = []

    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain}"
        url = f"{protocol}://{domain}{port_part}"  # URL points to the main domain
        headers = {'Host': full_domain}  # Host header includes the full subdomain

        status_code, size, response = fetch_url(url, headers, max_redirects)
        is_invalid_size = int(size) == invalid_size if invalid_size is not None else False
        is_valid = size != baseline_size and not is_invalid_size and status_code != 0

        color = Fore.GREEN if is_valid else Fore.RED
        status_message = "Valid" if is_valid else "Not Valid"

        print(f"{Fore.YELLOW}URL: {Fore.CYAN}{url} with Host: {full_domain}\n"
              f"  -> Response: {color}HTTP Status Code: {status_code}, Size Received: {size} bytes ({status_message})")

        if is_valid:
            valid_domains.append(full_domain)

        if verbose and response:
            headers_output = ', '.join([f"{k}: {v}" for k, v in response.headers.items()])
            body_preview = response.text[:500] + '...' if len(response.text) > 500 else response.text
            print(f"{Fore.BLUE}  -> Full response details:\n"
                  f"     {Fore.MAGENTA}Headers: {headers_output}\n"
                  f"     {Fore.MAGENTA}Body: {body_preview}")

    return valid_domains

def run_cewl(url):
    try:
        result = subprocess.run(['cewl', '-d', '2', '-m', '5', url], capture_output=True, text=True, check=True)
        words = set(result.stdout.lower().split())
        return list(words)
    except subprocess.CalledProcessError as e:
        print(f"Failed to run CeWL: {e}")
        return []

def main(domain, subdomain_input, verbose=False, use_tls=False, port=None, max_redirects=3, cewl_url=None, invalid_size=None):
    valid_domains = []
    if cewl_url:
        print(f"{Fore.YELLOW}Running CeWL on {cewl_url}")
        subdomains = run_cewl(cewl_url)
    else:
        try:
            with open(subdomain_input, 'r') as file:
                subdomains = [line.strip().lower() for line in file if line.strip()]
        except FileNotFoundError:
            subdomains = [subdomain_input.lower()]

    if subdomains:
        protocol = 'https' if use_tls else 'http'
        port_part = f":{port}" if port else ""
        main_url = f"{protocol}://{domain}{port_part}"
        _, baseline_size, _ = fetch_url(main_url)
        print(f"{Fore.GREEN}Main domain {domain} size: {baseline_size} bytes")
        valid_domains.extend(process_subdomains(domain, baseline_size, subdomains, invalid_size, verbose, use_tls, port, max_redirects))

    if valid_domains:
        print(f"{Fore.GREEN}Valid domains found:")
        for domain in valid_domains:
            print(f"{Fore.CYAN}{domain}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quick and dirty V-Host enumeration based on guesses.')
    parser.add_argument('domain', type=str, help='The domain')
    parser.add_argument('subdomain_input', nargs='?', type=str, default='', help='A subdomain or file containing subdomains.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print full output of the subdomain response.')
    parser.add_argument('--tls', action='store_true', help='Use HTTPS instead of HTTP.')
    parser.add_argument('--port', type=int, help='Specify a custom port for the requests.')
    parser.add_argument('--max-redirects', type=int, default=3, help='Maximum number of redirects to follow (default is 3).')
    parser.add_argument('--cewl', type=str, help='Run CeWL on a given URL to generate a list of subdomains.')
    parser.add_argument('--fs', type=int, help='Specify a response size that should be considered invalid.')

    args = parser.parse_args()

    main(args.domain, args.subdomain_input, args.verbose, args.tls, args.port, args.max_redirects, args.cewl, args.fs)
