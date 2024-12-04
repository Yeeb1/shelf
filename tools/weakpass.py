#!/usr/bin/env python3

import argparse
import requests
import sys
import os
import json
import re
from json import JSONDecodeError

BASE_URL = 'https://weakpass.com/api/v1'

def is_valid_hash(hash_value):
    """Check if the input is a valid hash (hexadecimal string of length 32 to 64)."""
    if re.fullmatch(r'[a-fA-F0-9]{32,64}', hash_value):
        return True
    return False

def search_hash(hash_value, output, output_format, highlight):
    """Search for a supplied hash in the Weakpass database."""
    hash_value = hash_value.lower() 
    url = f"{BASE_URL}/search/{hash_value}.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            try:
                data = response.json()
            except JSONDecodeError as e:
                print(f"JSON decoding error: {e}")
                print("Response text that caused the error:")
                print(response.text)
                return
            if data:
                if output_format == 'json':
                    output_data = data
                else:
                    output_data = f"[!] Type: {data['type']}, Hash: {data['hash']}, Password: {data['pass']}"
                handle_output(output_data, output, output_format)
            else:
                print("No data found for the given hash.")
        elif response.status_code == 404:
            print(f"No data associated with the provided hash: {hash_value}")
        else:
            print(f"Error: {response.status_code} - {response.reason}")
            print("Response content:")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def search_hashes_from_file(file_path, output, output_format, highlight):
    """Search for multiple hashes provided in a file."""
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' does not exist.")
        sys.exit(1)

    with open(file_path, 'r') as f:
        hashes = [line.strip() for line in f if line.strip()]

    results = []
    for hash_value in hashes:
        hash_value = hash_value.lower()
        if not is_valid_hash(hash_value):
            print(f"Invalid hash skipped: {hash_value}")
            continue
        url = f"{BASE_URL}/search/{hash_value}.json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                try:
                    data = response.json()
                except JSONDecodeError as e:
                    print(f"JSON decoding error for hash {hash_value}: {e}")
                    continue
                if data:
                    if output_format == 'json':
                        results.append(data)
                    else:
                        output_data = f"[!] Type: {data['type']}, Hash: {data['hash']}, Password: {data['pass']}"
                        print(output_data)
                else:
                    print(f"No data found for the hash: {hash_value}")
            elif response.status_code == 404:
                print(f"No data associated with the provided hash: {hash_value}")
            else:
                print(f"Error for hash {hash_value}: {response.status_code} - {response.reason}")
                print("Response content:")
                print(response.text)
        except requests.exceptions.RequestException as e:
            print(f"An error occurred for hash {hash_value}: {e}")

    if output_format == 'json' and results:
        handle_output(results, output, output_format)

def generate_wordlist(string, ruleset, data_type, output, output_format):
    """Generate a wordlist for a specific string based on a Hashcat ruleset."""
    url = f"{BASE_URL}/generate/{string}"
    params = {
        'set': ruleset,
        'type': data_type
    }
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            if data_type == 'json':
                try:
                    data = response.json()
                except JSONDecodeError as e:
                    print(f"JSON decoding error: {e}")
                    print("Response text that caused the error:")
                    print(response.text)
                    return
                output_data = "\n".join(data)
            else:
                output_data = response.text
            handle_output(output_data, output, output_format, command='generate', string=string)
        else:
            print(f"Error: {response.status_code} - {response.reason}")
            print("Response content:")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def generate_wordlist_custom(string, rules_file, data_type, output, output_format):
    """Generate a wordlist using custom Hashcat rules provided in a file."""
    url = f"{BASE_URL}/generate/custom/{string}"
    params = {'type': data_type}
    with open(rules_file, 'r') as f:
        rules_content = f.read()
    headers = {'Content-Type': 'text/plain'}
    try:
        response = requests.post(url, data=rules_content, headers=headers, params=params)
        if response.status_code == 200:
            if data_type == 'json':
                try:
                    data = response.json()
                except JSONDecodeError as e:
                    print(f"JSON decoding error: {e}")
                    print("Response text that caused the error:")
                    print(response.text)
                    return
                output_data = "\n".join(data)
            else:
                output_data = response.text
            handle_output(output_data, output, output_format, command='generate', string=string)
        else:
            print(f"Error: {response.status_code} - {response.reason}")
            print("Response content:")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def get_range(prefix, hash_type, filter_type, output, output_format):
    """Retrieve a list of hash-password pairs based on a specific prefix."""
    prefix = prefix.lower()  # Convert prefix to lowercase, seems like the the backend doesnt like upper case hashes
    url = f"{BASE_URL}/range/{prefix}.json"
    params = {
        'type': hash_type,
        'filter': filter_type
    }
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            try:
                data = response.json()
            except JSONDecodeError as e:
                print(f"JSON decoding error: {e}")
                print("Response text that caused the error:")
                print(response.text)
                return
            if data:
                if output_format == 'json':
                    output_data = data
                else:
                    if filter_type == 'hash':
                        output_data = "\n".join(item['hash'] for item in data)
                    elif filter_type == 'pass':
                        output_data = "\n".join(item['pass'] for item in data)
                    else:
                        output_data = "\n".join(
                            f"Hash: {item['hash']}, Password: {item['pass']}" for item in data
                        )
                handle_output(output_data, output, output_format)
            else:
                print("No data found for the given prefix.")
        elif response.status_code == 404:
            print("No data associated with the provided prefix.")
        else:
            print(f"Error: {response.status_code} - {response.reason}")
            print("Response content:")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def list_wordlists(output, output_format):
    """List all available wordlists and rules."""
    url = f"{BASE_URL}/wordlists"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            response_text = response.text.strip()
            if response_text:
                wordlists = response_text.split('\n')
                if output_format == 'json':
                    output_data = wordlists
                else:
                    output_data = "\n".join(wordlists)
                handle_output(output_data, output, output_format)
            else:
                print("No wordlists found.")
        else:
            print(f"Error: {response.status_code} - {response.reason}")
            print("Response content:")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def get_wordlist(wordlist_name, output, output_format):
    """Retrieve the content of a specific wordlist or rule."""
    url = f"{BASE_URL}/wordlists/{wordlist_name}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            output_data = response.text
            if not output:
                output = wordlist_name
            try:
                with open(output, 'w') as f:
                    f.write(output_data)
                print(f"Wordlist '{wordlist_name}' saved to '{output}'")
            except IOError as e:
                print(f"Failed to write to file '{output}': {e}")
        elif response.status_code == 404:
            print(f"No data associated with the provided wordlist: {wordlist_name}")
        else:
            print(f"Error: {response.status_code} - {response.reason}")
            print("Response content:")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def handle_output(data, output_file, output_format, command=None, string=None):
    """Handle the output data, print to console or save to a file."""
    if command == 'generate':
        if not output_file:
            output_file = f"{string}_wordlist.txt"
        try:
            with open(output_file, 'a') as f: 
                f.write(data)
                if not data.endswith('\n'):
                    f.write('\n')
            print(f"Wordlist saved to {output_file}")
        except IOError as e:
            print(f"Failed to write to file {output_file}: {e}")
    else:
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    if output_format == 'json':
                        json.dump(data, f, indent=2)
                    else:
                        f.write(data)
                print(f"Output saved to {output_file}")
            except IOError as e:
                print(f"Failed to write to file {output_file}: {e}")
        else:
            if output_format == 'json':
                print(json.dumps(data, indent=2))
            else:
                print(data)

def main():
    parser = argparse.ArgumentParser(
        description='Weakpass API Client - Query hashes and generate wordlists on demand.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output', help='Save output to a file instead of printing.'
    )
    output_group.add_argument(
        '--format', choices=['json', 'txt'], default='txt',
        help='Output format (default: txt).'
    )

    parser_search = subparsers.add_parser(
        'search', help='Search for a supplied hash or hashes from a file in the database.'
    )
    parser_search.add_argument(
        'input', help='Hash to search for or file containing list of hashes.'
    )
    parser_search.add_argument(
        '--highlight', action='store_true', help='Highlight output when a hash is recovered.'
    )

    parser_generate = subparsers.add_parser(
        'generate', help='Generate a wordlist for a specific string.'
    )
    parser_generate.add_argument(
        'string', help='String to generate the wordlist for.'
    )
    parser_generate.add_argument(
        '--set', default='online.rule',
        choices=[
            'online.rule', 'top_3000.rule', 'top_1500.rule', 'top_750.rule',
            'top_500.rule', 'top_250.rule', 'nsa64.rule', 'numbers.rule',
            'numbers100.rule', 'years_1900_2025.rule', 'years.rule', 'symbols.rule'
        ],
        help='Select a specific ruleset for wordlist generation (default: online.rule).'
    )
    parser_generate.add_argument(
        '--type', default='txt', choices=['json', 'txt'],
        help='Type of the return data (default: txt).'
    )
    parser_generate.add_argument(
        '--rules-file', help='Use custom rules from a file instead of predefined sets.'
    )
    output_group_generate = parser_generate.add_argument_group('Output Options')
    output_group_generate.add_argument(
        '-o', '--output', help='Filename to save the generated wordlist.'
    )

    parser_range = subparsers.add_parser(
        'range', help='Retrieve hash-password pairs based on a specific prefix.'
    )
    parser_range.add_argument(
        'prefix', help='Hash prefix (5 to 64 hex characters).'
    )
    parser_range.add_argument(
        '--type', default='md5',
        choices=['md5', 'ntlm', 'sha1', 'sha256'],
        help='Specify the type of hash list (default: md5).'
    )
    parser_range.add_argument(
        '--filter', choices=['hash', 'pass'],
        help='Show only the pass or hash in response.'
    )

    subparsers.add_parser(
        'list-wordlists', help='List all available wordlists and rules.'
    )

    parser_get_wordlist = subparsers.add_parser(
        'get-wordlist', help='Retrieve the content of a specific wordlist or rule.'
    )
    parser_get_wordlist.add_argument(
        'wordlist', help='Name of the wordlist to retrieve.'
    )

    args = parser.parse_args()

    output_file = args.output if hasattr(args, 'output') else None
    output_format = args.format if hasattr(args, 'format') else 'txt'

    if args.command == 'search':
        highlight = args.highlight
        input_value = args.input
        if is_valid_hash(input_value):
            search_hash(input_value, output_file, output_format, highlight)
        elif os.path.isfile(input_value):
            search_hashes_from_file(input_value, output_file, output_format, highlight)
        else:
            print(f"Invalid hash or file not found: {input_value}")
    elif args.command == 'generate':
        if args.rules_file:
            if not os.path.isfile(args.rules_file):
                print(f"Rules file '{args.rules_file}' does not exist.")
                sys.exit(1)
            generate_wordlist_custom(args.string, args.rules_file, args.type, output_file, output_format)
        else:
            generate_wordlist(args.string, args.set, args.type, output_file, output_format)
    elif args.command == 'range':
        get_range(args.prefix, args.type, args.filter, output_file, output_format)
    elif args.command == 'list-wordlists':
        list_wordlists(output_file, output_format)
    elif args.command == 'get-wordlist':
        get_wordlist(args.wordlist, output_file, output_format)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
