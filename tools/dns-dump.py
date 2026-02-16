#!/usr/bin/env python3
import argparse
import socket
import json
import dns.resolver

def read_domains(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def resolve_domains(domains, dump_dns):
    results = []
    for domain in domains:
        domain_info = {'Domain': domain, 'IP': None, 'DNS Records': None}
        try:
            ip = socket.gethostbyname(domain)
            domain_info['IP'] = ip
            print(f"{domain}: {ip}")
        except (socket.gaierror, UnicodeError) as e:
            print(f"Failed to resolve {domain}: {e}")
            continue  # skip if parse errors out

        if dump_dns:
            try:
                dns_records = dump_all_dns_records(domain)
                domain_info['DNS Records'] = dns_records
            except UnicodeError as e:
                print(f"Failed to dump DNS for {domain}: {e}")

        results.append(domain_info)
    return results

def dump_all_dns_records(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    all_records = []
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answers.rrset is not None:
                records = [str(r) for r in answers.rrset]
                all_records.append({record_type: records})
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN):
            all_records.append({record_type: ['No record found']})
    return all_records

def save_to_json(results, filename='output.json'):
    with open(filename, 'w') as jsonfile:
        json.dump(results, jsonfile, indent=4)

def main():
    parser = argparse.ArgumentParser(description='Resolve domains to IP addresses and optionally dump all DNS records.')
    parser.add_argument('file', type=str, help='File containing list of domain names to resolve')
    parser.add_argument('--json', action='store_true', help='Save the results to JSON file')
    parser.add_argument('--dump', action='store_true', help='Dump all DNS entries for the domain')

    args = parser.parse_args()

    domains = read_domains(args.file)

    results = resolve_domains(domains, args.dump)

    if args.json:
        save_to_json(results)

if __name__ == '__main__':
    main()
