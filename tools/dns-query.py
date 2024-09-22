import argparse
import dns.resolver

def dump_all_dns_records(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    all_records = {}
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answers.rrset is not None:
                records = [str(r) for r in answers.rrset]
                all_records[record_type] = records
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN):
            all_records[record_type] = ['No record found']
    return all_records

def main():
    parser = argparse.ArgumentParser(description="DNS Record Lookup Tool")
    parser.add_argument("domain", type=str, help="Domain name to look up DNS records for")
    args = parser.parse_args()

    domain = args.domain
    dns_records = dump_all_dns_records(domain)

    print(f"DNS Records for {domain}:")
    for record_type, records in dns_records.items():
        print(f"{record_type}: {records}")

if __name__ == '__main__':
    main()
