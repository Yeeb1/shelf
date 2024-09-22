#!/usr/bin/python3
import argparse
import sys

def read_hosts_file():
    with open("/etc/hosts", "r") as file:
        lines = file.readlines()
    return [line for line in lines if line.strip() and not line.startswith('#')]

def write_hosts_file(lines):
    with open("/etc/hosts", "w") as file:
        file.writelines(lines)

def list_entries():
    lines = read_hosts_file()
    print("{:<5} {:<15} {}".format("No.", "IP Address", "Domain(s)"))
    print("-" * 50)
    for idx, entry in enumerate(lines):
        parts = entry.split()
        ip = parts[0]
        domains = " ".join(parts[1:])
        print("{:<5} {:<15} {}".format(idx + 1, ip, domains))

def replace_entry(new_ip, domain):
    lines = read_hosts_file()
    updated = False
    for i, line in enumerate(lines):
        parts = line.split()
        if domain in parts[1:]:
            parts[0] = new_ip
            lines[i] = "\t".join(parts) + "\n"
            updated = True
            break
    if updated:
        write_hosts_file(lines)
        print(f"IP address for {domain} replaced with {new_ip}.")
    else:
        print("Domain not found. No changes made.")

def delete_entry():
    lines = read_hosts_file()
    list_entries()
    try:
        index = int(input("Enter the number of the entry to delete: ")) - 1
        if index >= 0 and index < len(lines):
            selected_line = lines[index]
            parts = selected_line.split()
            ip = parts[0]
            domains = parts[1:]
            if len(domains) > 1:
                print("Multiple domains found for this IP:")
                for idx, domain in enumerate(domains):
                    print(f"{idx + 1}: {domain}")
                print(f"{len(domains) + 1}: Delete all domains for this IP.")
                domain_index = int(input("Select a domain to delete or delete all domains: ")) - 1
                if domain_index == len(domains):
                    del lines[index]
                    print("All domains for this IP deleted successfully.")
                elif 0 <= domain_index < len(domains):
                    del domains[domain_index]
                    lines[index] = "\t".join([ip] + domains) + "\n"
                    print("Selected domain deleted successfully.")
                else:
                    print("Invalid selection.")
            else:
                del lines[index]
                print("Entry deleted successfully.")
            write_hosts_file(lines)
        else:
            print("Invalid entry number.")
    except ValueError:
        print("Please enter a valid number.")

def add_entry(ip, domain):
    lines = read_hosts_file()
    if ip:
        new_entry = f"{ip}\t{domain}\n"
        lines.append(new_entry)
    else:
        base_domain = domain.split('.')[-2] + '.' + domain.split('.')[-1]
        found = False
        for i, line in enumerate(lines):
            if base_domain in line:
                parts = line.split()
                if domain not in parts[1:]:
                    parts.append(domain)
                    lines[i] = "\t".join(parts) + "\n"
                found = True
                break
        if not found:
            print(f"No existing entry found for base domain {base_domain}. Please provide an IP to add a new entry.")
            return
    write_hosts_file(lines)
    print("Entry added/updated successfully.")

def main():
    parser = argparse.ArgumentParser(description="Edit /etc/hosts file")
    subparsers = parser.add_subparsers(dest="command", help="commands")

    parser_list = subparsers.add_parser("list", help="List all IP/domain entries")
    parser_delete = subparsers.add_parser("rm", help="Delete an entry or a specific domain from an entry")
    parser_add = subparsers.add_parser("add", help="Add an entry")
    parser_replace = subparsers.add_parser("replace", help="Replace the IP address for an existing entry")
    
    parser_add.add_argument("ip", nargs='?', default='', help="IP address (optional, leave empty to append subdomain)")
    parser_add.add_argument("domain", help="Domain name (include subdomains as needed)")
    
    parser_replace.add_argument("new_ip", help="New IP address")
    parser_replace.add_argument("domain", help="Domain to update")

    args = parser.parse_args()

    if args.command == "list":
        list_entries()
    elif args.command == "rm":
        delete_entry()
    elif args.command == "add":
        add_entry(args.ip, args.domain)
    elif args.command == "replace":
        replace_entry(args.new_ip, args.domain)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
