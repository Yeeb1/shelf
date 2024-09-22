import json
import argparse
import csv

def load_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def search_permissions(data, additional_exclusions, active_only):
    results = []

    exclude_groups = [
        "Domain Admins", "Authenticated Users", "Enterprise Admins",
        "Domänen-Admins", "Organisations-Admins", "Domain Controllers",
        "Enterprise Domain Controllers", "Enterprise Read-only Domain Controllers",
        "RAS and IAS Servers", "Administrator", "Domänencontroller",
        "Schreibgeschützte Domänencontroller der Organisation"
    ] + additional_exclusions

    for template_id, template in data.get('Certificate Templates', {}).items():
        template_name = template.get('Template Name', 'Unknown')
        is_activated = template.get('Enabled', False)
        if active_only and not is_activated:
            continue
        client_authentication = template.get('Client Authentication', False)
        enrollee_supplies_subject = template.get('Enrollee Supplies Subject', False)
        permissions = template.get('Permissions', {})
        vulnerabilities = template.get('[!] Vulnerabilities', {})

        enrollment_permissions = permissions.get('Enrollment Permissions', {}).get('Enrollment Rights', [])
        object_control_permissions = permissions.get('Object Control Permissions', {})

        write_owner_principals = object_control_permissions.get('Write Owner Principals', [])
        write_dacl_principals = object_control_permissions.get('Write Dacl Principals', [])
        write_property_principals = object_control_permissions.get('Write Property Principals', [])

        all_permissions = [
            ('Enrollment Permissions', enrollment_permissions),
            ('Write Owner Principals', write_owner_principals),
            ('Write Dacl Principals', write_dacl_principals),
            ('Write Property Principals', write_property_principals)
        ]

        template_results = []
        for permission_type, principals in all_permissions:
            filtered_principals = [principal for principal in principals if not any(group in principal for group in exclude_groups)]
            if filtered_principals:
                template_results.append({
                    'Permission Type': permission_type,
                    'Principals': ', '.join(filtered_principals)
                })

        if template_results or vulnerabilities:
            if client_authentication and enrollee_supplies_subject:
                vulnerabilities = vulnerabilities or {}
                if 'ESC1' not in vulnerabilities:
                    vulnerabilities['ESC1'] = 'Unreachable... yet'
            results.append({
                'Template ID': template_id,
                'Template Name': template_name,
                'Activated': is_activated,
                'Client Authentication': client_authentication,
                'Enrollee Supplies Subject': enrollee_supplies_subject,
                'Vulnerabilities': vulnerabilities,
                'Details': template_results
            })

    return results

def save_to_csv(results, csv_file_path):
    with open(csv_file_path, 'w', newline='') as csvfile:
        fieldnames = ['Template ID', 'Template Name', 'Activated', 'Client Authentication', 'Enrollee Supplies Subject', 'Vulnerability', 'Permission Type', 'Principals']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            for detail in result['Details']:
                writer.writerow({
                    'Template ID': result['Template ID'],
                    'Template Name': result['Template Name'],
                    'Activated': result['Activated'],
                    'Client Authentication': 'Yes' if result['Client Authentication'] else 'No',
                    'Enrollee Supplies Subject': 'Yes' if result['Enrollee Supplies Subject'] else 'No',
                    'Vulnerability': result['Vulnerabilities'],
                    'Permission Type': detail['Permission Type'],
                    'Principals': detail['Principals']
                })

def print_results(results):
    if not results:
        print("No anomalies found.")
    else:
        for result in results:
            print(f"Template ID: {result['Template ID']}")
            print(f"Template Name: {result['Template Name']}")
            print(f"Activated: {'Yes' if result['Activated'] else 'No'}")
            if result['Client Authentication']:
                print("[!] Client Authentication: Yes")
            if result['Enrollee Supplies Subject']:
                print("[!] Enrollee Supplies Subject: Yes")
            if result['Vulnerabilities']:
                for vuln_key, vuln_value in result['Vulnerabilities'].items():
                    print(f"[!] {vuln_key}: {vuln_value}")
            print("=" * 50)
            for detail in result['Details']:
                print(f"  Permission Type: {detail['Permission Type']}")
                print(f"    Principals: {detail['Principals']}")
                print("    " + "-" * 30)
            print("\n" + "=" * 50 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description='Parse Certipy JSON output for anomalies in ACLs to help hunt for possible targets.'
    )
    parser.add_argument('file_path', type=str, help='Path to the JSON file')
    parser.add_argument('--csv', type=str, help='Path to save the output CSV file')
    parser.add_argument('--exclude', type=str, nargs='*', default=[], help='Additional principals to exclude')
    parser.add_argument('--active-only', action='store_true', help='Only check active certificates')
    args = parser.parse_args()

    data = load_json(args.file_path)
    results = search_permissions(data, args.exclude, args.active_only)
    
    if args.csv:
        save_to_csv(results, args.csv)
        print(f"Results saved to {args.csv}")
    else:
        print_results(results)

if __name__ == "__main__":
    main()
