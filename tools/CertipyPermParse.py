import json
import argparse
import csv
import re

def load_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def search_permissions(data, additional_exclusions, active_only):
    results = []

    # Default list of common principals to exclude from anomalies
    default_exclude_groups = [
        "Domain Admins", "Authenticated Users", "Enterprise Admins",
        "Domänen-Admins", "Organisations-Admins", "Domain Controllers",
        "Enterprise Domain Controllers", "Enterprise Read-only Domain Controllers",
        "RAS and IAS Servers", "Administrator", "Domänencontroller",
        "Schreibgeschützte Domänencontroller der Organisation"
    ]

    exclude_groups = default_exclude_groups + additional_exclusions

    standard_principals = set(exclude_groups)

    def is_uncommon(principal):
        principal_name = principal.split('\\')[-1]
        return principal_name not in standard_principals

    for template_id, template in data.get('Certificate Templates', {}).items():
        template_name = template.get('Template Name', 'Unknown')
        is_activated = template.get('Enabled', False)
        if active_only and not is_activated:
            continue
        client_authentication = template.get('Client Authentication', False)
        enrollee_supplies_subject = template.get('Enrollee Supplies Subject', False)
        permissions = template.get('Permissions', {})
        vulnerabilities = template.get('[!] Vulnerabilities', {})

        if not vulnerabilities:
            vulnerabilities = {}

        enrollment_permissions = permissions.get('Enrollment Permissions', {}).get('Enrollment Rights', [])
        autoenrollment_permissions = permissions.get('Enrollment Permissions', {}).get('Autoenrollment Rights', [])
        object_control_permissions = permissions.get('Object Control Permissions', {})

        write_owner_principals = object_control_permissions.get('Write Owner Principals', [])
        write_dacl_principals = object_control_permissions.get('Write Dacl Principals', [])
        write_property_principals = object_control_permissions.get('Write Property Principals', [])

        all_permissions = [
            ('Enrollment Permissions', enrollment_permissions),
            ('Autoenrollment Permissions', autoenrollment_permissions),
            ('Write Owner Principals', write_owner_principals),
            ('Write Dacl Principals', write_dacl_principals),
            ('Write Property Principals', write_property_principals)
        ]

        template_results = []
        for permission_type, principals in all_permissions:
            uncommon_principals = [principal for principal in principals if is_uncommon(principal)]
            if uncommon_principals:
                template_results.append({
                    'Permission Type': permission_type,
                    'Principals': ', '.join(uncommon_principals)
                })

        ekus = template.get('Extended Key Usage', [])
        key_length = template.get('Minimum Key Size', 0)
        crypto_providers = template.get('Crypto Providers', [])
        validity_period = template.get('Validity Period', '')
        renewal_period = template.get('Renewal Period', '')
        publish_to_ad = template.get('Publish to AD', False)
        version = template.get('Version', 0)
        issuance_policies = template.get('Issuance Policies', [])
        application_policies = template.get('Application Policies', [])
        subject_alternative_name = template.get('Subject Alternative Name', {})
        flags = template.get('Template Flags', [])

        # Perform checks for each ESC vulnerability
        # ESC1: Client supplies subject and has Client Authentication EKU
        if enrollee_supplies_subject and 'Client Authentication' in ekus:
            vulnerabilities['ESC1'] = 'Template allows for potential ESC1 exploitation.'

        # ESC2: Any Purpose EKU is enabled
        if 'Any Purpose' in ekus:
            vulnerabilities['ESC2'] = 'Template includes Any Purpose EKU.'

        # ESC3: Certificate Request Agent EKU is enabled and uncommon principals can enroll
        if 'Certificate Request Agent' in ekus:
            uncommon_enrollers = [principal for principal in enrollment_permissions if is_uncommon(principal)]
            if uncommon_enrollers:
                vulnerabilities['ESC3'] = 'Template includes CRA EKU and uncommon principals can enroll.'

        # ESC4: Uncommon users have write privileges over the template
        uncommon_write_privs = []
        for principals in [write_owner_principals, write_dacl_principals, write_property_principals]:
            uncommon = [principal for principal in principals if is_uncommon(principal)]
            uncommon_write_privs.extend(uncommon)
        if uncommon_write_privs:
            vulnerabilities['ESC4'] = 'Uncommon users have write privileges over the template.'

        # ESC9: CT_FLAG_NO_SECURITY_EXTENSION is enabled with Client Authentication EKU and uncommon enrollers
        if 'CT_FLAG_NO_SECURITY_EXTENSION' in flags and 'Client Authentication' in ekus:
            uncommon_enrollers = [principal for principal in enrollment_permissions if is_uncommon(principal)]
            if uncommon_enrollers:
                vulnerabilities['ESC9'] = 'Template is vulnerable to ESC9 exploitation with uncommon enrollers.'

        # ESC13: Issuance Policy is configured with msDS-OIDToGroupLink and uncommon enrollers
        if issuance_policies and template.get('msDS-OIDToGroupLink'):
            uncommon_enrollers = [principal for principal in enrollment_permissions if is_uncommon(principal)]
            if uncommon_enrollers:
                vulnerabilities['ESC13'] = 'Template has msDS-OIDToGroupLink configured and uncommon enrollers.'

        # ESC15: Version 1 template with Application Policies confusion and uncommon enrollers
        if version == 1 and application_policies:
            uncommon_enrollers = [principal for principal in enrollment_permissions if is_uncommon(principal)]
            if uncommon_enrollers:
                vulnerabilities['ESC15'] = 'Version 1 template with Application Policies may be vulnerable (ESC15).'

        # Weak cryptography checks
        weak_key = False
        weak_hash = False
        if key_length and key_length < 2048:
            weak_key = True
            vulnerabilities['Weak Key Size'] = f"Key size is {key_length} bits."
        if any(algo for algo in crypto_providers if 'MD5' in algo or 'SHA1' in algo):
            weak_hash = True
            vulnerabilities['Weak Hash Algorithm'] = f"Uses weak hash algorithms: {', '.join(crypto_providers)}"

        # Enrollee Supplies Subject Alternative Name
        if subject_alternative_name.get('Enrollee Supplies Subject Alternative Name'):
            vulnerabilities['Enrollee Supplies SAN'] = True

        # Check for Authenticated Users enrollment (excluding default groups)
        if any(is_uncommon(principal) for principal in enrollment_permissions if principal == 'Authenticated Users'):
            vulnerabilities['Authenticated Users Enrollment'] = 'Authenticated Users group can enroll.'

        # Check for Autoenrollment enabled for uncommon principals
        uncommon_autoenrollers = [principal for principal in autoenrollment_permissions if is_uncommon(principal)]
        if uncommon_autoenrollers:
            vulnerabilities['Autoenrollment Enabled'] = f"Autoenrollment enabled for: {', '.join(uncommon_autoenrollers)}"

        if vulnerabilities or template_results:
            results.append({
                'Template ID': template_id,
                'Template Name': template_name,
                'Activated': is_activated,
                'Client Authentication': client_authentication,
                'Enrollee Supplies Subject': enrollee_supplies_subject,
                'Vulnerabilities': vulnerabilities,
                'Details': template_results,
                'Type': 'Certificate Template',
                'Weak Key': weak_key,
                'Weak Hash': weak_hash,
                'EKUs': ekus,
                'Version': version,
                'Validity Period': validity_period,
                'Renewal Period': renewal_period
            })

    # Check Certificate Authorities
    for ca_name, ca in data.get('Certificate Authorities', {}).items():
        permissions = ca.get('Permissions', {})
        vulnerabilities = ca.get('[!] Vulnerabilities', {})

        if not vulnerabilities:
            vulnerabilities = {}

        enrollment_services = permissions.get('Enrollment Services', [])
        manage_ca = permissions.get('Manage CA', [])
        request_certificate = permissions.get('Request Certificates', [])
        issue_certificate = permissions.get('Issue and Manage Certificates', [])
        read_ca = permissions.get('Read', [])
        cert_publishers = permissions.get('Certificate Publishers', [])

        all_permissions = [
            ('Enrollment Services', enrollment_services),
            ('Manage CA', manage_ca),
            ('Request Certificates', request_certificate),
            ('Issue and Manage Certificates', issue_certificate),
            ('Certificate Publishers', cert_publishers)
        ]

        ca_results = []
        for permission_type, principals in all_permissions:
            uncommon_principals = [principal for principal in principals if is_uncommon(principal)]
            if uncommon_principals:
                ca_results.append({
                    'Permission Type': permission_type,
                    'Principals': ', '.join(uncommon_principals)
                })

        # Perform checks for CA-level ESC vulnerabilities
        # ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
        ca_flags = ca.get('Flags', [])
        if 'EDITF_ATTRIBUTESUBJECTALTNAME2' in ca_flags:
            vulnerabilities['ESC6'] = 'CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.'

        # ESC7: Uncommon users have ManageCA or IssueAndManageCertificates permissions
        uncommon_manage_ca = [principal for principal in manage_ca if is_uncommon(principal)]
        uncommon_issue_cert = [principal for principal in issue_certificate if is_uncommon(principal)]
        if uncommon_manage_ca or uncommon_issue_cert:
            vulnerabilities['ESC7'] = 'Uncommon users have high privileges over the CA.'

        # ESC10: Weak certificate mapping settings in the CA registry
        cert_mapping_methods = ca.get('CertificateMappingMethods', 0)
        strong_cert_bind_enforcement = ca.get('StrongCertificateBindingEnforcement', 0)
        if cert_mapping_methods & 0x4 or strong_cert_bind_enforcement == 0:
            vulnerabilities['ESC10'] = 'CA is configured with weak certificate mapping settings.'

        if vulnerabilities or ca_results:
            results.append({
                'CA Name': ca_name,
                'Vulnerabilities': vulnerabilities,
                'Details': ca_results,
                'Type': 'Certificate Authority'
            })

    return results

def save_to_csv(results, csv_file_path):
    with open(csv_file_path, 'w', newline='') as csvfile:
        fieldnames = ['Type', 'Template ID/CA Name', 'Template Name', 'Activated', 'Client Authentication', 'Enrollee Supplies Subject', 'Vulnerabilities', 'Permission Type', 'Principals']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            if result['Type'] == 'Certificate Template':
                for detail in result['Details']:
                    writer.writerow({
                        'Type': result['Type'],
                        'Template ID/CA Name': result['Template ID'],
                        'Template Name': result['Template Name'],
                        'Activated': 'Yes' if result['Activated'] else 'No',
                        'Client Authentication': 'Yes' if result['Client Authentication'] else 'No',
                        'Enrollee Supplies Subject': 'Yes' if result['Enrollee Supplies Subject'] else 'No',
                        'Vulnerabilities': '; '.join([f"{k}: {v}" for k, v in result['Vulnerabilities'].items()]),
                        'Permission Type': detail['Permission Type'],
                        'Principals': detail['Principals']
                    })
            elif result['Type'] == 'Certificate Authority':
                for detail in result['Details']:
                    writer.writerow({
                        'Type': result['Type'],
                        'Template ID/CA Name': result['CA Name'],
                        'Template Name': '',
                        'Activated': '',
                        'Client Authentication': '',
                        'Enrollee Supplies Subject': '',
                        'Vulnerabilities': '; '.join([f"{k}: {v}" for k, v in result['Vulnerabilities'].items()]),
                        'Permission Type': detail['Permission Type'],
                        'Principals': detail['Principals']
                    })

def print_results(results):
    if not results:
        print("No anomalies found.")
    else:
        for result in results:
            if result['Type'] == 'Certificate Template':
                print("=" * 80)
                print(f"Template ID: {result['Template ID']}")
                print(f"Template Name: {result['Template Name']}")
                print(f"Activated: {'Yes' if result['Activated'] else 'No'}")
                if result['Client Authentication']:
                    print("[!] Client Authentication: Yes")
                if result['Enrollee Supplies Subject']:
                    print("[!] Enrollee Supplies Subject: Yes")
                print(f"Version: {result['Version']}")
                print(f"Validity Period: {result['Validity Period']}")
                print(f"Renewal Period: {result['Renewal Period']}")
                if result.get('Weak Key'):
                    print("[!] Weak Key Size Detected")
                if result.get('Weak Hash'):
                    print("[!] Weak Hash Algorithm Detected")
                if result.get('EKUs'):
                    print(f"EKUs: {', '.join(result['EKUs'])}")
                if result['Vulnerabilities']:
                    print("\n[!!!] Vulnerabilities Detected:")
                    for vuln_key, vuln_value in result['Vulnerabilities'].items():
                        print(f"    - {vuln_key}: {vuln_value}")
                print("\n[+] Permission Details:")
                for detail in result['Details']:
                    print(f"  - Permission Type: {detail['Permission Type']}")
                    print(f"    Principals: {detail['Principals']}")
                print("=" * 80 + "\n")
            elif result['Type'] == 'Certificate Authority':
                print("=" * 80)
                print(f"CA Name: {result['CA Name']}")
                if result['Vulnerabilities']:
                    print("\n[!!!] Vulnerabilities Detected:")
                    for vuln_key, vuln_value in result['Vulnerabilities'].items():
                        print(f"    - {vuln_key}: {vuln_value}")
                print("\n[+] Permission Details:")
                for detail in result['Details']:
                    print(f"  - Permission Type: {detail['Permission Type']}")
                    print(f"    Principals: {detail['Principals']}")
                print("=" * 80 + "\n")

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
