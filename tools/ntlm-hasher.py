#!/usr/bin/env python3

import argparse
import hashlib

def compute_ntlm_hash(password):
    password = password.encode('utf-16-le')
    return hashlib.new('md4', password).hexdigest().lower()

  
def main():
    parser = argparse.ArgumentParser(description='Compute the NTLM hash of a given password.')
    parser.add_argument('password', type=str, help='The password to hash.')
    
    args = parser.parse_args()
    
    ntlm_hash = compute_ntlm_hash(args.password)
    print("NTLM Hash:", ntlm_hash)

if __name__ == '__main__':
    main()
