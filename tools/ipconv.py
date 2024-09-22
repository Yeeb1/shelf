#!/usr/bin/env python3

import argparse
import ipaddress

def ip_to_decimal(ip):
    return int(ipaddress.ip_address(ip))

def ip_to_octal(ip):
    decimal_val = ip_to_decimal(ip)
    return '0' + oct(decimal_val)[2:]


def ip_to_hex(ip):
    decimal_val = ip_to_decimal(ip)
    return hex(decimal_val)

def main():
    parser = argparse.ArgumentParser(description='Convert IPv4 address to decimal, octal, and hexadecimal formats.')
    parser.add_argument('ip', type=str, help='IPv4 address to convert')
    args = parser.parse_args()
    
    print(f"Decimal:\t{ip_to_decimal(args.ip)}")
    print(f"Octal:\t\t{ip_to_octal(args.ip)}")
    print(f"Hexadecimal:\t{ip_to_hex(args.ip)}")

if __name__ == "__main__":
    main()
