#!/usr/bin/python3

import argparse
import random

DEFAULT_PREFIXES = ['Summer', 'Winter', 'Spring', 'Fall', 'Admin', 'User', 'Password', 'Default', 'Guest']
DEFAULT_SUFFIXES = ['123', '1234!', '123!', '2024', '2025', '2022', '2023', '2021', '2020', '!', '@', '#', '$', '01', '02', '03', '007', 'admin', 'root', 'guest']

leet_dict = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}

def leet_speak(word):
    return ''.join(leet_dict.get(char.lower(), char) for char in word)

def generate_wordlist(all_flag, additional_prefixes, additional_suffixes, custom_prefixes_flag, leet_flag):
    wordlist = []

    if custom_prefixes_flag:
        prefixes = additional_prefixes
    else:
        prefixes = DEFAULT_PREFIXES + additional_prefixes

    if all_flag:
        prefixes += [prefix.lower() for prefix in prefixes]

    suffixes = additional_suffixes + DEFAULT_SUFFIXES

    for prefix in prefixes:
        wordlist.append(prefix)
        for suffix in suffixes:
            wordlist.append(f'{prefix}{suffix}')
            
            if leet_flag:
                leet_suffix = leet_speak(suffix)
                wordlist.append(f'{prefix}{leet_suffix}')
    
    if leet_flag:
        for prefix in prefixes:
            leet_prefix = leet_speak(prefix)
            wordlist.append(leet_prefix)
            for suffix in suffixes:
                wordlist.append(f'{leet_prefix}{suffix}')
                leet_suffix = leet_speak(suffix)
                wordlist.append(f'{leet_prefix}{leet_suffix}')
    
    return wordlist

def main():
    parser = argparse.ArgumentParser(description="Generate a wordlist with predefined and additional prefixes and suffixes.")
    parser.add_argument('--all', action='store_true', help="Include lowercase versions of the predefined and additional prefixes")
    parser.add_argument('--prefix', '-p', nargs='+', default=[], help="Add additional prefixes (space-separated)")
    parser.add_argument('--suffix', '-s', nargs='+', default=[], help="Add additional suffixes (space-separated)")
    parser.add_argument('--custom-prefixes', '-cp', action='store_true', help="Use only the additional prefixes provided via command line")
    parser.add_argument('--leet', action='store_true', help="Apply Leet speak transformations to the wordlist")
    parser.add_argument('--output', '-o', default='prefixsuffix.txt', help="Save the wordlist to a file (default: prefixsuffix.txt)")

    args = parser.parse_args()

    wordlist = generate_wordlist(args.all, args.prefix, args.suffix, args.custom_prefixes, args.leet)

    with open(args.output, 'w') as f:
        for word in wordlist:
            f.write(f"{word}\n")

    print(f"Wordlist saved to {args.output}")

if __name__ == "__main__":
    main()
