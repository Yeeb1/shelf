#!/usr/bin/env python3
import argparse
import re

def convert_1337(keyword):
    leet_translations = {
        'a': '[a4@]', 'b': '[b8]', 'c': '[c<({]', 'e': '[e3&]',
        'g': '[g9]', 'h': '[h#]', 'i': '[i1!|]', 'l': '[l1|]',
        'o': '[o0]', 's': '[s5$]', 't': '[t7+]', 'z': '[z2]',
        'u': '[uµ]'
    }
    return ''.join(leet_translations.get(char, char) for char in keyword.lower())

def search_keywords(file_path, keywords, leet_speak=False):
    if leet_speak:
        keywords = [convert_1337(kw) for kw in keywords]

    with open(file_path, 'r', encoding='latin-1') as file:
        lines = file.readlines()

    matches = []
    for line in lines:
        for keyword in keywords:
            if re.search(keyword, line, re.IGNORECASE):
                matches.append(line)
                break

    return matches

def main():
    parser = argparse.ArgumentParser(description='Search keywords in /usr/share/wordlists/rockyou.txt and write found passwords into quickwins.txt. Keywords can be related to box name, service, or username. Supports leet speak search.')
    parser.add_argument('keywords', nargs='+', help='Keywords to search for (case insensitive)')
    parser.add_argument('--leet', action='store_true', help='Search for keywords in 1337-speak format')
    args = parser.parse_args()

    rockyou_path = '/usr/share/wordlists/rockyou.txt'
    matches = search_keywords(rockyou_path, args.keywords, args.leet)

    with open('quickwins.txt', 'w') as outfile:
        outfile.writelines(matches)

    print(f"Found {len(matches)} matching passwords. Written to quickwins.txt")

if __name__ == "__main__":
    main()
