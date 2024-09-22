#!/usr/bin/env python3

import os
import sys
import time

def main(input_file):
    output_file = os.path.join(os.getcwd(), 'users.generated')

    if os.path.isfile(output_file):
        os.remove(output_file)

    open(output_file, 'x').close()

    print("[*] Names Loaded:")
    with open(input_file, "r") as user_file:
        for line in user_file:
            username = line.strip()
            if username:
                print(f"    + {username}")
                if len(username.split(" ")) > 1:
                    generate_variants(username, output_file)
                else:
                    save_to_file(username, output_file)


    print(f"[*] File Saved to: {output_file}")

def generate_variants(word, output_file):
    base_variants = [word.replace(' ', '-'), word.replace(' ', '_'), word.replace(' ', '.'), word]
    for variant in base_variants:
        save_to_file(variant, output_file)

    splits = word.split(" ")
    if len(splits) > 2:
        generate_more_variants(splits, output_file)
    else:
        generate_two_word_variants(splits, output_file)

def generate_two_word_variants(splits, output_file):
    fw, sw = splits[0][0], splits[1][0]
    variants = [
        splits[0] + splits[1], fw + splits[1], splits[0] + sw,
        fw + '-' + splits[1], fw + '_' + splits[1], fw + '.' + splits[1],
        splits[0] + '-' + sw, splits[0] + '_' + sw, splits[0] + '.' + sw,
        fw + sw
    ]
    for variant in variants:
        save_to_file(variant, output_file)

def generate_more_variants(splits, output_file):
    if len(splits) == 3:
        fl, sl, tl = splits[0][0], splits[1][0], splits[2][0]
        variants = [
            splits[0] + splits[1] + splits[2], fl + splits[1] + splits[2], 
            splits[0] + sl + splits[2], splits[0] + splits[1] + tl,
            fl + '-' + splits[1] + '-' + splits[2], fl + '.' + splits[1] + '.' + splits[2],
            fl + '_' + splits[1] + '_' + splits[2], splits[0] + '-' + sl + '-' + splits[2],
            splits[0] + '.' + sl + '.' + splits[2], splits[0] + '_' + sl + '_' + splits[2],
            splits[0] + '_' + splits[1] + '_' + tl, splits[0] + '.' + splits[1] + '.' + tl,
            splits[0] + '-' + splits[1] + '-' + tl, fl + sl + tl
        ]
    else:
        fl, sl, tl, ftl = splits[0][0], splits[1][0], splits[2][0], splits[3][0]
        variants = [
            splits[0] + splits[1] + splits[2] + splits[3], fl + splits[1] + splits[2] + splits[3],
            splits[0] + sl + splits[2] + splits[3], splits[0] + splits[1] + tl + splits[3],
            splits[0] + splits[1] + splits[2] + ftl, fl + '-' + splits[1] + '-' + splits[2] + '-' + splits[3],
            fl + '.' + splits[1] + '.' + splits[2] + '.' + splits[3], fl + '_' + splits[1] + '_' + splits[2] + '_' + splits[3],
            splits[0] + '-' + sl + '-' + splits[2] + '-' + splits[3], splits[0] + '.' + sl + '.' + splits[2] + '.' + splits[3],
            splits[0] + '_' + sl + '_' + splits[2] + '_' + splits[3], splits[0] + '_' + splits[1] + '_' + tl + '_' + splits[3],
            splits[0] + '.' + splits[1] + '.' + tl + '.' + splits[3], splits[0] + '-' + splits[1] + '-' + tl + '-' + splits[3],
            splits[0] + '.' + splits[1] + '.' + splits[2] + '.' + ftl, splits[0] + '-' + splits[1] + '-' + splits[2] + '-' + ftl,
            splits[0] + '_' + splits[1] + '_' + splits[2] + '_' + ftl, fl + sl + tl + ftl
        ]

    for variant in variants:
        save_to_file(variant, output_file)

def save_to_file(username, output_file):
    with open(output_file, 'a') as f:
        f.write(username + '\n')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 namegen.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.isfile(input_file):
        print(f"Error: The file {input_file} does not exist.")
        sys.exit(1)

    main(input_file)
