#!/usr/bin/env python3
import sys
import argparse
from binascii import hexlify

try:
    from asn1crypto import pem
    from asn1crypto.keys import EncryptedPrivateKeyInfo
except ImportError:
    sys.stderr.write(
        "Error: asn1crypto is required. Install with:\n"
        "    pip install asn1crypto\n"
    )
    sys.exit(1)

# Cipher → numeric ID mapping (3DES/AES)
CIPHER_IDS = {
    'tripledes_3key': 1,
    'aes128_cbc':      2,
    'aes192_cbc':      3,
    'aes256_cbc':      4,
}

# PRF → Hashcat mode
HC_MODES = {
    'sha1':   24410,
    'sha256': 24420,
}

def extract_hash(filename):
    blob = open(filename, 'rb').read()
    if pem.detect(blob):
        _, _, blob = pem.unarmor(blob)

    info = EncryptedPrivateKeyInfo.load(blob).native
    alg  = info['encryption_algorithm']
    params = alg['parameters']
    kdf    = params['key_derivation_func']
    kdfp   = kdf['parameters']

    # if the 'prf' field mentions sha256 → SHA-256, else SHA-1
    prf_field = kdfp.get('prf')
    if prf_field:
        algo_name = prf_field['algorithm'].lower()
        if 'sha256' in algo_name:
            prf = 'sha256'
        else:
            # covers sha1, hmacwithsha1, OID strings, etc.
            prf = 'sha1'
    else:
        prf = 'sha1'

    mode    = HC_MODES[prf]
    version = 1 if prf == 'sha1' else 2

    salt       = kdfp['salt']
    iterations = kdfp['iteration_count']

    scheme = params['encryption_scheme']
    cipher = scheme['algorithm']
    iv     = scheme['parameters']
    enc    = info['encrypted_data']

    cid = CIPHER_IDS.get(cipher)
    if cid is None:
        raise ValueError(f"Unsupported cipher: {cipher!r}")

    parts = [
        f"$PEM${version}",
        str(cid),
        hexlify(salt).decode('ascii'),
        str(iterations),
        hexlify(iv).decode('ascii'),
        str(len(enc)),
        hexlify(enc).decode('ascii'),
    ]
    return mode, '$'.join(parts)

def main():
    p = argparse.ArgumentParser(
        description="Extract Hashcat-compatible $PEM$ hash from PKCS#8 key"
    )
    p.add_argument('files', nargs='+', help="Encrypted PKCS#8 files (PEM or DER)")
    args = p.parse_args()

    for fn in args.files:
        try:
            mode, h = extract_hash(fn)
        except Exception as e:
            sys.stderr.write(f"{fn}: ERROR: {e}\n")
            continue

        print(f"# {fn}  →  mode {mode}")
        print(h)
        print()

if __name__ == '__main__':
    main()
