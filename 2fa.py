#!/usr/bin/env python3
import sys
import os
import time
import base64
import hmac
import hashlib

TOTP_INTERVAL = 30
TOTP_DIGITS = 6
TOTP_ALGO = hashlib.sha1
TOTP_FILE = os.path.expanduser('~/.2fa')

def parse_2fa_file(path):
    entries = {}
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            name = parts[0]
            try:
                digits = int(parts[1])
            except ValueError:
                digits = TOTP_DIGITS
            secret = parts[2]
            entries[name] = (digits, secret)
    return entries

def get_totp_token(secret, digits, for_time=None):
    if for_time is None:
        for_time = int(time.time())
    key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
    counter = int(for_time // TOTP_INTERVAL)
    msg = counter.to_bytes(8, 'big')
    h = hmac.new(key, msg, TOTP_ALGO).digest()
    o = h[-1] & 0x0F
    code = (int.from_bytes(h[o:o+4], 'big') & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)

HELP_MSG = f"""
Usage: 2fa [options] [name]

Options:
  -a         Sort output alphabetically by site name
  -f         Sort output in the order of the .2fa file (default)
  --help     Show this help message and exit
  -add NAME  Add a new key for NAME to the ~/.2fa file (will prompt for secret)

Arguments:
  name       (Optional) Only print the code for the given site name

Setup:
  Create a ~/.2fa file with one entry per line in the format:
    <name> <digits> <base32_secret>
  Example:
    github 6 FFFFFFAAAAAAEEEE
    gitlab 6 ABCDEFGAAAAAABBBBBBCCCCCCCX
    ...
  <name>         A label for the service (no spaces)
  <digits>       Number of digits for the code (usually 6)
  <base32_secret> The TOTP secret (Base32, no spaces)
"""

def add_key(name):
    secret = input(f"2fa key for {name}: ").strip()
    if not secret:
        print("No secret entered. Aborting.", file=sys.stderr)
        sys.exit(1)
    line = f"{name} 6 {secret}\n"
    with open(TOTP_FILE, 'a') as f:
        f.write(line)
    print(f"Added key for {name} to {TOTP_FILE}")

def main():
    args = sys.argv[1:]
    sort_alpha = False
    sort_file = False
    name_arg = None
    # Help flag
    if '--help' in args:
        print(HELP_MSG)
        sys.exit(0)
    # Add key flag
    if '-add' in args:
        idx = args.index('-add')
        if idx + 1 >= len(args):
            print("Usage: 2fa -add <name>", file=sys.stderr)
            sys.exit(1)
        name = args[idx + 1]
        add_key(name)
        sys.exit(0)
    # Parse flags
    filtered_args = []
    for arg in args:
        if arg == '-a':
            sort_alpha = True
        elif arg == '-f':
            sort_file = True
        else:
            filtered_args.append(arg)
    args = filtered_args
    if sort_alpha and sort_file:
        print("Cannot use both -a and -f flags together.", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(TOTP_FILE):
        print(f"2FA file not found: {TOTP_FILE}\n")
        print(HELP_MSG)
        sys.exit(1)
    entries = parse_2fa_file(TOTP_FILE)
    if not entries:
        print(f"No entries found in {TOTP_FILE}", file=sys.stderr)
        sys.exit(1)
    if len(args) == 1:
        name = args[0]
        if name not in entries:
            print(f"No entry for '{name}' in {TOTP_FILE}", file=sys.stderr)
            sys.exit(1)
        digits, secret = entries[name]
        code = get_totp_token(secret, digits)
        print(code)
    else:
        # Determine order
        if sort_alpha:
            names = sorted(entries)
        else:
            # dict preserves file order in Python 3.7+
            names = list(entries.keys())
        maxlen = max(len(name) for name in entries)
        for name in names:
            digits, secret = entries[name]
            code = get_totp_token(secret, digits)
            print(f"{name.ljust(maxlen)} {code}")

if __name__ == '__main__':
    main() 