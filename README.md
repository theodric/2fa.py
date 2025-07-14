# 2fa.py
TOTP CLI client in Python 

This is an implementation spiritually similar to [rsc/2fa](https://github.com/rsc/2fa) but written in nice, auditable Python.

It uses the exact same ~/.2fa file format as rsc's program.

For _branding_ reasons I've named this 2fa.py, but I recommend renaming the executable to just `2fa` tbh

```bash
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
```
