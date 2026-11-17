#!/usr/bin/env bash
# openssl-pbkdf2.sh - build/pbkdf2's interface, computed by OpenSSL.
#
#     openssl-pbkdf2.sh -i ITERATIONS -l OUTPUT_LEN -s SALT_HEX < password
#
# For side-by-side comparison with build/pbkdf2 (README "Comparing with
# OpenSSL"). Same options, same stdin password (raw bytes, newline kept),
# same output (lowercase hex + newline), same exit statuses: 0 success,
# 1 key derivation or I/O error, 2 usage error.
#
# Differences from build/pbkdf2:
# - No CLI buffer limits (4096-byte password, 1024-byte salt and output):
#   only the iteration count must fit in 32 bits, as in the library.
# - `openssl kdf` takes the password only as an argument, so it is visible
#   in `ps` while this runs. Do not use it with a real password.
#
# Needs OpenSSL 3.0 or later (`openssl kdf`), usually present on desktop
# Linux; meant for the host, not the build image. Not part of the shipped
# project: a developer tool, like scripts/lint.py.

set -euo pipefail

prog=${0##*/}
usage="usage: $prog -i ITERATIONS -l OUTPUT_LEN -s SALT_HEX < password"
uint32_max=4294967295

die_usage() { printf '%s: %s; %s\n' "$prog" "$1" "$usage" >&2; exit 2; }
die() { printf '%s: %s\n' "$prog" "$1" >&2; exit 1; }

# Strip leading zeros from a digit string ("" and "000" become "0").
strip_zeros() {
    local v=${1#"${1%%[!0]*}"}
    printf '%s' "${v:-0}"
}

# --- Arguments (same rules as build/pbkdf2) ----------------------------------

have_i='' have_l='' have_s=''
while (($#)); do
    case $1 in
        -i | -l | -s) ;;
        *) die_usage "unknown argument" ;;
    esac
    (($# >= 2)) || die_usage "option needs a value"
    case $1 in
        -i) [[ -z $have_i ]] || die_usage "option given more than once"
            have_i=1 iterations=$2 ;;
        -l) [[ -z $have_l ]] || die_usage "option given more than once"
            have_l=1 length=$2 ;;
        -s) [[ -z $have_s ]] || die_usage "option given more than once"
            have_s=1 salt_hex=$2 ;;
    esac
    shift 2
done
[[ -n $have_i && -n $have_l && -n $have_s ]] ||
    die_usage "-i, -l and -s are all required"

[[ $iterations =~ ^[0-9]+$ ]] ||
    die_usage "-i must be a decimal number from 0 to $uint32_max"
iterations=$(strip_zeros "$iterations")
((${#iterations} <= ${#uint32_max} && 10#$iterations <= uint32_max)) ||
    die_usage "-i must be a decimal number from 0 to $uint32_max"

[[ $length =~ ^[0-9]+$ ]] || die_usage "-l must be a decimal number"
length=$(strip_zeros "$length")
# Bash arithmetic is signed 64-bit; anything longer is far beyond memory.
((${#length} <= 18)) || die_usage "-l is over the output length limit"

((${#salt_hex} % 2 == 0)) || die_usage "-s has an odd number of hex digits"
[[ $salt_hex =~ ^[0-9a-fA-F]*$ ]] || die_usage "-s contains a non-hex character"

command -v openssl >/dev/null || die "openssl not found"

# --- Password and derivation -------------------------------------------------

# Hex-encode stdin, so NUL bytes survive (bash strings cannot hold them).
password_hex=$(od -An -v -tx1 2>/dev/null | tr -d ' \n') ||
    die "cannot read the password from stdin"

errors=$(mktemp)
trap 'rm -f "$errors"' EXIT

# -binary + od gives lowercase hex without OpenSSL's "AB:CD:" formatting.
# 0 iterations or length are passed on; OpenSSL rejects them (exit 1).
if ! key=$(openssl kdf -binary -keylen "$length" \
        -kdfopt digest:SHA256 \
        -kdfopt "hexpass:$password_hex" \
        -kdfopt "hexsalt:$salt_hex" \
        -kdfopt "iter:$iterations" \
        PBKDF2 2>"$errors" | od -An -v -tx1 | tr -d ' \n'); then
    die "openssl: $(head -n 1 "$errors")"
fi

printf '%s\n' "$key" 2>/dev/null || die "cannot write to stdout"
