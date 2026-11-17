# pbkdf2-asm

An educational, from-scratch implementation of PBKDF2-HMAC-SHA-256 in x86-64
NASM assembly for Linux. Not for protecting real passwords.

The code favors readability over speed: it is a plain, commented
implementation for learning the internals, not an optimized one, and it
makes no constant-time guarantees.

It builds two artifacts from the same assembly code:

- `build/pbkdf2`: a standalone executable, statically linked, no libc.
- `build/libpbkdf2.so`: a shared library, used by the Python test suite.

See `pbkdf2-assembly-project-spec.md` for the full specification.

## Building

With Docker (the default; needs only Docker and GNU Make):

```bash
make            # build both artifacts
make test       # run the test suite
make lint       # check source conventions
make clean
```

Without Docker, with `nasm` and `binutils` installed locally:

```bash
make BUILD_MODE=host          # build only
make BUILD_MODE=host test     # also needs python3 and pytest
```

Inside the development container (`.devcontainer/`), `BUILD_MODE=host` is
preset, so plain `make` and `make test` work there without Docker.

## Usage

```text
pbkdf2 -i ITERATIONS -l OUTPUT_LEN -s SALT_HEX  < password
```

The executable has no runtime dependencies (static, no libc), so it runs on
any Linux x86-64 host, inside or outside a container.

| Option | Value | Rules |
|---|---|---|
| `-i ITERATIONS` | PBKDF2 iteration count | Unsigned decimal, 1 to 4294967295. |
| `-l OUTPUT_LEN` | Derived key length in bytes | Unsigned decimal, 1 to 1024. |
| `-s SALT_HEX` | Salt, hex-encoded | Even number of hex digits, upper or lower case, up to 2048 digits (1024 bytes). May be empty (`-s ''`). |

All three options are required and each may be given once, in any order.
The value is always a separate argument (`-i 1000`, not `-i1000`). There
are no other options.

**Password.** Read from stdin: every byte until end of file, up to 4096
bytes, used exactly as given. A trailing newline is *not* stripped, so pipe
it with `printf`, not `echo`. Binary passwords (NUL bytes, newlines) work.
Passwords are never accepted as arguments, because arguments are visible in
`ps` and shell history.

**Output.** The derived key on stdout as lowercase hex, followed by one
newline. Nothing is written to stdout on failure.

**Numbers.** Decimal digits only: no sign, no spaces, no `0x`. Leading
zeros are fine.

**Exit status.** Every failure prints one line to stderr, starting with
`pbkdf2: `.

| Status | Meaning | Examples |
|---|---|---|
| 0 | Success | |
| 1 | Key derivation or I/O error | `-i 0`, `-l 0`, stdin unreadable, stdout not writable |
| 2 | Usage error | Missing, repeated or unknown option; malformed number or hex; a value over a limit; password over 4096 bytes |

All arguments are checked before stdin is read, so a usage error never
consumes the password. The password and derived-key buffers are zeroed
before the program exits.

Examples:

```bash
# RFC 7914 section 11 test vector: password "passwd", salt "salt"
printf passwd | ./build/pbkdf2 -i 1 -l 64 -s 73616c74

# Password from a file, random 16-byte salt
salt=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
./build/pbkdf2 -i 600000 -l 32 -s "$salt" < password.txt
```

The size limits are the fixed buffer sizes in `include/cli.inc`. The
library itself (`pbkdf2_hmac_sha256`) has no such limits; its input rules
are in the spec, section 5.1.

## Comparing with OpenSSL

`scripts/openssl-pbkdf2.sh` has the same interface (options, stdin
password, output format, exit statuses) but computes the key with
`openssl kdf` (OpenSSL 3.0 or later), so the two can be run side by side:

```bash
printf passwd | ./build/pbkdf2               -i 600000 -l 32 -s 73616c74
printf passwd | scripts/openssl-pbkdf2.sh    -i 600000 -l 32 -s 73616c74

# Timing
time (printf passwd | ./build/pbkdf2            -i 600000 -l 32 -s 73616c74)
time (printf passwd | scripts/openssl-pbkdf2.sh -i 600000 -l 32 -s 73616c74)
```

Differences: the wrapper has no CLI buffer limits, and `openssl kdf`
accepts the password only as a command-line argument (hex-encoded), so it
is briefly visible in `ps`. Use it for testing, never with a real password.
The script is meant for the host, where desktop Linux usually has
OpenSSL; the build image deliberately does not install it.

## Layout

```text
pbkdf2-asm/
├── src/
│   ├── sha256/        SHA-256
│   ├── hmac/          HMAC-SHA-256, on SHA-256
│   ├── pbkdf2/        PBKDF2, on HMAC
│   └── cli/           the executable's entry point (_start)
├── include/
│   ├── sha256.inc     SHA-256 sizes and context layout
│   ├── hmac.inc       HMAC context layout
│   ├── pbkdf2.inc     public API: params layout, error codes
│   ├── cli.inc        CLI exit statuses and size limits
│   └── syscalls.inc   Linux system call numbers (CLI only)
├── tests/             pytest suite (Python stdlib as reference)
│   ├── bindings.py    ctypes structs and signatures
│   └── guard.py       guard-page buffers for overrun tests
├── scripts/
│   ├── lint.py        source convention checks
│   └── openssl-pbkdf2.sh  same CLI interface, computed by OpenSSL
├── build/             generated files (not committed)
├── Dockerfile         build image for the default Docker mode
├── Makefile
└── pytest.ini
```

## TODO

- **Constants leak into the symbol table.** NASM emits every `equ` constant
  as an absolute symbol (`nm` type `a`, e.g. `SCHEDULE_SIZE`,
  `SHA256_CTX_SIZE`). They stay out of the exported symbols (`nm -D`), but
  `objdump` uses them to label nearby addresses, so `make disasm` shows
  misleading targets such as `jmp 1000 <SCHEDULE_SIZE+0xf00>`. Candidate fix:
  define constants with `%assign`/`%define` (preprocessor only, no symbols)
  and update the naming rule in `scripts/lint.py`. Stripping at link time is
  not an option: `ld -x` also drops the local labels GDB relies on.
- **Bounds and integer-arithmetic review (Milestone 6).** One pass over
  every place a length or offset is computed, checking for overflow,
  off-by-one and out-of-bounds access, and adding a test for each
  documented limit where practical:
  - SHA-256: the 64-bit byte counter (documented limit 2^61 bytes, so the
    bit length fits), the buffered-byte count `length & 63`, and the
    padding offsets in `sha256_final`.
  - HMAC: the key-length branch (over 64 bytes the key is hashed).
  - PBKDF2: the 32-bit block counter and the `output_len` bound that keeps
    it from wrapping, and the `min(32, bytes left)` copy of each block.
  - CLI: `parse_decimal` overflow checks, `hex_decode` length and odd-digit
    arithmetic, `read_all`/`write_all` offsets, and the buffer sizes in
    `include/cli.inc`.
- **Leftover key material (Milestone 6).** Contexts, the SHA-256 message
  schedule, the HMAC key block, PBKDF2's stack frame and the CLI buffers
  are already zeroed. Still to check: secret data left in registers or on
  the stack after each function returns (for example, `sha256_compress`
  leaves state words in r8-r11, and the stack below `rsp` keeps old
  callee frames), and decide what is worth clearing while keeping the
  code simple.
