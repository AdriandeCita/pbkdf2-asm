# pbkdf2-asm

An educational, from-scratch implementation of PBKDF2-HMAC-SHA-256 in x86-64
NASM assembly for Linux. Not for protecting real passwords.

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

## Running

The executable has no runtime dependencies:

```bash
printf passwd | ./build/pbkdf2 -i 1 -l 64 -s 73616c74
```

(Available from Milestone 5; see the spec.)

## Layout

```text
pbkdf2-asm/
├── src/
│   ├── sha256/        SHA-256
│   ├── hmac/          HMAC-SHA-256, on SHA-256
│   ├── pbkdf2/        PBKDF2, on HMAC
│   └── cli/           the executable's entry point (_start)
├── include/
│   ├── pbkdf2.inc     shared interface definitions
│   └── syscalls.inc   Linux system call numbers (CLI only)
├── tests/             pytest suite (Python stdlib as reference)
├── scripts/
│   └── lint.py        source convention checks
├── build/             generated files (not committed)
├── Dockerfile         build image for the default Docker mode
├── Makefile
└── pytest.ini
```
