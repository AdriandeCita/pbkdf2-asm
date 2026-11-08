# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Educational, from-scratch **PBKDF2-HMAC-SHA-256 in x86-64 NASM assembly** (Linux, ELF64, System V AMD64 ABI). `pbkdf2-assembly-project-spec.md` is the authoritative spec — read the relevant section before making structural decisions (Makefile layout, ABI, CLI behavior, test policy, milestones).

Hard rules from the spec:
- Everything shipped is NASM: SHA-256, HMAC, PBKDF2, and the command-line wrapper. No C anywhere, and no C compiler in the toolchain (both artifacts are linked with `ld`). Python is only for tests, reference oracles, and dev scripts.
- Tests use Python's stdlib (`hashlib.sha256`, `hmac`, `hashlib.pbkdf2_hmac`) as the oracle plus published vectors (FIPS 180-4, RFC 4231, RFC 7914 §11). Never reimplement the algorithms in Python; the `ctypes` wrapper only marshals arguments.
- Work in milestone order (spec §11): scaffold → SHA-256 → HMAC → PBKDF2 → CLI → hardening. No crypto code before the scaffold is verified.

## Current state

Milestone 1 (scaffold) is done and verified in host mode; Docker mode is untested because there is no Docker in the devcontainer. `sha256.asm` and `hmac.asm` are empty stubs; `pbkdf2.asm` only has `pbkdf2_abi_version`; `cli.asm`'s `_start` only exits 0. Next is Milestone 2 (SHA-256).

The spec embeds the Makefile and `tests/conftest.py` verbatim — when changing either, update the copy in spec §4.3 / §6.1 too.

`.devcontainer/` is the development environment you run in (spec §4.5). It is separate from the root build image but must install the same project toolchain (`nasm make binutils gdb python3 python3-pytest`, both Debian bookworm) — keep the two package lists in sync. It sets `BUILD_MODE=host`; there is no Docker inside it.

## Commands

`BUILD_MODE` selects where public targets run: `docker` (default, for a fresh clone; uses the `pbkdf2-asm-dev` image) or `host` (local tools; preset in the devcontainer). So inside the devcontainer the plain commands just work:
```bash
make            # build/libpbkdf2.so and build/pbkdf2
make test       # pytest
make lint       # scripts/lint.py
make debug      # gdb on the pytest run
make disasm
make clean
```
`host-*` targets are the internal implementation that both modes call; `tests/conftest.py` calls `make -s host-all` at the start of every session (so single-test runs never see stale artifacts) — directly, because the build container doesn't set `BUILD_MODE`.

Single test: `python3 -m pytest -v tests/test_build.py::test_library_reports_abi_version`.

Header dependencies come from a separate `nasm -M` pass into `build/*.d` (NASM 2.16's `-MD` drops `%include`s), so don't hand-write `.inc` prerequisites. New modules need a `vpath` entry and a place in `OBJECTS`.

`tests/test_build.py` enforces the artifact rules (no TEXTREL, non-exec stack, static exe with no interpreter) by parsing ELF headers; `make lint` enforces naming, whitespace, the GNU-stack note, and the exported-function header fields (`Purpose:`, `Args:`, `Returns:`, `Modifies:`, `Preserves:`, `Stack:`, `Inputs:`, `Overlap:`).

Run the CLI directly (no container needed): `printf passwd | ./build/pbkdf2 -i 1 -l 64 -s 73616c74`.

Inspection: `nm -D`, `readelf -r` / `readelf -d … | grep TEXTREL` (must be empty), `readelf -l build/pbkdf2 | grep -i interp` (must be empty), `objdump -d -Mintel`.

## Architecture

The same crypto objects are linked twice:

```
sha256.o → hmac.o → pbkdf2.o ──┬── ld -shared ─────► build/libpbkdf2.so  ← tests/ via ctypes
                               └── + cli.o, ld -static ► build/pbkdf2      ← tests/test_cli.py via subprocess
```

- Strict one-way dependencies: SHA-256 knows nothing of HMAC, HMAC nothing of PBKDF2, and no crypto module knows about the CLI or makes system calls. The CLI calls only `pbkdf2_hmac_sha256`.
- `include/pbkdf2.inc` holds shared interface definitions (struct offsets, constants, externs); `include/syscalls.inc` holds Linux syscall numbers for the CLI.
- Public entry point: `int pbkdf2_hmac_sha256(const struct pbkdf2_params *params, uint8_t *output)`, struct `{password ptr, password_len, salt ptr, salt_len, uint32 iterations, size_t output_len}`. Offsets must match between NASM and `ctypes` and stay stable. Returns 0 on success, documented nonzero codes for invalid input.
- CLI (`src/cli/cli.asm`, spec §5.2): `_start` entry, no libc, raw `read`/`write`/`exit` syscalls, fixed `.bss` buffers with named size limits. Password comes from stdin (never argv, not newline-stripped), salt as hex via `-s`, output is lowercase hex + newline. Exit 0 = success, 1 = library/I/O error, 2 = usage error.
- When adding modules/includes, keep Makefile dependencies on actual source/`.inc` files.

## Assembly conventions

- Code must be position-independent (it goes into the `.so`): `default rel` / RIP-relative addressing, no text relocations.
- End every `.asm` file with `section .note.GNU-stack noalloc noexec nowrite progbits`; otherwise the `.so` needs an executable stack and recent glibc refuses to load it.
- Preserve callee-saved RBX, RBP, R12–R15; keep RSP 16-byte aligned at every `call` (including from `_start`).
- Lowercase mnemonics, `snake_case` labels/functions, UPPERCASE constants in `.inc` files; no unexplained magic numbers.
- Every exported function needs a header comment covering: purpose, args and sizes, return/error behavior, registers modified, callee-saved preserved, stack usage/alignment, whether inputs are modified, whether output may overlap input.
- Boundary tests should use guard-page buffers (`mmap` + `PROT_NONE` page right after the buffer) to catch overruns; Valgrind and LLVM are intentionally not in the toolchain.
