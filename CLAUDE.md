# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Educational, from-scratch **PBKDF2-HMAC-SHA-256 in x86-64 NASM assembly** (Linux, ELF64, System V AMD64 ABI). `pbkdf2-assembly-project-spec.md` is the authoritative spec — read the relevant section before making structural decisions (Makefile layout, ABI, CLI behavior, test policy, milestones).

Hard rules from the spec:
- Everything shipped is NASM: SHA-256, HMAC, PBKDF2, and the command-line wrapper. No C anywhere, and no C compiler in the toolchain (both artifacts are linked with `ld`). Python is only for tests, reference oracles, and dev scripts.
- Tests use Python's stdlib (`hashlib.sha256`, `hmac`, `hashlib.pbkdf2_hmac`) as the oracle plus published vectors (FIPS 180-4, RFC 4231, RFC 7914 §11). Never reimplement the algorithms in Python; the `ctypes` wrapper only marshals arguments.
- Work in milestone order (spec §11): scaffold → SHA-256 → HMAC → PBKDF2 → CLI → hardening. No crypto code before the scaffold is verified.

## Current state

Milestone 1 (scaffold) is done and its acceptance checklist is complete: host mode verified in the devcontainer, Docker mode (`make && make test && make lint` with the default `BUILD_MODE`) verified by the user on a host with Docker. Milestones 2–5 (SHA-256, HMAC, PBKDF2, CLI) are implemented and tested (`tests/test_sha256.py`, `test_hmac.py`, `test_pbkdf2.py`, `test_cli.py`). Milestone 6 (hardening, spec §11) is not started and is on hold: its two remaining items (bounds/integer-arithmetic review, leftover key material) are written up as checklists in README's TODO section. Performance optimization and constant-time review are explicitly out of scope (user decision): keep the code plain and readable; don't propose unrolling, SHA-NI, fast paths or benchmarks. Known cosmetic issue logged in README's TODO: `equ` constants appear as absolute symbols that mislabel `objdump` output.

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

Header dependencies come from a separate `nasm -M` pass into `build/*.d` (NASM 2.16's `-MD` drops `%include`s), so don't hand-write `.inc` prerequisites. Put every `.inc` in `include/`: NASM 2.16 searches only the cwd and `-I` paths, not the source file's directory, so a `.inc` next to its module fails to assemble (and `-M` records it without a path). The `-M` pass is preprocess-only, so `%if` on `equ` values fails there; wrap such assemble-time checks in `%if __?PASS?__ != 0` (NASM 2.16.01 reports pass 0 in `-M` mode), as `pbkdf2.asm`'s frame-alignment check does. Also in NASM 2.16.01, plain `alignb N` makes `-Wall` warn about NASM's own macro ("unknown warning name: push"); write `alignb N, resb 1`. Module-private tables (e.g. SHA-256's K/H0) go inline in the `.asm`. New modules need a `vpath` entry and a place in `OBJECTS`.

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
- `include/pbkdf2.inc` holds shared interface definitions (struct offsets, constants); `include/syscalls.inc` holds Linux syscall numbers for the CLI; `include/sha256.inc` holds SHA-256 sizes and the `sha256_ctx` layout (state[8] u32 @0, length u64 bytes @32, buffer[64] @40; 104 bytes, caller-allocated).
- `.inc` files hold no `extern`s: NASM errors when a file declares `extern` for a symbol it then defines, so each consumer declares the externs it uses.
- SHA-256 exports `sha256_init/update/final` (streaming over the context; `final` zeroes it) and `sha256_compress(state, block)`. They don't validate or fail; input checking happens once, in `pbkdf2_hmac_sha256`.
- HMAC (`include/hmac.inc`) exports `hmac_sha256_init(ctx, key, len)/update/final` over a 208-byte context `{sha256_ctx inner @0, outer @104}`. After `init` both halves have absorbed exactly the padded-key block, so a byte copy of an initialized context is reusable for any message under that key. `final` zeroes both halves; its output may be the buffer last passed to `update` (PBKDF2's in-place `U_j`).
- Contexts are transparent: `tests/bindings.py` mirrors them as `ctypes.Structure`s, holds all function signatures (`bind(library)`), and `inc_constants()` assembles a NASM probe so the tests compare struct offsets against the `.inc` values exactly as NASM evaluates them.
- Public entry point: `int pbkdf2_hmac_sha256(const struct pbkdf2_params *params, uint8_t *output)`, struct `{password ptr @0, password_len @8, salt ptr @16, salt_len @24, uint32 iterations @32 (+4 padding), size_t output_len @40}` = 48 bytes (`include/pbkdf2.inc`). Offsets must match between NASM and `ctypes` and stay stable. Input policy (spec §5.1), checked in order, output untouched on error: NULL `params`/`output`, or NULL `password`/`salt` with nonzero length → `PBKDF2_ERR_NULL` 1; `iterations` 0 → `PBKDF2_ERR_ITERATIONS` 2; `output_len` 0 or > (2^32−1)·32 → `PBKDF2_ERR_OUTPUT_LEN` 3. It inits one HMAC context from the password and byte-copies it for every HMAC; output must not overlap the salt (reread per block).
- CLI (`src/cli/cli.asm`, spec §5.2): `_start` entry, no libc, raw `read`/`write`/`exit` syscalls, fixed `.bss` buffers with named size limits. Password comes from stdin (never argv, not newline-stripped), salt as hex via `-s`, output is lowercase hex + newline. Exit 0 = success, 1 = library/I/O error, 2 = usage error.
  - Limits and exit statuses are in `include/cli.inc` (password 4096, salt 1024 bytes, output 1024); `tests/test_cli.py` reads them with `inc_constants`.
  - Options are exactly `-i`/`-l`/`-s` each followed by a separate value; anything else is a usage error. All arguments are validated before stdin is read. `-i`/`-l` value 0 is passed to the library (exit 1); `-i` > 2^32−1 or `-l` over the limit is exit 2.
  - Internal helpers (`parse_decimal`, `hex_decode`, `read_all`, `write_all`, `die`, `die_usage`) follow the ABI using only caller-saved registers, so `_start` keeps its state in callee-saved ones. Every exit goes through `exit_wipe`, which zeroes the password, key and hex buffers. Messages are NUL-terminated strings.
  - `_start` pushes nothing, so its calls are aligned; it calls `pbkdf2_hmac_sha256` directly (static link, no PLT).
- When adding modules/includes, keep Makefile dependencies on actual source/`.inc` files.

## Assembly conventions

- Code must be position-independent (it goes into the `.so`): `default rel` / RIP-relative addressing, no text relocations.
- End every `.asm` file with `section .note.GNU-stack noalloc noexec nowrite progbits`; otherwise the `.so` needs an executable stack and recent glibc refuses to load it.
- Preserve callee-saved RBX, RBP, R12–R15; keep RSP 16-byte aligned at every `call` (including from `_start`).
- Calls to an exported (default-visibility) function fail to link with `ld -shared` ("relocation R_X86_64_PC32 … can not be used when making a shared object"). Across modules, write `call sha256_update wrt ..plt` (direct call in the static exe, one PLT jump in the `.so`). Within a module, call a file-local alias label placed right after the global one (e.g. `sha256_compress_local`).
- Lowercase mnemonics, `snake_case` labels/functions, UPPERCASE constants in `.inc` files; no unexplained magic numbers.
- Every exported function needs a header comment covering: purpose, args and sizes, return/error behavior, registers modified, callee-saved preserved, stack usage/alignment, whether inputs are modified, whether output may overlap input.
- Boundary tests should use guard-page buffers to catch overruns: `tests/guard.py`'s `guard` fixture (import it into the test module) / `GuardedAllocator` maps `[PROT_NONE][data][PROT_NONE]` and places a buffer flush against either guard (`at_end=True` for overruns, `False` for underruns). Valgrind and LLVM are intentionally not in the toolchain.
