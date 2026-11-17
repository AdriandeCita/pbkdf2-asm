# PBKDF2 Assembly Project — Local Setup Specification

## 1. Purpose and scope

Build an educational, from-scratch implementation of **PBKDF2-HMAC-SHA-256** in x86-64 assembly.

The cryptographic implementation must be written in NASM assembly. Python is permitted only for the test harness, reference calculations, and developer scripts. Do not use a C implementation of SHA-256, HMAC, or PBKDF2.

The project produces two artifacts from the same assembly objects:

- `build/libpbkdf2.so` — a shared library loaded by the Python test harness through `ctypes`.
- `build/pbkdf2` — a self-contained command-line executable, also written in NASM, that runs directly from the shell. It is statically linked, does not use libc, and talks to the kernel through raw Linux system calls. It needs no Python or other runtime.

No C code is used anywhere in the project, including the command-line wrapper.

This project prioritizes:

- Learning x86-64 assembly and the System V AMD64 ABI.
- Small, independently testable cryptographic modules.
- Reproducible builds.
- Useful debugging and inspection tools.
- A minimal toolchain and build system.

It is an educational project, not a production password-storage library. Do not deploy the implementation to protect real user passwords without independent security review.

## 2. Target platform and conventions

| Item | Choice |
|---|---|
| Target | Linux x86-64 |
| Assembler | NASM |
| Object format | ELF64 |
| Linker | GNU `ld` (binutils); no C compiler required |
| Calling convention | System V AMD64 ABI |
| Assembly syntax | NASM / Intel syntax |
| Build system | GNU Make |
| Default build environment | Docker |
| Tests | Python 3 + pytest |
| Debugger | GDB |

Use `default rel` in NASM source where appropriate for RIP-relative addressing. Shared-library objects must be position-independent and must not introduce unwanted text relocations.

The project should also permit a developer to use locally installed tools instead of Docker by explicitly selecting the host build mode (`BUILD_MODE=host`, see §4.3). Docker remains the default.

There are three supported environments:

| Environment | Build mode | Used for |
|---|---|---|
| Fresh clone on any machine with Docker | `docker` (default) | Building, and optionally testing, with no local toolchain |
| Plain host with `nasm`, `binutils`, `make` | `host` | Building the artifacts without Docker; tests also work if Python 3 and pytest are installed |
| Development container (`.devcontainer/`) | `host`, preset | Day-to-day development, including by a coding agent: build, test, debug |

The built executable is the demonstration artifact and needs none of these environments to run.

## 3. Repository layout

Create the following structure:

```text
pbkdf2-asm/
├── Dockerfile
├── .dockerignore
├── Makefile
├── pytest.ini
├── README.md
├── .gitignore
│
├── src/
│   ├── sha256/
│   │   └── sha256.asm
│   ├── hmac/
│   │   └── hmac.asm
│   ├── pbkdf2/
│   │   └── pbkdf2.asm
│   └── cli/
│       └── cli.asm
│
├── include/
│   ├── cli.inc
│   ├── hmac.inc
│   ├── pbkdf2.inc
│   ├── sha256.inc
│   └── syscalls.inc
│
├── tests/
│   ├── conftest.py
│   ├── bindings.py
│   ├── guard.py
│   ├── test_build.py
│   ├── test_sha256.py
│   ├── test_hmac.py
│   ├── test_pbkdf2.py
│   └── test_cli.py
│
├── scripts/
│   ├── lint.py
│   ├── benchmark.py
│   └── openssl-pbkdf2.sh
│
└── build/
    └── .gitkeep
```

Responsibilities:

- `src/sha256`: SHA-256 compression and complete hash operation. The round constants (K) and initial hash values (H0) are `.rodata` tables in `sha256.asm` itself, since no other module uses them.
- `src/hmac`: HMAC-SHA-256 built on the SHA-256 module.
- `src/pbkdf2`: PBKDF2 built on HMAC.
- `src/cli`: the standalone executable's entry point (`_start`), argument parsing, stdin reading, hex encoding/decoding, and error reporting. Linked only into `build/pbkdf2`, never into the shared library.
- `include`: shared interface definitions and assembly declarations. `sha256.inc` holds the SHA-256 sizes and the layout of the caller-allocated `sha256_ctx` used by the streaming `sha256_init`/`sha256_update`/`sha256_final` functions. `hmac.inc` does the same for `hmac_sha256_ctx` (an inner and an outer `sha256_ctx`). `syscalls.inc` holds the Linux x86-64 system call numbers and constants used by the CLI, and `cli.inc` the CLI's exit statuses and size limits.
- `tests`: independent tests for each primitive, plus end-to-end tests of the executable.
- `scripts`: lightweight source checks, later benchmarking, and `openssl-pbkdf2.sh`, a wrapper with the executable's interface that computes the key with `openssl kdf`, for side-by-side comparison (developer tool only; it passes the password to OpenSSL as an argument).
- `build`: generated object files, the shared library, and the executable; never commit generated artifacts.

Keep the modules independent. SHA-256 must not know about HMAC, HMAC must not know about PBKDF2, and none of the cryptographic modules may know about the CLI. The CLI uses only the public `pbkdf2_hmac_sha256` entry point and must not call internal SHA-256 or HMAC routines. Cryptographic modules must not make system calls.

## 4. Docker-based development environment

### 4.1 Requirements on the host

The host should only need:

- Docker Engine or Docker Desktop with Linux-container support.
- GNU Make.
- Git (recommended).

Do not require NASM, binutils, Python, pytest, or GDB to be installed on the host when using the default workflow.

For host mode, building needs only GNU Make, NASM, and binutils. Python 3 and pytest are needed only for `make test`, and GDB only for `make debug`.

The built executable `build/pbkdf2` has no runtime dependencies and can be run on any Linux x86-64 host, inside or outside the container.

### 4.2 Dockerfile

Create a `Dockerfile` at the repository root:

```dockerfile
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    nasm \
    make \
    binutils \
    gdb \
    python3 \
    python3-pytest \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["bash"]
```

The image contains the assembler, the linker (`ld`, from binutils), the debugger, the test runner, and inspection tools (`objdump`, `readelf`, `nm`, also from binutils). Dependencies are installed in the image rather than on the host.

No C compiler is installed: both artifacts are linked directly with `ld`. Valgrind and LLVM are intentionally omitted (see §8); add them later only if a milestone needs them.

For reproducibility beyond an educational local setup, pin the base image to a specific digest and manage package versions deliberately.

### 4.3 Makefile: Docker is the default

The ordinary commands (`make`, `make test`, `make lint`, `make debug`, and `make disasm`) run inside the Docker image by default. Setting `BUILD_MODE=host` makes the same commands run the tools directly, with no Docker involved.

Use a Makefile with two layers:

1. Public targets whose behavior depends on `BUILD_MODE`: in `docker` mode they run the matching internal target in the build container; in `host` mode they run it directly.
2. Internal `host-*` targets that execute the actual commands. These are what runs inside the container.

The Makefile (kept identical to the one in the repository):

```makefile
# docker (default): run every step in the build image.
# host: run the tools directly (devcontainer, or a host with the tools).
BUILD_MODE  ?= docker

IMAGE       := pbkdf2-asm-dev
DOCKER      := docker
# Run as the invoking user so files created in the bind-mounted tree
# (build/, .pytest_cache/) are owned by them rather than by root.
DOCKER_OPTS := --rm \
               --user "$(shell id -u):$(shell id -g)" \
               -v "$(CURDIR):/work" \
               -w /work
DOCKER_RUN  := $(DOCKER) run $(DOCKER_OPTS) $(IMAGE)
# GDB is interactive and needs a TTY.
DOCKER_RUN_IT := $(DOCKER) run $(DOCKER_OPTS) -it $(IMAGE)

ASM         := nasm
LD          := ld
ASMFLAGS    := -f elf64 -g -F dwarf -Wall -I include/

BUILD       := build
SRC         := src

SHA256      := $(BUILD)/sha256.o
HMAC        := $(BUILD)/hmac.o
PBKDF2      := $(BUILD)/pbkdf2.o
CLI         := $(BUILD)/cli.o
OBJECTS     := $(SHA256) $(HMAC) $(PBKDF2)

LIB         := $(BUILD)/libpbkdf2.so
EXE         := $(BUILD)/pbkdf2

vpath %.asm $(SRC)/sha256 $(SRC)/hmac $(SRC)/pbkdf2 $(SRC)/cli

.PHONY: all image test lint debug disasm clean \
        host-all host-test host-lint host-debug host-disasm

ifeq ($(BUILD_MODE),docker)
# Default workflow: build and execute inside Docker.
all: image
	$(DOCKER_RUN) make host-all

test: image
	$(DOCKER_RUN) make host-test

lint: image
	$(DOCKER_RUN) make host-lint

debug: image
	$(DOCKER_RUN_IT) make host-debug

disasm: image
	$(DOCKER_RUN) make host-disasm
else ifeq ($(BUILD_MODE),host)
# Explicit host mode: no Docker.
all: host-all
test: host-test
lint: host-lint
debug: host-debug
disasm: host-disasm
else
$(error BUILD_MODE must be 'docker' or 'host', not '$(BUILD_MODE)')
endif

image:
	$(DOCKER) build -t $(IMAGE) .

# Cleaning generated files does not require a container.
clean:
	rm -f $(BUILD)/*.o $(BUILD)/*.d $(BUILD)/*.so $(BUILD)/*.lst $(EXE)

$(BUILD):
	mkdir -p $(BUILD)

# The first pass writes a .d file listing every %include, so editing an
# .inc file rebuilds exactly the objects that use it.
#
# NOTE: NASM bug workaround. Dependencies would normally be written while
# assembling, in one pass, with `-MD file`. In NASM 2.16.01 (Debian
# bookworm) that option silently omits %include'd files and lists only the
# source itself, so header edits would not trigger rebuilds. `-M -MF file`
# (dependencies only, no assembly) lists them correctly, hence two passes.
# To check whether a newer NASM still has the bug:
#   nasm -f elf64 -I include/ -MD /dev/stdout src/pbkdf2/pbkdf2.asm -o /dev/null
# If include/pbkdf2.inc appears in the output, the two passes can be merged.
$(BUILD)/%.o: %.asm | $(BUILD)
	$(ASM) $(ASMFLAGS) -M -MF $(@:.o=.d) -MT $@ -MP $<
	$(ASM) $(ASMFLAGS) $< -o $@

-include $(wildcard $(BUILD)/*.d)

# Internal targets: run inside the build container,
# or via BUILD_MODE=host (devcontainer, or a host with the tools).
host-all: $(LIB) $(EXE)

# Shared library for the Python test harness.
$(LIB): $(OBJECTS)
	$(LD) -shared -o $@ $(OBJECTS)

# Static, libc-free executable. Entry point is _start in cli.asm.
$(EXE): $(CLI) $(OBJECTS)
	$(LD) -static -o $@ $(CLI) $(OBJECTS)

host-test: host-all
	python3 -m pytest -v tests/

host-lint:
	python3 scripts/lint.py

host-debug: host-all
	gdb --args python3 -m pytest -v tests/

host-disasm: host-all
	objdump -d -Mintel $(LIB)
	objdump -d -Mintel $(EXE)
```

Notes:

- `make` builds the Docker image if necessary, then builds the project in a disposable container.
- `make test`, `make lint`, `make debug`, and `make disasm` also use Docker by default. `make debug` runs the container with `-it` because GDB needs an interactive terminal.
- `make BUILD_MODE=host` (or `BUILD_MODE=host` exported in the environment) runs every public target directly with local tools. The development container sets this variable, so plain `make` and `make test` work there without Docker.
- An unknown `BUILD_MODE` value is an error rather than a silent fallback.
- `host-all` builds both the shared library and the executable from the same cryptographic objects. Neither link step uses a C compiler or libc.
- The bind mount makes generated files appear in the project directory on the host.
- The container is removed after each command; the image is retained.
- `make clean` removes generated build artifacts directly on the host.
- The `host-*` targets are the internal implementation. They run inside the build container and are what host mode maps to. Calling them directly also works and never invokes Docker, but `BUILD_MODE=host` is the documented interface.
- Every object is built by one pattern rule; `vpath` finds each `.asm` in its module directory. A new module needs a `vpath` entry, an object variable, and a place in `OBJECTS` (or, for CLI-only code, in the `$(EXE)` link).
- Containers run with `--user $(id -u):$(id -g)`, so files created in the bind-mounted tree are owned by the invoking user, not root. The user has no entry in the image's `/etc/passwd`; nothing in the build or tests needs one.

Header dependencies are generated, not written by hand: each object's recipe first runs `nasm -M` to write `build/<name>.d`, listing every `%include` the source uses, and the Makefile includes those files. Editing an `.inc` file therefore rebuilds exactly the objects that use it. This is a separate pass to work around a NASM bug: in NASM 2.16.01, `-MD` (dependencies written while assembling) omits included files. The Makefile comment explains how to check whether a newer NASM still has it.

### 4.4 Position-independent code

Because the test harness will load the implementation as a shared library, all assembly objects must be suitable for position-independent linking.

Use RIP-relative references for local data where possible. Avoid absolute addresses in executable sections. Inspect relocations with:

```bash
make disasm
```

and, when needed:

```bash
docker run --rm -v "$PWD:/work" -w /work pbkdf2-asm-dev \
    readelf -r build/libpbkdf2.so
```

The final shared-library link should not require text relocations. A quick check is `readelf -d build/libpbkdf2.so | grep TEXTREL`, which must print nothing.

The same objects are also linked into the static executable. Position-independent, RIP-relative code links into a static executable without changes, so no separate build of the cryptographic modules is needed.

Every `.asm` file must declare a non-executable stack:

```nasm
section .note.GNU-stack noalloc noexec nowrite progbits
```

Without it, `ld` warns and marks the output as needing an executable stack. Recent glibc versions refuse to `dlopen` such a shared library, which breaks the `ctypes` tests in host mode.

### 4.5 Development container

`.devcontainer/` defines the day-to-day development environment, used both by people (for example through `docker exec -it` or an IDE) and by a coding agent. It is separate from the build image: it also carries editor and agent tooling.

Requirements:

- It installs the same project toolchain as the build image in §4.2 (`nasm`, `make`, `binutils`, `gdb`, `python3`, `python3-pytest`) from the same Debian release, so both environments use the same tool versions. When the package list in one Dockerfile changes, change the other too.
- It sets `BUILD_MODE=host` in its environment, so `make`, `make test`, `make lint`, `make debug`, and `make disasm` run directly inside it. Docker is not needed or available inside the development container.
- The repository is mounted at `/workspace` there, not `/work`. Nothing in the Makefile or tests may depend on the absolute path.

## 5. Assembly interface and ABI

Use the Linux System V AMD64 ABI.

Integer and pointer arguments are passed in:

| Argument | Register |
|---|---|
| 1 | RDI |
| 2 | RSI |
| 3 | RDX |
| 4 | RCX |
| 5 | R8 |
| 6 | R9 |

Integer return values are returned in RAX.

Callee-saved registers:

- RBX
- RBP
- R12
- R13
- R14
- R15

Caller-saved registers:

- RAX
- RCX
- RDX
- RSI
- RDI
- R8–R11

Preserve all callee-saved registers used by a function. Maintain the ABI's required stack alignment before making calls. Document register use, stack layout, clobbers, and input/output ownership for every exported assembly function.

### 5.1 Initial PBKDF2 API

Use a small C-compatible structure as the public interface. The structure is an ABI description only; it does not imply that the cryptographic implementation is written in C.

```c
#include <stddef.h>
#include <stdint.h>

struct pbkdf2_params {
    const uint8_t *password;
    size_t password_len;

    const uint8_t *salt;
    size_t salt_len;

    uint32_t iterations;
    size_t output_len;
};

int pbkdf2_hmac_sha256(
    const struct pbkdf2_params *params,
    uint8_t *output
);
```

Define and document the exact structure layout and offsets for NASM and Python `ctypes`. Keep the ABI stable once tests depend on it.

Return `0` on success and a documented nonzero error code for invalid input. Define policy for zero iterations, null pointers, zero-length buffers, and output length limits before implementing the entry point.

Layout (`include/pbkdf2.inc`): `password` at offset 0, `password_len` 8, `salt` 16, `salt_len` 24, `iterations` 32 (a 32-bit field followed by 4 ignored padding bytes), `output_len` 40; 48 bytes in total.

Input policy. Checks run in this order and the first failure is returned; on any error, `output` is not written:

| Condition | Result |
|---|---|
| `params` or `output` is NULL | `PBKDF2_ERR_NULL` (1) |
| `password` or `salt` is NULL with a nonzero length | `PBKDF2_ERR_NULL` (1) |
| `password` or `salt` is empty (NULL or not) | allowed |
| `iterations` is 0 | `PBKDF2_ERR_ITERATIONS` (2) |
| `output_len` is 0, or over (2^32 − 1) × 32 (RFC 8018's limit) | `PBKDF2_ERR_OUTPUT_LEN` (3) |
| otherwise | `PBKDF2_OK` (0) |

Pointer checks only catch NULL; a dangling pointer or an output buffer shorter than `output_len` cannot be detected. Only this entry point validates its inputs: the SHA-256 and HMAC functions are internal building blocks that trust their callers.

### 5.2 Command-line executable

`build/pbkdf2` is a thin NASM wrapper around `pbkdf2_hmac_sha256`. It performs no cryptographic work of its own.

Usage:

```text
pbkdf2 -i ITERATIONS -l OUTPUT_LEN -s SALT_HEX
```

- The password is read from **stdin**: all bytes until end-of-file, used exactly as given. A trailing newline is not stripped, so use `printf`, not `echo`, when piping a password. Passwords are never accepted as command-line arguments, because arguments are visible in `ps` output and shell history.
- `-s` takes the salt as hexadecimal, so binary salts can be passed. Uppercase and lowercase hex digits are accepted; an odd number of digits or a non-hex character is a usage error.
- `-i` and `-l` are unsigned decimal numbers. Overflow and non-digit characters are usage errors. Zero values and output length limits follow the library policy from §5.1.
- On success, the derived key is written to stdout as lowercase hex followed by a single newline.

Example (RFC 7914 §11, first PBKDF2-HMAC-SHA-256 vector):

```bash
printf passwd | ./build/pbkdf2 -i 1 -l 64 -s 73616c74
```

Exit status:

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Error returned by `pbkdf2_hmac_sha256`, or an I/O error |
| 2 | Usage error: missing, unknown, or malformed arguments; input over a size limit |

Every nonzero exit prints a one-line message to stderr. Nothing is written to stdout on failure.

Implementation constraints:

- Entry point is `_start`. There is no libc and no C runtime startup code. On entry, `[rsp]` holds `argc`, followed by the `argv` pointers, a NULL, and the environment pointers.
- At `_start`, RSP is 16-byte aligned. Keep it 16-byte aligned at every `call`, including the call into `pbkdf2_hmac_sha256`.
- Use raw `syscall` instructions for `read`, `write`, and `exit` (and nothing else unless needed). Define system call numbers in `include/syscalls.inc`; do not hard-code them. A negative return value in RAX means an error (`-errno`).
- Handle short reads and short writes, and retry on `EINTR`.
- Use fixed-size buffers in `.bss` instead of dynamic allocation. Define the maximum password, salt, and output lengths as named constants and reject larger input with exit status 2. Never write past a buffer. The limits live in `include/cli.inc`: 4096 password bytes, 1024 salt bytes (2048 hex digits), and 1024 output bytes.
- Check all arguments before reading stdin, so a usage error never consumes the password.
- Clear the password and derived-key buffers before exiting.

## 6. Testing strategy

Use Python as an independent oracle. Do not reimplement the reference algorithms in the test harness.

Python's standard library provides:

- `hashlib.sha256`
- `hmac`
- `hashlib.pbkdf2_hmac`

Load the assembly shared library using `ctypes`. The wrapper should only marshal arguments and results; it must not perform cryptographic work itself. `tests/bindings.py` holds the `ctypes` structures and function signatures shared by the test modules.

Suggested test progression:

1. **SHA-256:** compare against `hashlib.sha256` and published known-answer vectors.
2. **HMAC-SHA-256:** compare against Python's `hmac` module and RFC 4231 test vectors.
3. **PBKDF2-HMAC-SHA-256:** compare against `hashlib.pbkdf2_hmac` and published PBKDF2-HMAC-SHA-256 test vectors (RFC 7914 §11; RFC 8018 defines PBKDF2 but has no test vectors).
4. **CLI:** run `build/pbkdf2` with `subprocess`, feeding the password on stdin, and compare stdout against `hashlib.pbkdf2_hmac(...).hex()`. These end-to-end tests also cover argument parsing, hex decoding, exit status, and stderr/stdout behavior, which the `ctypes` tests cannot reach.

For each module include:

- Known-answer tests.
- Boundary cases.
- Empty and short inputs where allowed by the specification.
- Inputs around block boundaries.
- Long inputs.
- Randomized differential tests.
- Regression tests for every bug discovered.

For the CLI, additionally include:

- Each exit status from §5.2, with an empty stdout on failure.
- Missing, repeated, and unknown options.
- Malformed numbers and hex: odd length, invalid characters, overflow.
- Empty password, binary passwords containing NUL and newline bytes, and passwords at and just over the size limit.
- Large `-l` values that produce multiple PBKDF2 blocks.

Test each primitive independently before testing the next layer. This makes failures much easier to localize.

To catch out-of-bounds reads and writes in the `ctypes` tests, place input and output buffers so that they end right before an inaccessible guard page: `mmap` two pages, `mprotect` the second one to `PROT_NONE`, and put the buffer at the end of the first page. A one-byte overrun then crashes the test at once. Use this for boundary-length tests of every primitive. `tests/guard.py` implements this, with a guard page on both sides so a buffer can also be placed at the start of its page to catch underruns.

### 6.1 pytest configuration

Create `pytest.ini`:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = -ra
```

Create `tests/conftest.py`:

```python
import ctypes
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "build" / "libpbkdf2.so"
EXECUTABLE = ROOT / "build" / "pbkdf2"

# PBKDF2_ABI_VERSION (include/pbkdf2.inc) that these ctypes bindings match.
ABI_VERSION = 1


@pytest.fixture(scope="session", autouse=True)
def build():
    # Always run make, so a single-test run never uses stale artifacts; it
    # is a no-op when everything is up to date. host-all, not all: pytest
    # already runs where the tools are (build container, devcontainer, or
    # host), and the build container does not set BUILD_MODE.
    subprocess.run(["make", "-s", "host-all"], cwd=ROOT, check=True)


@pytest.fixture(scope="session")
def library(build):
    lib = ctypes.CDLL(str(LIBRARY))

    lib.pbkdf2_abi_version.argtypes = []
    lib.pbkdf2_abi_version.restype = ctypes.c_uint32

    return lib


@pytest.fixture(scope="session")
def cli(build):
    return EXECUTABLE
```

When pytest runs in Docker, the artifact paths are `/work/build/...` inside the container. The bind mount maps them to the host project's `build/` directory.

## 7. Lightweight linting and inspection

There is no universally adopted NASM equivalent of `rustfmt` plus `clippy`. Keep linting modest.

Use NASM's warnings for syntax and assembler diagnostics. `scripts/lint.py` checks repository conventions:

- `snake_case` labels (local `.labels` included) and `UPPER_CASE` `equ` constants in `.asm` and `.inc` files.
- No trailing whitespace and a final newline, in assembly and Python files.
- Every `.asm` file declares the `.note.GNU-stack` section (§4.4).
- Every `global` symbol has a header comment, directly above the `global` line, containing all fields from §9.
- No symbol is exported from more than one file.

It prints `path:line: message` per problem and exits nonzero if there are any.

Do not attempt to statically prove cryptographic correctness with a home-grown linter. Correctness belongs in tests and review.

Useful inspection commands:

```bash
# Exported symbols
nm -D build/libpbkdf2.so

# ELF sections
readelf -S build/libpbkdf2.so

# Relocations; TEXTREL must not appear
readelf -r build/libpbkdf2.so
readelf -d build/libpbkdf2.so | grep TEXTREL

# Executable: must be statically linked with no program interpreter
readelf -l build/pbkdf2 | grep -i interp   # prints nothing

# Disassembly in Intel syntax
objdump -d -Mintel build/libpbkdf2.so
objdump -d -Mintel build/pbkdf2
```

Run these inside the Docker image through `make disasm` or an equivalent Docker command.

## 8. Debugging and performance tools

GDB is included in the development image. Useful commands:

```gdb
break sha256_compress
run
info registers
x/32gx $rsp
x/64bx ADDRESS
disassemble
display/i $rip
stepi
nexti
```

The executable can be debugged directly, without Python in the way. Use `starti` to stop at the first instruction of `_start`, and redirect stdin in `run`:

```bash
printf passwd > /tmp/pw
gdb --args build/pbkdf2 -i 1 -l 32 -s 73616c74
```

```gdb
starti < /tmp/pw
break pbkdf2_hmac_sha256
continue
```

Other tools available in the image:

- **objdump/readelf/nm:** inspect machine code, ELF metadata, symbols, and relocations.

Valgrind and LLVM are not included:

- **Valgrind** adds little here. Under `ctypes`, Python's own allocator hides most small heap overruns, Python itself produces a lot of noise, and Valgrind cannot detect overruns of stack buffers. The guard-page tests in §6 catch the likely bugs more directly.
- **LLVM** is not used by NASM. Its only use would be `llvm-mca` for throughput analysis during optimization (Milestone 6). Add it to the image then if needed.

None of these tools prove constant-time behavior or cryptographic security. Treat them as debugging and performance aids.

## 9. Source style

Adopt a consistent style from the beginning:

- NASM / Intel syntax only.
- Lowercase instruction mnemonics.
- `snake_case` for function and label names.
- Uppercase names for constants where appropriate.
- Explicit comments for non-obvious register usage.
- Document callee-saved registers and stack layout.
- Keep exported symbols clearly separated from internal labels.
- Avoid unexplained numeric constants.
- Prefer named constants and shared `.inc` files.
- Keep functions focused and independently testable.
- End every `.asm` file with `section .note.GNU-stack noalloc noexec nowrite progbits` (see §4.4).

Every exported function has a header comment directly above its `global` line, with one field per item. `scripts/lint.py` checks that all eight field names are present:

| Field | Content |
|---|---|
| `Purpose:` | What the function does |
| `Args:` | Arguments, their registers, and sizes |
| `Returns:` | Return value and error behavior |
| `Modifies:` | Registers modified |
| `Preserves:` | Callee-saved registers preserved |
| `Stack:` | Stack usage and alignment assumptions |
| `Inputs:` | Whether input buffers may be modified |
| `Overlap:` | Whether output may overlap input |

Example (`src/pbkdf2/pbkdf2.asm`):

```nasm
; ---------------------------------------------------------------------------
; pbkdf2_abi_version
;
; Purpose:   Report the version of the exported interface, so callers can
;            check they were built against a compatible library.
; Args:      none
; Returns:   eax = PBKDF2_ABI_VERSION (uint32). Cannot fail.
; Modifies:  rax
; Preserves: all callee-saved registers (none are used)
; Stack:     none used; no alignment assumption
; Inputs:    none
; Overlap:   not applicable (no buffers)
; ---------------------------------------------------------------------------
global pbkdf2_abi_version:function
pbkdf2_abi_version:
```

## 10. Development workflow

The normal Docker-first workflow:

```bash
# Build using Docker
make

# Run tests using Docker
make test

# Run lightweight source checks using Docker
make lint

# Start GDB with the test runner
make debug

# Inspect disassembly
make disasm

# Remove generated build files
make clean

# Run the executable directly; works on the host, no container needed
printf passwd | ./build/pbkdf2 -i 1 -l 64 -s 73616c74
```

The explicit host-tool workflow, for developers who have installed the dependencies locally (only `make`, `nasm`, and `binutils` are needed to build):

```bash
make BUILD_MODE=host          # build only
make BUILD_MODE=host test     # needs python3 and pytest
```

Inside the development container, `BUILD_MODE=host` is already set, so the plain commands from the first block (`make`, `make test`, …) run without Docker.

Commit source, tests, test vectors, scripts, and documentation. Do not commit generated object files, shared libraries, or the executable.

## 11. Implementation milestones

Work in dependency order:

### Milestone 1 — Project scaffold

- Create the repository layout.
- Build the Docker image.
- Verify `make` invokes Docker by default.
- Verify `make BUILD_MODE=host` builds without Docker when the tools are installed locally.
- Add the project toolchain to `.devcontainer/` (§4.5) and verify that `make` and `make test` work inside it without Docker.
- Verify the container can create build artifacts in the mounted project directory.
- Add a trivial assembly function and confirm it can be loaded from Python. This is `pbkdf2_abi_version`, which returns `PBKDF2_ABI_VERSION` from `include/pbkdf2.inc`; it stays as part of the interface.
- Add a minimal `src/cli/cli.asm` whose `_start` exits with status 0 using a raw `exit` system call. Confirm `build/pbkdf2` links statically and runs on the host.

### Milestone 2 — SHA-256

Implement and test:

- SHA-256 constants.
- Message schedule expansion.
- Compression function.
- Message padding and arbitrary-length input handling.
- Final digest serialization.

Verify against independent test vectors and Python.

### Milestone 3 — HMAC-SHA-256

Implement and test:

- Key normalization.
- Inner and outer pad processing.
- HMAC computation.
- Correct handling of keys longer than the SHA-256 block size.

Verify against RFC 4231 and Python's `hmac`.

### Milestone 4 — PBKDF2

Implement and test:

- Salt plus big-endian block counter.
- Iterative HMAC computation.
- XOR accumulation.
- Multiple output blocks.
- Output truncation and parameter validation.

Verify against RFC 7914 §11 test vectors and Python's `hashlib.pbkdf2_hmac`.

### Milestone 5 — Command-line executable

Start only after Milestone 4 passes, so CLI bugs cannot hide cryptographic bugs. Implement and test, as specified in §5.2:

- `_start`: reading `argc`/`argv` from the initial stack, stack alignment, exit status.
- System call helpers for `read`, `write`, and `exit`, with short-read/short-write and `EINTR` handling.
- Option parsing, decimal parsing with overflow detection, and hex decoding of the salt.
- Reading the password from stdin into a bounded buffer.
- Calling `pbkdf2_hmac_sha256`, hex-encoding the result, and mapping errors to exit statuses and stderr messages.
- Clearing the password and derived-key buffers before exit.

Verify with `tests/test_cli.py` against `hashlib.pbkdf2_hmac`, and confirm the executable is static with no program interpreter (§7).

### Milestone 6 — Hardening and optimization

- Expand boundary and randomized tests.
- Review buffer bounds and integer arithmetic.
- Review constant-time behavior, especially secret-dependent branches and memory accesses.
- Clear temporary key material where appropriate.
- Benchmark before optimizing.
- Inspect generated machine code and test after every optimization.

## 12. References

- [NASM documentation](https://www.nasm.us/doc/)
- [System V AMD64 ABI](https://gitlab.com/x86-psABIs/x86-64-ABI)
- [NIST FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [RFC 4231 — HMAC test cases](https://www.rfc-editor.org/rfc/rfc4231)
- [RFC 8018 — PKCS #5 / PBKDF2](https://www.rfc-editor.org/rfc/rfc8018)
- [RFC 7914 §11 — PBKDF2-HMAC-SHA-256 test vectors](https://www.rfc-editor.org/rfc/rfc7914#section-11)
- [Linux x86-64 system call table (kernel source)](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)
- [Python hashlib documentation](https://docs.python.org/3/library/hashlib.html)
- [pytest documentation](https://docs.pytest.org/)
- [GDB documentation](https://sourceware.org/gdb/documentation/)

---

## Acceptance checklist for the initial scaffold

- [x] Repository structure exists.
- [ ] Docker image builds successfully.
- [ ] `make` uses Docker by default.
- [ ] `make test` runs pytest inside Docker.
- [ ] `make lint` runs source checks inside Docker.
- [x] `make clean` removes generated artifacts.
- [x] `make BUILD_MODE=host` builds without Docker.
- [x] `make` and `make test` work inside the devcontainer without Docker.
- [ ] Build artifacts are visible in the host working tree.
- [x] A trivial NASM ELF64 function can be assembled, linked, and loaded from Python.
- [x] A minimal `build/pbkdf2` links statically without libc and exits 0 when run on the host.
- [x] No cryptographic implementation has been added before the scaffold is verified.
