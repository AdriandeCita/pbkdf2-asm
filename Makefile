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
