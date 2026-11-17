"""Properties of the built artifacts that the spec requires (sections 4.4, 7).

These read the ELF program headers directly, so they need no binutils.
"""

import struct
import subprocess

from conftest import ABI_VERSION, EXECUTABLE, LIBRARY

PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 0x1

DT_NULL = 0
DT_TEXTREL = 22
DT_FLAGS = 30
DF_TEXTREL = 0x4


def program_headers(path):
    """Return (data, [(p_type, p_flags, p_offset, p_filesz), ...])."""
    data = path.read_bytes()
    assert data[:4] == b"\x7fELF", f"{path} is not an ELF file"
    assert data[4] == 2, "expected ELFCLASS64"
    assert data[5] == 1, "expected little-endian"
    (e_phoff,) = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    headers = []
    for i in range(e_phnum):
        p_type, p_flags, p_offset, _, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, e_phoff + i * e_phentsize
        )
        headers.append((p_type, p_flags, p_offset, p_filesz))
    return data, headers


def dynamic_entries(path):
    data, headers = program_headers(path)
    entries = []
    for p_type, _, p_offset, p_filesz in headers:
        if p_type != PT_DYNAMIC:
            continue
        for off in range(p_offset, p_offset + p_filesz, 16):
            tag, value = struct.unpack_from("<qQ", data, off)
            if tag == DT_NULL:
                break
            entries.append((tag, value))
    return entries


def test_library_reports_abi_version(library):
    assert library.pbkdf2_abi_version() == ABI_VERSION


def test_library_has_no_text_relocations():
    for tag, value in dynamic_entries(LIBRARY):
        assert tag != DT_TEXTREL
        if tag == DT_FLAGS:
            assert not value & DF_TEXTREL


def test_stacks_are_not_executable():
    for path in (LIBRARY, EXECUTABLE):
        _, headers = program_headers(path)
        stacks = [flags for p_type, flags, _, _ in headers if p_type == PT_GNU_STACK]
        assert stacks, f"{path.name}: no PT_GNU_STACK header"
        assert not stacks[0] & PF_X, f"{path.name}: executable stack"


def test_executable_is_static_without_interpreter():
    _, headers = program_headers(EXECUTABLE)
    types = {p_type for p_type, _, _, _ in headers}
    assert PT_INTERP not in types
    assert PT_DYNAMIC not in types


def test_executable_runs(cli):
    # Full behavior is in test_cli.py; this only checks the binary starts
    # and exits cleanly on its own (no loader, no libc).
    result = subprocess.run(
        [cli, "-i", "1", "-l", "1", "-s", ""], input=b"", capture_output=True
    )
    assert result.returncode == 0
    assert result.stderr == b""
