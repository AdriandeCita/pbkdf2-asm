"""ctypes mirrors of the assembly structures and function signatures.

Marshalling only: nothing here computes a hash. Struct layouts are checked
against the include/*.inc constants by the tests (see inc_constants).
"""

import ctypes
import pathlib
import re
import struct
import subprocess
import tempfile

from conftest import ROOT

SHA256_BLOCK = 64
SHA256_DIGEST = 32

_vp = ctypes.c_void_p
_sz = ctypes.c_size_t

# name -> argtypes; all of these return void unless listed in _RESTYPES.
_SIGNATURES = {
    "sha256_compress": [_vp, _vp],
    "sha256_init": [_vp],
    "sha256_update": [_vp, _vp, _sz],
    "sha256_final": [_vp, _vp],
    "hmac_sha256_init": [_vp, _vp, _sz],
    "hmac_sha256_update": [_vp, _vp, _sz],
    "hmac_sha256_final": [_vp, _vp],
    "pbkdf2_hmac_sha256": [_vp, _vp],
}
_RESTYPES = {"pbkdf2_hmac_sha256": ctypes.c_int}


class Sha256Ctx(ctypes.Structure):
    """struct sha256_ctx (include/sha256.inc)."""

    _fields_ = [
        ("state", ctypes.c_uint32 * 8),
        ("length", ctypes.c_uint64),
        ("buffer", ctypes.c_uint8 * SHA256_BLOCK),
    ]


class HmacCtx(ctypes.Structure):
    """struct hmac_sha256_ctx (include/hmac.inc)."""

    _fields_ = [
        ("inner", Sha256Ctx),
        ("outer", Sha256Ctx),
    ]


class Pbkdf2Params(ctypes.Structure):
    """struct pbkdf2_params (include/pbkdf2.inc). ctypes inserts the same
    4 bytes of padding after iterations as the System V ABI does."""

    _fields_ = [
        ("password", ctypes.c_void_p),
        ("password_len", ctypes.c_size_t),
        ("salt", ctypes.c_void_p),
        ("salt_len", ctypes.c_size_t),
        ("iterations", ctypes.c_uint32),
        ("output_len", ctypes.c_size_t),
    ]


def bind(library):
    """Set argtypes/restype for every function in _SIGNATURES."""
    for name, args in _SIGNATURES.items():
        fn = getattr(library, name)
        fn.argtypes = args
        fn.restype = _RESTYPES.get(name)
    return library


def inc_constants(name):
    """Every `equ` constant in include/<name>, as NASM evaluates it.

    Assembles a probe that %includes the file and emits each constant as a
    qword, so expressions such as `2 * SHA256_CTX_SIZE` resolve exactly as
    they do in the real build.
    """
    text = (ROOT / "include" / name).read_text()
    names = re.findall(r"^\s*(\w+)\s+equ\b", text, re.M)
    probe = f'%include "{name}"\n' + "".join(f"dq {n}\n" for n in names)
    with tempfile.TemporaryDirectory() as tmp:
        src, out = pathlib.Path(tmp, "probe.asm"), pathlib.Path(tmp, "probe.bin")
        src.write_text(probe)
        subprocess.run(
            ["nasm", "-f", "bin", "-I", str(ROOT / "include") + "/", "-o", str(out), str(src)],
            check=True,
        )
        values = struct.unpack(f"<{len(names)}q", out.read_bytes())
    return dict(zip(names, values))


def addr(obj):
    return ctypes.addressof(obj)
