"""PBKDF2-HMAC-SHA-256 (Milestone 4) against RFC 7914 and hashlib.pbkdf2_hmac."""

import ctypes
import hashlib
import random

import pytest

from bindings import SHA256_DIGEST as DIGEST, Pbkdf2Params, addr, bind, inc_constants
from guard import guard, read  # noqa: F401 (guard is a fixture)

PBKDF2_OK = 0
PBKDF2_ERR_NULL = 1
PBKDF2_ERR_ITERATIONS = 2
PBKDF2_ERR_OUTPUT_LEN = 3
MAX_OUTPUT_LEN = (2**32 - 1) * DIGEST  # RFC 8018 section 5.2

SENTINEL = 0xA5

# RFC 7914 section 11.
RFC7914 = [
    (b"passwd", b"salt", 1, 64,
     "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
     "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
    (b"Password", b"NaCl", 80000, 64,
     "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
     "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
]


@pytest.fixture(scope="module")
def lib(library):
    return bind(library)


def call(lib, password, salt, iterations, output_len, *, out_size=None):
    """Run pbkdf2_hmac_sha256; return (status, output buffer contents).

    bytes arguments are copied into ctypes buffers; None passes NULL.
    """
    keep = []

    def ptr(data):
        if data is None:
            return None
        buf = ctypes.create_string_buffer(data, max(len(data), 1))
        keep.append(buf)
        return addr(buf)

    params = Pbkdf2Params(
        ptr(password), len(password or b""), ptr(salt), len(salt or b""), iterations, output_len,
    )
    size = output_len if out_size is None else out_size
    out = (ctypes.c_uint8 * size)(*([SENTINEL] * size))
    status = lib.pbkdf2_hmac_sha256(addr(params), addr(out))
    return status, bytes(out)


def derive(lib, password, salt, iterations, output_len):
    status, out = call(lib, password, salt, iterations, output_len)
    assert status == PBKDF2_OK
    return out


def reference(password, salt, iterations, output_len):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, output_len)


def test_params_layout_and_codes_match_include():
    consts = inc_constants("pbkdf2.inc")
    for field in ("password", "password_len", "salt", "salt_len", "iterations", "output_len"):
        assert getattr(Pbkdf2Params, field).offset == consts[f"PBKDF2_PARAMS_{field.upper()}"]
    assert ctypes.sizeof(Pbkdf2Params) == consts["PBKDF2_PARAMS_SIZE"]
    assert consts["PBKDF2_OK"] == PBKDF2_OK
    assert consts["PBKDF2_ERR_NULL"] == PBKDF2_ERR_NULL
    assert consts["PBKDF2_ERR_ITERATIONS"] == PBKDF2_ERR_ITERATIONS
    assert consts["PBKDF2_ERR_OUTPUT_LEN"] == PBKDF2_ERR_OUTPUT_LEN
    assert consts["PBKDF2_MAX_OUTPUT_LEN"] == MAX_OUTPUT_LEN


@pytest.mark.parametrize("password,salt,iterations,length,expected", RFC7914, ids=["c1", "c80000"])
def test_rfc7914(lib, password, salt, iterations, length, expected):
    assert derive(lib, password, salt, iterations, length).hex() == expected


def test_output_lengths_across_blocks(lib):
    # 1..100 covers partial first blocks, exact multiples of 32, and the
    # first bytes of blocks 2-4.
    for n in range(1, 101):
        assert derive(lib, b"pw", b"salt", 3, n) == reference(b"pw", b"salt", 3, n), n


def test_iteration_counts(lib):
    for c in (1, 2, 3, 4, 5, 16, 100, 1000):
        assert derive(lib, b"password", b"salt", c, 40) == reference(b"password", b"salt", c, 40), c


def test_password_lengths_around_block_size(lib):
    # The password is the HMAC key: over 64 bytes it is hashed first.
    rng = random.Random(1)
    for n in (0, 1, 31, 32, 63, 64, 65, 128, 1000):
        pw = rng.randbytes(n)
        assert derive(lib, pw, b"salt", 2, 33) == reference(pw, b"salt", 2, 33), n


def test_salt_lengths_around_block_size(lib):
    # S || INT(i) is the first HMAC message: 55/56 and 59/60 bytes are where
    # its padding needs an extra block (the counter adds 4 bytes).
    rng = random.Random(2)
    for n in (0, 1, 51, 52, 55, 56, 59, 60, 63, 64, 65, 200):
        salt = rng.randbytes(n)
        assert derive(lib, b"pw", salt, 2, 33) == reference(b"pw", salt, 2, 33), n


def test_large_output(lib):
    n = 32 * 40 + 7
    assert derive(lib, b"pw", b"salt", 2, n) == reference(b"pw", b"salt", 2, n)


def test_randomized_differential(lib):
    rng = random.Random(3)
    for _ in range(200):
        pw = rng.randbytes(rng.randrange(0, 150))
        salt = rng.randbytes(rng.randrange(0, 150))
        c = rng.randrange(1, 20)
        n = rng.randrange(1, 150)
        assert derive(lib, pw, salt, c, n) == reference(pw, salt, c, n)


def test_empty_password_and_salt_may_be_null(lib):
    expected = reference(b"", b"", 2, 32)
    assert derive(lib, None, None, 2, 32) == expected
    assert derive(lib, b"", b"", 2, 32) == expected


@pytest.mark.parametrize("password,salt", [(None, b"salt"), (b"pw", None)], ids=["password", "salt"])
def test_null_pointer_with_nonzero_length(lib, password, salt):
    params = Pbkdf2Params(None, 0, None, 0, 1, 32)
    keep = []
    for field, data in (("password", password), ("salt", salt)):
        if data is None:
            setattr(params, f"{field}_len", 5)
        else:
            buf = ctypes.create_string_buffer(data)
            keep.append(buf)
            setattr(params, field, addr(buf))
            setattr(params, f"{field}_len", len(data))
    out = (ctypes.c_uint8 * 32)(*([SENTINEL] * 32))
    assert lib.pbkdf2_hmac_sha256(addr(params), addr(out)) == PBKDF2_ERR_NULL
    assert bytes(out) == bytes([SENTINEL] * 32)


def test_null_params(lib):
    out = (ctypes.c_uint8 * 32)(*([SENTINEL] * 32))
    assert lib.pbkdf2_hmac_sha256(None, addr(out)) == PBKDF2_ERR_NULL
    assert bytes(out) == bytes([SENTINEL] * 32)


def test_null_output(lib):
    params = Pbkdf2Params(None, 0, None, 0, 1, 32)
    assert lib.pbkdf2_hmac_sha256(addr(params), None) == PBKDF2_ERR_NULL


def test_zero_iterations(lib):
    status, out = call(lib, b"pw", b"salt", 0, 32)
    assert status == PBKDF2_ERR_ITERATIONS
    assert out == bytes([SENTINEL] * 32)


@pytest.mark.parametrize("output_len", [0, MAX_OUTPUT_LEN + 1, 2**63, 2**64 - 1])
def test_bad_output_len(lib, output_len):
    # The buffer is only 32 bytes: a missed check would write far past it.
    status, out = call(lib, b"pw", b"salt", 1, output_len, out_size=32)
    assert status == PBKDF2_ERR_OUTPUT_LEN
    assert out == bytes([SENTINEL] * 32)


def test_error_precedence(lib):
    # NULL beats iterations beats output_len (include/pbkdf2.inc).
    params = Pbkdf2Params(None, 1, None, 0, 0, 0)
    out = (ctypes.c_uint8 * 1)()
    assert lib.pbkdf2_hmac_sha256(addr(params), addr(out)) == PBKDF2_ERR_NULL
    params.password_len = 0
    assert lib.pbkdf2_hmac_sha256(addr(params), addr(out)) == PBKDF2_ERR_ITERATIONS
    params.iterations = 1
    assert lib.pbkdf2_hmac_sha256(addr(params), addr(out)) == PBKDF2_ERR_OUTPUT_LEN


def test_iterations_padding_is_ignored(lib):
    # Only the low 32 bits at offset 32 are iterations; the 4 padding bytes
    # after them may hold anything.
    params = Pbkdf2Params(None, 0, None, 0, 2, 32)
    raw = (ctypes.c_uint8 * ctypes.sizeof(params)).from_buffer(params)
    raw[Pbkdf2Params.iterations.offset + 4:Pbkdf2Params.output_len.offset] = (ctypes.c_uint8 * 4)(0xFF, 0xFF, 0xFF, 0xFF)
    out = (ctypes.c_uint8 * 32)()
    assert lib.pbkdf2_hmac_sha256(addr(params), addr(out)) == PBKDF2_OK
    assert bytes(out) == reference(b"", b"", 2, 32)


@pytest.mark.parametrize("at_end", [True, False], ids=["overrun", "underrun"])
@pytest.mark.parametrize("output_len", [1, 31, 32, 33, 64, 65])
@pytest.mark.parametrize("pw_len,salt_len", [(0, 0), (1, 1), (64, 60), (65, 64)])
def test_guard_pages(lib, guard, output_len, pw_len, salt_len, at_end):
    rng = random.Random(output_len * 10000 + pw_len * 100 + salt_len)
    pw, salt = rng.randbytes(pw_len), rng.randbytes(salt_len)
    p = guard.alloc(pw_len, data=pw, at_end=at_end)
    s = guard.alloc(salt_len, data=salt, at_end=at_end)
    out = guard.alloc(output_len, at_end=at_end)
    params = Pbkdf2Params(p, pw_len, s, salt_len, 3, output_len)
    prm = guard.alloc(ctypes.sizeof(params), data=bytes(params), at_end=at_end)
    assert lib.pbkdf2_hmac_sha256(prm, out) == PBKDF2_OK
    assert read(out, output_len) == reference(pw, salt, 3, output_len)
    assert read(p, pw_len) == pw
    assert read(s, salt_len) == salt
    assert read(prm, ctypes.sizeof(params)) == bytes(params)
