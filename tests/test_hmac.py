"""HMAC-SHA-256 (Milestone 3) against RFC 4231 and Python's hmac module."""

import ctypes
import hashlib
import hmac
import random

import pytest

from bindings import SHA256_BLOCK as BLOCK, SHA256_DIGEST as DIGEST, HmacCtx, addr, bind, inc_constants
from guard import guard, read  # noqa: F401 (guard is a fixture)

# RFC 4231 section 4: (key, data, HMAC-SHA-256, bytes compared).
# Test case 5 specifies output truncated to 128 bits.
RFC4231 = [
    (b"\x0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32),
    (b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32),
    (b"\xaa" * 20, b"\xdd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", 32),
    (bytes(range(1, 26)), b"\xcd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", 32),
    (b"\x0c" * 20, b"Test With Truncation",
     "a3b6167473100ee06e0c796c2955552b", 16),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32),
    (b"\xaa" * 131,
     b"This is a test using a larger than block-size key and a larger than "
     b"block-size data. The key needs to be hashed before being used by the "
     b"HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", 32),
]


@pytest.fixture(scope="module")
def lib(library):
    return bind(library)


def mac(lib, key, chunks):
    ctx = HmacCtx()
    out = (ctypes.c_uint8 * DIGEST)()
    lib.hmac_sha256_init(addr(ctx), key, len(key))
    for chunk in chunks:
        lib.hmac_sha256_update(addr(ctx), chunk, len(chunk))
    lib.hmac_sha256_final(addr(ctx), addr(out))
    return bytes(out)


def reference(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def test_ctx_layout_matches_include():
    consts = inc_constants("hmac.inc")
    assert HmacCtx.inner.offset == consts["HMAC_CTX_INNER"]
    assert HmacCtx.outer.offset == consts["HMAC_CTX_OUTER"]
    assert ctypes.sizeof(HmacCtx) == consts["HMAC_CTX_SIZE"]


@pytest.mark.parametrize("key,data,expected,size", RFC4231, ids=[f"tc{i}" for i in range(1, 8)])
def test_rfc4231(lib, key, data, expected, size):
    assert mac(lib, key, [data])[:size].hex() == expected


def test_key_lengths_around_block_size(lib):
    # Up to 64 bytes the key is zero-padded; from 65 on it is hashed first.
    rng = random.Random(1)
    msg = b"message"
    for n in range(0, 3 * BLOCK + 2):
        key = rng.randbytes(n)
        assert mac(lib, key, [msg]) == reference(key, msg), n


def test_message_lengths(lib):
    # The inner hash starts one block in, so message padding boundaries
    # fall at the same offsets as in plain SHA-256.
    rng = random.Random(2)
    key = b"key"
    for n in range(0, 3 * BLOCK + 2):
        msg = rng.randbytes(n)
        assert mac(lib, key, [msg]) == reference(key, msg), n


def test_long_inputs(lib):
    # A 1 MiB message (thousands of blocks, plus a partial one) under a
    # long key, fed whole and in uneven chunks.
    rng = random.Random(5)
    key = rng.randbytes(1000)
    msg = rng.randbytes((1 << 20) + 17)
    expected = reference(key, msg)
    assert mac(lib, key, [msg]) == expected
    chunks = [msg[i:i + 4099] for i in range(0, len(msg), 4099)]
    assert mac(lib, key, chunks) == expected


def test_long_key_equals_its_hash(lib):
    # RFC 2104: a key longer than a block is replaced by its hash.
    key = random.Random(3).randbytes(200)
    assert mac(lib, key, [b"x"]) == mac(lib, hashlib.sha256(key).digest(), [b"x"])


@pytest.mark.parametrize("sizes", [[1] * 100, [0, 0, 7, 0], [63, 1, 64, 65], [32, 32]])
def test_chunking_does_not_change_mac(lib, sizes):
    msg = random.Random(sum(sizes)).randbytes(sum(sizes))
    chunks, pos = [], 0
    for size in sizes:
        chunks.append(msg[pos:pos + size])
        pos += size
    assert mac(lib, b"k", chunks) == reference(b"k", msg)


def test_randomized_differential(lib):
    rng = random.Random(4)
    for _ in range(300):
        key = rng.randbytes(rng.randrange(0, 300))
        msg = rng.randbytes(rng.randrange(0, 1000))
        cut = rng.randrange(0, len(msg) + 1)
        assert mac(lib, key, [msg[:cut], msg[cut:]]) == reference(key, msg)


def test_null_key_and_data_with_zero_length(lib):
    ctx = HmacCtx()
    out = (ctypes.c_uint8 * DIGEST)()
    lib.hmac_sha256_init(addr(ctx), None, 0)
    lib.hmac_sha256_update(addr(ctx), None, 0)
    lib.hmac_sha256_final(addr(ctx), addr(out))
    assert bytes(out) == reference(b"", b"")


def test_initialized_context_can_be_copied(lib):
    # The PBKDF2 pattern: init once per key, then reuse a byte copy of the
    # context for each message.
    key = b"password"
    template = HmacCtx()
    lib.hmac_sha256_init(addr(template), key, len(key))
    saved = bytes(template)
    for msg in (b"", b"one", b"two" * 50):
        ctx = HmacCtx.from_buffer_copy(saved)
        out = (ctypes.c_uint8 * DIGEST)()
        lib.hmac_sha256_update(addr(ctx), msg, len(msg))
        lib.hmac_sha256_final(addr(ctx), addr(out))
        assert bytes(out) == reference(key, msg)
    assert bytes(template) == saved  # copies are independent


def test_output_may_be_the_input_buffer(lib):
    # PBKDF2 computes U_j = HMAC(P, U_{j-1}) in place.
    key = b"password"
    buf = (ctypes.c_uint8 * DIGEST)(*range(DIGEST))
    msg = bytes(buf)
    ctx = HmacCtx()
    lib.hmac_sha256_init(addr(ctx), key, len(key))
    lib.hmac_sha256_update(addr(ctx), addr(buf), DIGEST)
    lib.hmac_sha256_final(addr(ctx), addr(buf))
    assert bytes(buf) == reference(key, msg)


def test_final_wipes_context(lib):
    ctx = HmacCtx()
    out = (ctypes.c_uint8 * DIGEST)()
    lib.hmac_sha256_init(addr(ctx), b"secret", 6)
    lib.hmac_sha256_update(addr(ctx), b"msg", 3)
    lib.hmac_sha256_final(addr(ctx), addr(out))
    assert bytes(ctx) == bytes(ctypes.sizeof(ctx))


@pytest.mark.parametrize("at_end", [True, False], ids=["overrun", "underrun"])
@pytest.mark.parametrize("key_len", [0, 1, 32, 63, 64, 65, 131])
@pytest.mark.parametrize("msg_len", [0, 1, 55, 56, 64, 65, 200])
def test_guard_pages(lib, guard, key_len, msg_len, at_end):
    rng = random.Random(key_len * 1000 + msg_len)
    key, msg = rng.randbytes(key_len), rng.randbytes(msg_len)
    k = guard.alloc(key_len, data=key, at_end=at_end)
    m = guard.alloc(msg_len, data=msg, at_end=at_end)
    ctx = guard.alloc(ctypes.sizeof(HmacCtx), at_end=at_end)
    out = guard.alloc(DIGEST, at_end=at_end)
    lib.hmac_sha256_init(ctx, k, key_len)
    lib.hmac_sha256_update(ctx, m, msg_len)
    lib.hmac_sha256_final(ctx, out)
    assert read(out, DIGEST) == reference(key, msg)
    assert read(k, key_len) == key
    assert read(m, msg_len) == msg
