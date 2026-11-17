"""SHA-256 (Milestone 2) against FIPS 180-4 vectors and hashlib.sha256."""

import ctypes
import hashlib
import random
import re

import pytest

from conftest import ROOT
from guard import GuardedAllocator, read

BLOCK = 64
DIGEST = 32

# H(0) from FIPS 180-4 section 5.3.3.
H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

# FIPS 180-4 / NIST CSRC example vectors.
KNOWN_ANSWERS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
    (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
]


class Sha256Ctx(ctypes.Structure):
    """Mirror of struct sha256_ctx in include/sha256.inc."""

    _fields_ = [
        ("state", ctypes.c_uint32 * 8),
        ("length", ctypes.c_uint64),
        ("buffer", ctypes.c_uint8 * BLOCK),
    ]


@pytest.fixture(scope="module")
def lib(library):
    vp, sz = ctypes.c_void_p, ctypes.c_size_t
    for name, args in [
        ("sha256_compress", [vp, vp]),
        ("sha256_init", [vp]),
        ("sha256_update", [vp, vp, sz]),
        ("sha256_final", [vp, vp]),
    ]:
        fn = getattr(library, name)
        fn.argtypes = args
        fn.restype = None
    return library


@pytest.fixture
def guard():
    allocator = GuardedAllocator()
    yield allocator
    allocator.close()


def addr(obj):
    return ctypes.addressof(obj)


def digest(lib, chunks):
    ctx = Sha256Ctx()
    out = (ctypes.c_uint8 * DIGEST)()
    lib.sha256_init(addr(ctx))
    for chunk in chunks:
        lib.sha256_update(addr(ctx), chunk, len(chunk))
    lib.sha256_final(addr(ctx), addr(out))
    return bytes(out)


def test_ctx_layout_matches_include():
    text = (ROOT / "include" / "sha256.inc").read_text()
    consts = {m[1]: int(m[2]) for m in re.finditer(r"^(SHA256_\w+)\s+equ\s+(\d+)", text, re.M)}
    assert Sha256Ctx.state.offset == consts["SHA256_CTX_STATE"]
    assert Sha256Ctx.length.offset == consts["SHA256_CTX_LENGTH"]
    assert Sha256Ctx.buffer.offset == consts["SHA256_CTX_BUFFER"]
    assert ctypes.sizeof(Sha256Ctx) == consts["SHA256_CTX_SIZE"]
    assert consts["SHA256_BLOCK_SIZE"] == BLOCK
    assert consts["SHA256_DIGEST_SIZE"] == DIGEST


def test_init_sets_h0_and_zero_length(lib):
    ctx = Sha256Ctx()
    ctypes.memset(addr(ctx), 0xAA, ctypes.sizeof(ctx))
    lib.sha256_init(addr(ctx))
    assert tuple(ctx.state) == H0
    assert ctx.length == 0


def test_compress_single_block(lib):
    # FIPS 180-4 example: "abc" padded to one block (section 5.1.1).
    msg = b"abc"
    block = msg + b"\x80" + bytes(BLOCK - len(msg) - 9) + (8 * len(msg)).to_bytes(8, "big")
    state = (ctypes.c_uint32 * 8)(*H0)
    lib.sha256_compress(addr(state), block)
    got = b"".join(w.to_bytes(4, "big") for w in state)
    assert got == hashlib.sha256(msg).digest()


@pytest.mark.parametrize("msg,expected", KNOWN_ANSWERS, ids=lambda v: str(len(v)) if isinstance(v, bytes) else "")
def test_known_answers(lib, msg, expected):
    assert digest(lib, [msg]).hex() == expected


def test_all_lengths_around_block_boundaries(lib):
    # Covers every padding case: 0..55 fit the length in the last block,
    # 56..63 spill into an extra block, and the same again one block later.
    rng = random.Random(1)
    for n in range(0, 3 * BLOCK + 2):
        msg = rng.randbytes(n)
        assert digest(lib, [msg]) == hashlib.sha256(msg).digest(), n


def test_update_tracks_length(lib):
    ctx = Sha256Ctx()
    lib.sha256_init(addr(ctx))
    for n in (0, 1, 63, 64, 65, 200):
        lib.sha256_update(addr(ctx), bytes(n), n)
    assert ctx.length == 0 + 1 + 63 + 64 + 65 + 200


@pytest.mark.parametrize("sizes", [
    [1] * 130,
    [0, 0, 5, 0, 59, 0],
    [63, 1, 64, 0, 65],
    [55, 1, 8],
    [64, 64, 64],
    [3, 200, 7, 129],
])
def test_chunking_does_not_change_digest(lib, sizes):
    msg = random.Random(sum(sizes)).randbytes(sum(sizes))
    chunks, pos = [], 0
    for size in sizes:
        chunks.append(msg[pos:pos + size])
        pos += size
    assert digest(lib, chunks) == hashlib.sha256(msg).digest()


def test_randomized_differential(lib):
    rng = random.Random(2)
    for _ in range(300):
        msg = rng.randbytes(rng.randrange(0, 2000))
        cuts = sorted(rng.randrange(0, len(msg) + 1) for _ in range(rng.randrange(0, 5)))
        chunks = [msg[a:b] for a, b in zip([0] + cuts, cuts + [len(msg)])]
        assert digest(lib, chunks) == hashlib.sha256(msg).digest()


def test_final_wipes_context(lib):
    ctx = Sha256Ctx()
    out = (ctypes.c_uint8 * DIGEST)()
    lib.sha256_init(addr(ctx))
    lib.sha256_update(addr(ctx), b"secret key material", 19)
    lib.sha256_final(addr(ctx), addr(out))
    assert bytes(ctx) == bytes(ctypes.sizeof(ctx))


def test_update_with_null_and_zero_length(lib):
    ctx = Sha256Ctx()
    out = (ctypes.c_uint8 * DIGEST)()
    lib.sha256_init(addr(ctx))
    lib.sha256_update(addr(ctx), None, 0)
    lib.sha256_final(addr(ctx), addr(out))
    assert bytes(out) == hashlib.sha256(b"").digest()


@pytest.mark.parametrize("at_end", [True, False], ids=["overrun", "underrun"])
@pytest.mark.parametrize("n", [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1000])
def test_guard_pages(lib, guard, n, at_end):
    msg = random.Random(n).randbytes(n)
    data = guard.alloc(n, data=msg, at_end=at_end)
    ctx = guard.alloc(ctypes.sizeof(Sha256Ctx), at_end=at_end)
    out = guard.alloc(DIGEST, at_end=at_end)
    lib.sha256_init(ctx)
    lib.sha256_update(ctx, data, n)
    lib.sha256_final(ctx, out)
    assert read(out, DIGEST) == hashlib.sha256(msg).digest()
    assert read(data, n) == msg  # input untouched


@pytest.mark.parametrize("at_end", [True, False], ids=["overrun", "underrun"])
def test_compress_guard_pages(lib, guard, at_end):
    block = random.Random(3).randbytes(BLOCK)
    blk = guard.alloc(BLOCK, data=block, at_end=at_end)
    state = guard.alloc(DIGEST, data=b"".join(w.to_bytes(4, "little") for w in H0), at_end=at_end)
    lib.sha256_compress(state, blk)
    assert read(blk, BLOCK) == block
