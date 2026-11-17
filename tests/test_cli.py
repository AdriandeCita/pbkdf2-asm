"""The pbkdf2 executable (Milestone 5, spec 5.2), end to end via subprocess.

The oracle is hashlib.pbkdf2_hmac; these tests cover what the ctypes tests
cannot reach: argument parsing, hex decoding, stdin/stdout, exit statuses.
"""

import hashlib
import os
import random
import subprocess
import time

import pytest

from bindings import inc_constants

LIMITS = inc_constants("cli.inc")
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
MAX_PASSWORD = LIMITS["CLI_MAX_PASSWORD_LEN"]
MAX_SALT = LIMITS["CLI_MAX_SALT_LEN"]
MAX_OUTPUT = LIMITS["CLI_MAX_OUTPUT_LEN"]


def run(cli, args, password=b"", **kwargs):
    if "stdin" not in kwargs:
        kwargs["input"] = password
    return subprocess.run([cli, *args], capture_output=True, **kwargs)


def args(iterations, length, salt_hex):
    return ["-i", str(iterations), "-l", str(length), "-s", salt_hex]


def expected(password, salt, iterations, length):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, length).hex().encode() + b"\n"


def assert_ok(result, password, salt, iterations, length):
    assert result.stderr == b""
    assert result.returncode == EXIT_SUCCESS
    assert result.stdout == expected(password, salt, iterations, length)


def assert_fails(result, status):
    """Nonzero exit: exact status, nothing on stdout, one line on stderr."""
    assert result.returncode == status, result.stderr
    assert result.stdout == b""
    assert result.stderr.startswith(b"pbkdf2: ")
    assert result.stderr.endswith(b"\n")
    assert result.stderr.count(b"\n") == 1


def test_limits_and_statuses_match_include():
    assert LIMITS["EXIT_SUCCESS"] == EXIT_SUCCESS
    assert LIMITS["EXIT_FAILURE"] == EXIT_FAILURE
    assert LIMITS["EXIT_USAGE"] == EXIT_USAGE


# --- Success -----------------------------------------------------------------

def test_rfc7914_vector(cli):
    result = run(cli, args(1, 64, "73616c74"), b"passwd")
    assert result.stdout == (
        b"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        b"49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783\n"
    )
    assert result.returncode == EXIT_SUCCESS


def test_randomized_differential(cli):
    rng = random.Random(1)
    for _ in range(60):
        pw = rng.randbytes(rng.randrange(0, 100))
        salt = rng.randbytes(rng.randrange(0, 60))
        c = rng.randrange(1, 10)
        n = rng.randrange(1, 100)
        assert_ok(run(cli, args(c, n, salt.hex()), pw), pw, salt, c, n)


@pytest.mark.parametrize("password", [b"", b"\x00", b"a\x00b", b"pw\n", b"\n\n", bytes(range(256))],
                         ids=["empty", "nul", "inner-nul", "newline", "newlines", "all-bytes"])
def test_binary_passwords_used_exactly(cli, password):
    assert_ok(run(cli, args(2, 32, "73616c74"), password), password, b"salt", 2, 32)


def test_trailing_newline_is_not_stripped(cli):
    with_nl = run(cli, args(1, 32, "00"), b"pw\n").stdout
    without = run(cli, args(1, 32, "00"), b"pw").stdout
    assert with_nl != without
    assert with_nl == expected(b"pw\n", b"\x00", 1, 32)


def test_salt_hex_case(cli):
    salt = bytes.fromhex("abcdef0123456789ABCDEF")
    for text in ("abcdef0123456789abcdef", "ABCDEF0123456789ABCDEF", "aBcDeF0123456789AbCdEf"):
        assert_ok(run(cli, args(1, 16, text), b"pw"), b"pw", salt, 1, 16)


def test_empty_salt(cli):
    assert_ok(run(cli, args(1, 16, ""), b"pw"), b"pw", b"", 1, 16)


def test_option_order_does_not_matter(cli):
    want = expected(b"pw", b"\x12\x34", 3, 20)
    for order in (["-i", "3", "-l", "20", "-s", "1234"],
                  ["-s", "1234", "-i", "3", "-l", "20"],
                  ["-l", "20", "-s", "1234", "-i", "3"]):
        assert run(cli, order, b"pw").stdout == want


def test_leading_zeros(cli):
    assert_ok(run(cli, ["-i", "0003", "-l", "007", "-s", "00"], b"pw"), b"pw", b"\x00", 3, 7)


@pytest.mark.parametrize("length", [1, 31, 32, 33, 64, 65, 100, MAX_OUTPUT])
def test_output_lengths(cli, length):
    # Several of these need multiple PBKDF2 blocks; MAX_OUTPUT is 32 of them.
    assert_ok(run(cli, args(2, length, "73616c74"), b"pw"), b"pw", b"salt", 2, length)


def test_password_at_limit(cli):
    pw = random.Random(2).randbytes(MAX_PASSWORD)
    assert_ok(run(cli, args(1, 32, "00"), pw), pw, b"\x00", 1, 32)


def test_salt_at_limit(cli):
    salt = random.Random(3).randbytes(MAX_SALT)
    assert_ok(run(cli, args(1, 32, salt.hex()), b"pw"), b"pw", salt, 1, 32)


def test_password_in_slow_chunks(cli):
    # Several short reads from a pipe; read_all must keep going until EOF.
    proc = subprocess.Popen([cli, *args(1, 32, "00")], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for piece in (b"pass", b"\x00", b"word\n"):
        proc.stdin.write(piece)
        proc.stdin.flush()
        time.sleep(0.05)
    proc.stdin.close()
    out, err = proc.stdout.read(), proc.stderr.read()
    assert proc.wait() == EXIT_SUCCESS, err
    assert out == expected(b"pass\x00word\n", b"\x00", 1, 32)


# --- Usage errors (exit 2) ----------------------------------------------------

@pytest.mark.parametrize("argv", [
    [],
    ["-i", "1", "-l", "1"],
    ["-i", "1", "-s", "00"],
    ["-l", "1", "-s", "00"],
], ids=["none", "no-s", "no-l", "no-i"])
def test_missing_options(cli, argv):
    assert_fails(run(cli, argv, b"pw"), EXIT_USAGE)


@pytest.mark.parametrize("argv", [
    ["-i", "1", "-i", "2", "-l", "1", "-s", "00"],
    ["-i", "1", "-l", "1", "-l", "2", "-s", "00"],
    ["-i", "1", "-l", "1", "-s", "00", "-s", "00"],
], ids=["i", "l", "s"])
def test_repeated_options(cli, argv):
    assert_fails(run(cli, argv, b"pw"), EXIT_USAGE)


@pytest.mark.parametrize("extra", [["-x", "1"], ["--i", "1"], ["-ii", "1"], ["-", "1"], ["foo"], [""]],
                         ids=["unknown", "long", "glued", "dash", "positional", "empty"])
def test_unknown_arguments(cli, extra):
    assert_fails(run(cli, args(1, 1, "00") + extra, b"pw"), EXIT_USAGE)


@pytest.mark.parametrize("opt", ["-i", "-l", "-s"])
def test_option_without_value(cli, opt):
    others = {"-i": ["-l", "1", "-s", "00"], "-l": ["-i", "1", "-s", "00"], "-s": ["-i", "1", "-l", "1"]}
    assert_fails(run(cli, others[opt] + [opt], b"pw"), EXIT_USAGE)


BAD_NUMBERS = ["", "abc", "1a", "a1", "-1", "+1", " 1", "1 ", "1.0", "0x10", "\xff"]


@pytest.mark.parametrize("value", BAD_NUMBERS)
def test_malformed_iterations(cli, value):
    assert_fails(run(cli, ["-i", value, "-l", "1", "-s", "00"], b"pw"), EXIT_USAGE)


@pytest.mark.parametrize("value", BAD_NUMBERS)
def test_malformed_length(cli, value):
    assert_fails(run(cli, ["-i", "1", "-l", value, "-s", "00"], b"pw"), EXIT_USAGE)


@pytest.mark.parametrize("value", [str(2**32), str(2**64 - 1), str(2**64), "9" * 40])
def test_iterations_overflow(cli, value):
    assert_fails(run(cli, ["-i", value, "-l", "1", "-s", "00"], b"pw"), EXIT_USAGE)


@pytest.mark.parametrize("value", [str(MAX_OUTPUT + 1), str(2**64 - 1), str(2**64), "9" * 40])
def test_length_over_limit(cli, value):
    assert_fails(run(cli, ["-i", "1", "-l", value, "-s", "00"], b"pw"), EXIT_USAGE)


@pytest.mark.parametrize("salt", ["0", "abc", "zz", "0g", "g0", "0x12", "12 3", "12:3", "@1", "`1", "\xe9\xe9"],
                         ids=["one-digit", "odd", "zz", "0g", "g0", "0x", "space", "colon", "at", "backtick", "non-ascii"])
def test_malformed_salt(cli, salt):
    assert_fails(run(cli, args(1, 1, salt), b"pw"), EXIT_USAGE)


def test_salt_over_limit(cli):
    assert_fails(run(cli, args(1, 1, "00" * (MAX_SALT + 1)), b"pw"), EXIT_USAGE)


def test_password_over_limit(cli):
    assert_fails(run(cli, args(1, 1, "00"), bytes(MAX_PASSWORD + 1)), EXIT_USAGE)


def test_usage_error_does_not_read_stdin(cli):
    # Arguments are checked first; with a bad argument stdin is left alone,
    # so this must not block even though stdin is never closed.
    r, w = os.pipe()
    try:
        result = subprocess.run([cli, "-x"], stdin=r, capture_output=True, timeout=5)
    finally:
        os.close(r)
        os.close(w)
    assert_fails(result, EXIT_USAGE)


# --- Library and I/O errors (exit 1) ------------------------------------------

def test_zero_iterations(cli):
    assert_fails(run(cli, args(0, 32, "00"), b"pw"), EXIT_FAILURE)


def test_zero_length(cli):
    assert_fails(run(cli, args(1, 0, "00"), b"pw"), EXIT_FAILURE)


def test_unreadable_stdin(cli):
    # read(2) on a directory fails with EISDIR.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert_fails(run(cli, args(1, 32, "00"), stdin=fd), EXIT_FAILURE)
    finally:
        os.close(fd)


def test_unwritable_stdout(cli):
    # write(2) to /dev/full fails with ENOSPC.
    with open("/dev/full", "wb") as full:
        result = subprocess.run([cli, *args(1, 32, "00")], input=b"pw", stdout=full, stderr=subprocess.PIPE)
    assert result.returncode == EXIT_FAILURE
    assert result.stderr == b"pbkdf2: cannot write to stdout\n"
