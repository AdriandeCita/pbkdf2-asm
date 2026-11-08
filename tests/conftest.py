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
