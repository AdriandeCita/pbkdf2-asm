"""Guard-page buffers for boundary tests (spec section 6).

A buffer is placed flush against an inaccessible (PROT_NONE) page, so a
one-byte overrun past its end, or underrun before its start, faults at once
instead of silently corrupting memory. A fault kills the pytest process;
pytest's faulthandler then prints the Python stack of the test that did it.
"""

import ctypes
import mmap

PAGE = mmap.PAGESIZE
PROT_NONE = 0

_libc = ctypes.CDLL(None, use_errno=True)
_libc.mmap.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long,
]
_libc.mmap.restype = ctypes.c_void_p
_libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
_libc.mprotect.restype = ctypes.c_int
_libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libc.munmap.restype = ctypes.c_int

MAP_FAILED = ctypes.c_void_p(-1).value


def _check(ok, what):
    if not ok:
        err = ctypes.get_errno()
        raise OSError(err, f"{what} failed")


class GuardedAllocator:
    """Hands out buffers that touch a guard page; frees them all on close().

    Each allocation maps three pages, [guard][data][guard], and places the
    buffer at the end of the data page (catches overruns) or at its start
    (catches underruns).
    """

    def __init__(self):
        self._maps = []

    def alloc(self, size, *, at_end=True, data=None):
        """Return the address of a size-byte buffer next to a guard page.

        If data is given, the buffer holds a copy of it (size may be None).
        """
        if data is not None:
            size = len(data) if size is None else size
            assert len(data) == size
        assert 0 <= size <= PAGE
        base = _libc.mmap(
            None, 3 * PAGE, mmap.PROT_READ | mmap.PROT_WRITE,
            mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0,
        )
        _check(base not in (None, MAP_FAILED), "mmap")
        self._maps.append(base)
        _check(_libc.mprotect(base, PAGE, PROT_NONE) == 0, "mprotect")
        _check(_libc.mprotect(base + 2 * PAGE, PAGE, PROT_NONE) == 0, "mprotect")
        addr = base + 2 * PAGE - size if at_end else base + PAGE
        if data:
            ctypes.memmove(addr, data, size)
        return addr

    def close(self):
        for base in self._maps:
            _libc.munmap(base, 3 * PAGE)
        self._maps.clear()


def read(addr, size):
    return ctypes.string_at(addr, size)
