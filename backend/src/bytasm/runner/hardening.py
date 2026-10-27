"""Process hardening for the API process (blueprint 5.4.1 limitations, Q6).

On Linux, marking the API process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`)
makes its `/proc/<pid>/environ` (and memory) unreadable by other processes of
the same user, such as the adapter child. This is defence in depth only: a
same-user process can still read every file the API can read, including the
database and stored blobs. It also disables core dumps of the API.
"""

import ctypes
import ctypes.util
import sys

_PR_SET_DUMPABLE = 4


def make_non_dumpable() -> bool:
    """Return True if the flag was set. A no-op (False) outside Linux."""
    if sys.platform != "linux":
        return False
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return bool(libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0)
