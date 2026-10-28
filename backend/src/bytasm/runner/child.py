"""Code that runs *inside* the adapter child, before any parser is imported.

Only the standard library is imported here, so applying the limits cannot be
preceded by loading LIEF (or anything that loads it).
"""

import argparse
import hashlib
import os
import resource
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

# Exit codes of the adapter contract (blueprint 5.6).
EXIT_OK: Final = 0
EXIT_REJECTED: Final = 2  # one reason code on stdout
# Any other code is a failure. These two are used by Bytasm's own adapters.
EXIT_LIMITS_NOT_APPLIED: Final = 3
EXIT_INPUT_MISMATCH: Final = 4


@dataclass(frozen=True)
class ChildArgs:
    input: str
    out: str
    expected_sha256: str
    max_input_bytes: int
    address_space_bytes: int
    cpu_seconds: int
    file_size_bytes: int


def parse_child_args(argv: Sequence[str] | None = None) -> ChildArgs:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--max-input-bytes", type=int, required=True)
    parser.add_argument("--rlimit-as", type=int, required=True)
    parser.add_argument("--rlimit-cpu", type=int, required=True)
    parser.add_argument("--rlimit-fsize", type=int, required=True)
    ns = parser.parse_args(argv)
    return ChildArgs(
        input=ns.input,
        out=ns.out,
        expected_sha256=ns.expected_sha256,
        max_input_bytes=ns.max_input_bytes,
        address_space_bytes=ns.rlimit_as,
        cpu_seconds=ns.rlimit_cpu,
        file_size_bytes=ns.rlimit_fsize,
    )


class LimitsNotApplied(Exception):
    """A limit that must hold on this platform could not be set."""


def _lower_limit(which: int, value: int, hard_extra: int = 0) -> int:
    """Lower one rlimit to `value` (soft) and `value + hard_extra` (hard).

    A process may always lower its own limits. If the current hard limit is
    already lower than requested, that lower value is kept.
    """
    _, hard_now = resource.getrlimit(which)
    soft = value
    hard = value + hard_extra
    if hard_now != resource.RLIM_INFINITY:
        soft = min(soft, hard_now)
        hard = min(hard, hard_now)
    resource.setrlimit(which, (soft, hard))
    return soft


def apply_resource_limits(args: ChildArgs) -> dict[str, int | None]:
    """Apply RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE and RLIMIT_CORE to this process.

    Returns the value applied for each, or None where the platform refused it.
    On Linux every limit is required; failure raises LimitsNotApplied. On macOS,
    setrlimit(RLIMIT_AS) below the address space a process already reserves
    fails with ValueError, so the memory limit is recorded as not applied
    (a documented limitation: run Bytasm in Linux for enforced limits).
    """
    applied: dict[str, int | None] = {}
    # The soft CPU limit sends SIGXCPU; the hard limit one second later SIGKILL.
    wanted = (
        ("address_space_bytes", resource.RLIMIT_AS, args.address_space_bytes, 0),
        ("cpu_seconds", resource.RLIMIT_CPU, args.cpu_seconds, 1),
        ("file_size_bytes", resource.RLIMIT_FSIZE, args.file_size_bytes, 0),
        ("core_bytes", resource.RLIMIT_CORE, 0, 0),
    )
    for name, which, value, hard_extra in wanted:
        try:
            applied[name] = _lower_limit(which, value, hard_extra)
        except (ValueError, OSError) as exc:
            if sys.platform == "linux":
                raise LimitsNotApplied(name) from exc
            applied[name] = None
    return applied


def read_admitted_input(args: ChildArgs) -> bytes:
    """Read the input file and confirm it is exactly the bytes the parent admitted.

    The parent hashed and admitted these bytes before starting this process.
    Re-hashing here means the parser only ever sees those bytes: if the file
    changed in between, the child refuses to parse it.
    """
    return read_verified_file(args.input, args.max_input_bytes, args.expected_sha256)


def read_verified_file(path: str, max_bytes: int, expected_sha256: str) -> bytes:
    """Read a regular file (no symlink) of at most `max_bytes` with this SHA-256."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("input is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ValueError("input is larger than the admitted size limit")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("input does not match the admitted SHA-256")
    return data


def write_result(path: str, payload: bytes) -> None:
    """Create the result file; refuse to overwrite or follow anything existing."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
