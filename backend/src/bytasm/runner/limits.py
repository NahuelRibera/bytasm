"""Provisional v0.1 parser limits (ADR-0001 D4, blueprint 5.4.1).

M1 measurements (docs/measurements/2026-10-26-m1-parse-time-memory.md) support
these values, so none was changed.
"""

from dataclasses import dataclass
from typing import Final

KIB: Final = 1024
MIB: Final = 1024 * KIB
GIB: Final = 1024 * MIB

# Upload / input size limit, shared by the CLI and the API.
MAX_INPUT_BYTES: Final = 64 * MIB


@dataclass(frozen=True)
class ParserLimits:
    """Limits for one adapter run. Tests lower them to exercise each path."""

    # Wall-clock deadline enforced by the parent.
    timeout_seconds: float = 30.0
    # SIGTERM -> SIGKILL grace period on timeout.
    kill_grace_seconds: float = 2.0
    # Limits the child applies to itself before importing the parser.
    address_space_bytes: int = 1 * GIB  # RLIMIT_AS
    cpu_seconds: int = 25  # RLIMIT_CPU (below the wall-clock timeout)
    file_size_bytes: int = 32 * MIB  # RLIMIT_FSIZE
    # Parent-side caps on what it is willing to read back.
    result_bytes: int = 32 * MIB
    captured_stream_bytes: int = 64 * KIB  # each of stdout and stderr
    # How long the parent waits for the output pipes to close after the
    # process group is gone, before treating the run as failed.
    pipe_close_seconds: float = 2.0


DEFAULT_LIMITS: Final = ParserLimits()
