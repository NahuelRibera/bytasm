"""Start, supervise, and clean up one adapter child process (blueprint 5.4.1, steps 7-9, 11).

Lifecycle of `run_adapter`:

1. Start the child with an argv list (no shell), `stdin` = /dev/null, its own
   session and process group (`start_new_session=True`), the default
   `close_fds=True`, `cwd` = the caller's private work directory, and an
   explicit minimal environment with no secrets. `preexec_fn` is never used:
   the child lowers its own limits as its first action.
2. Drain stdout and stderr concurrently through bounded readers, so a chatty
   child can neither deadlock on a full pipe nor make the parent buffer
   unbounded output. Only the first `captured_stream_bytes` are kept.
3. Wait for the child with a wall-clock deadline. Reaching a deadline does not
   stop a child by itself, so on timeout the whole process group gets SIGTERM,
   then SIGKILL after a grace period.
4. After the child exits, any process still in its group is killed and the run
   counts as failed. If the output pipes do not close shortly after (a process
   that left the group still holds them), the run also counts as failed.
5. `finally`, on every path including errors and task cancellation: SIGKILL
   the process group and stop the pipe readers. asyncio reaps the child.

Classification never uses partial output: only exit code 0 with a present,
size-capped, schema-valid result file is a success. Exit code 2 with exactly
one known reason code is a rejection. Everything else is a failure.

Known limitation (Q4): a descendant that calls setsid()/setpgid() leaves the
process group, so the group kill cannot reach it. If it keeps an output pipe
open, the run is classified as failed (`output_not_closed`); if it closes its
pipes, it is not detected. RLIMIT_CPU bounds a busy loop in it; nothing here
bounds a sleeping one.
"""

import asyncio
import contextlib
import os
import signal
import stat
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import ValidationError

from bytasm.adapters.result import AdapterResult
from bytasm.runner.limits import DEFAULT_LIMITS, MAX_INPUT_BYTES, ParserLimits

INPUT_NAME: Final = "upload.bin"
RESULT_NAME: Final = "result.json"

# The only reason codes an adapter may report with exit code 2. They are
# mapped to Bytasm's own messages; adapter text is never shown to users.
REJECTION_CODES: Final = frozenset(
    {"empty_file", "file_too_large", "unsupported_format", "malformed_input", "parse_failed"}
)

# The child's complete environment. `-I` (isolated mode) already makes Python
# ignore PYTHON* variables, the user site directory, and the current directory.
CHILD_ENV: Final = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

Status = Literal["succeeded", "rejected", "failed", "timed_out"]


@dataclass(frozen=True)
class AdapterOutcome:
    """What happened to one adapter run.

    `reason` is a fixed code: for "rejected" the adapter's reason code; for
    "failed" one of nonzero_exit, killed_by_signal, invalid_output,
    output_overflow, orphan_processes, output_not_closed; "timeout" for
    "timed_out"; "ok" for "succeeded". `stdout`/`stderr` are capped excerpts
    with control characters removed, for tests and debugging only. They must
    never be shown to users or logged.
    """

    status: Status
    reason: str
    exit_code: int | None
    duration_ms: int
    result: AdapterResult | None = None
    result_bytes: bytes | None = None
    stdout: str = ""
    stderr: str = ""


def adapter_command(module: str) -> list[str]:
    """argv prefix for a Bytasm adapter module, run in isolated mode."""
    return [sys.executable, "-I", "-m", module]


def metadata_adapter_command() -> list[str]:
    return adapter_command("bytasm.adapters.metadata_lief")


def sanitize(data: bytes) -> str:
    """Decode leniently and drop control characters (keeps newlines and tabs)."""
    text = data.decode("utf-8", errors="replace")
    return "".join(ch for ch in text if ch in "\n\t" or (ord(ch) >= 0x20 and ord(ch) != 0x7F))


async def _drain(stream: asyncio.StreamReader | None, cap: int) -> tuple[bytes, bool]:
    """Read a pipe to EOF, keeping at most `cap` bytes. Returns (kept, overflowed)."""
    if stream is None:
        return b"", False
    kept = bytearray()
    overflowed = False
    while chunk := await stream.read(64 * 1024):
        room = cap - len(kept)
        if room > 0:
            kept += chunk[:room]
        if len(chunk) > max(room, 0):
            overflowed = True
    return bytes(kept), overflowed


def _signal_group(pgid: int, sig: signal.Signals) -> bool:
    """Send `sig` to the process group. False if the group no longer exists."""
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return False
    except PermissionError:
        # macOS reports EPERM for a group that only has zombies left.
        return False
    return True


async def _wait_exit(process: asyncio.subprocess.Process, timeout: float) -> None:
    """Wait until the child itself has exited, or raise TimeoutError.

    `Process.wait()` is not used: on some Python versions (observed on 3.12)
    it also waits for the stdout/stderr pipes to close, so a descendant that
    holds a pipe would make the child look hung. `returncode` is set as soon
    as asyncio has reaped the child.
    """
    deadline = time.monotonic() + timeout
    while process.returncode is None:
        if time.monotonic() >= deadline:
            raise TimeoutError
        await asyncio.sleep(0.01)


async def _wait_quietly(process: asyncio.subprocess.Process, timeout: float) -> None:
    with contextlib.suppress(TimeoutError):
        await _wait_exit(process, timeout)


def _close_transport(process: asyncio.subprocess.Process) -> None:
    """Close the child's pipes even if a descendant still holds them open.

    asyncio has no public API for this; without it the pipes would only be
    closed when the transport is garbage-collected, possibly after the event
    loop has closed.
    """
    transport = getattr(process, "_transport", None)
    if transport is not None:
        with contextlib.suppress(Exception):
            transport.close()


def _read_result(workdir: Path, cap: int) -> bytes | None:
    """Read result.json if it is a regular file (not a link) of at most `cap` bytes."""
    path = workdir / RESULT_NAME
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
        return None
    # O_NONBLOCK: if the path was swapped for a FIFO after lstat (only a
    # process that escaped the group kill could), opening must not block the
    # event loop. The fstat re-check then refuses anything but that regular file.
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            info.st_dev,
            info.st_ino,
        ):
            return None
        data = handle.read(cap + 1)
    return data if len(data) <= cap else None


def _classify_exit(
    exit_code: int,
    stdout: bytes,
    workdir: Path,
    expected_sha256: str,
    limits: ParserLimits,
) -> tuple[Status, str, AdapterResult | None, bytes | None]:
    if exit_code < 0:
        return "failed", "killed_by_signal", None, None
    if exit_code == 2:
        code = stdout.decode("ascii", errors="replace").strip()
        if code in REJECTION_CODES and stdout in (code.encode(), code.encode() + b"\n"):
            return "rejected", code, None, None
        return "failed", "invalid_output", None, None
    if exit_code != 0:
        return "failed", "nonzero_exit", None, None

    raw = _read_result(workdir, limits.result_bytes)
    if raw is None:
        return "failed", "invalid_output", None, None
    try:
        result = AdapterResult.model_validate_json(raw)
    except ValidationError:
        return "failed", "invalid_output", None, None
    if result.input.sha256 != expected_sha256:
        return "failed", "invalid_output", None, None
    return "succeeded", "ok", result, raw


async def run_adapter(
    command: Sequence[str],
    workdir: Path,
    expected_sha256: str,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> AdapterOutcome:
    """Run one adapter on `workdir/upload.bin` and classify the outcome.

    The caller owns `workdir` (a private directory) and deletes it afterwards.
    """
    argv = [
        *command,
        "--input",
        INPUT_NAME,
        "--out",
        RESULT_NAME,
        "--expected-sha256",
        expected_sha256,
        "--max-input-bytes",
        str(MAX_INPUT_BYTES),
        "--rlimit-as",
        str(limits.address_space_bytes),
        "--rlimit-cpu",
        str(limits.cpu_seconds),
        "--rlimit-fsize",
        str(limits.file_size_bytes),
    ]
    started = time.monotonic()
    process = await asyncio.create_subprocess_exec(
        *argv,
        cwd=workdir,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=dict(CHILD_ENV),
        start_new_session=True,
    )
    pgid = process.pid  # the child leads its own new process group
    cap = limits.captured_stream_bytes
    out_task = asyncio.create_task(_drain(process.stdout, cap))
    err_task = asyncio.create_task(_drain(process.stderr, cap))

    timed_out = False
    orphans = False
    pipes_closed = True
    try:
        try:
            await _wait_exit(process, limits.timeout_seconds)
        except TimeoutError:
            timed_out = True
            _signal_group(pgid, signal.SIGTERM)
            await _wait_quietly(process, limits.kill_grace_seconds)
            _signal_group(pgid, signal.SIGKILL)
            await _wait_quietly(process, limits.kill_grace_seconds)
        else:
            # The leader has exited and been reaped; anything left in its
            # group was started by it and outlived it.
            orphans = _signal_group(pgid, signal.SIGKILL)

        done, _ = await asyncio.wait({out_task, err_task}, timeout=limits.pipe_close_seconds)
        pipes_closed = len(done) == 2
    finally:
        _signal_group(pgid, signal.SIGKILL)
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        for task in (out_task, err_task):
            task.cancel()
        # Let the cancelled readers finish, then release the pipes.
        await asyncio.gather(out_task, err_task, return_exceptions=True)
        _close_transport(process)

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, out_overflow = out_task.result() if not out_task.cancelled() else (b"", False)
    stderr, err_overflow = err_task.result() if not err_task.cancelled() else (b"", False)
    exit_code = process.returncode

    def outcome(
        status: Status,
        reason: str,
        result: AdapterResult | None = None,
        raw: bytes | None = None,
    ) -> AdapterOutcome:
        return AdapterOutcome(
            status=status,
            reason=reason,
            exit_code=exit_code,
            duration_ms=duration_ms,
            result=result,
            result_bytes=raw,
            stdout=sanitize(stdout),
            stderr=sanitize(stderr),
        )

    if timed_out:
        return outcome("timed_out", "timeout")
    if orphans:
        return outcome("failed", "orphan_processes")
    if not pipes_closed:
        return outcome("failed", "output_not_closed")
    if out_overflow or err_overflow:
        return outcome("failed", "output_overflow")
    if exit_code is None:  # not reachable: the child was awaited or killed above
        return outcome("failed", "nonzero_exit")
    return outcome(*_classify_exit(exit_code, stdout, workdir, expected_sha256, limits))
