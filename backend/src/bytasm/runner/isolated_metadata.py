"""Trusted Docker broker: no mounts, socket, credentials or writable app state in worker.

Opt-in architectural step, not I1 approval. Same Linux kernel as Docker's VM;
Docker daemon and trusted image are part of the TCB. No native fallback.
"""

import asyncio
import contextlib
import hashlib
import re
import shutil
import time
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

from bytasm.adapters.result import AdapterResult
from bytasm.intake.policy import InputPolicy
from bytasm.runner.limits import MAX_INPUT_BYTES
from bytasm.runner.supervisor import AdapterOutcome, _drain

MAX_OUTPUT = 4 * 1024 * 1024


@dataclass(frozen=True)
class IsolationConfig:
    image: str
    timeout_seconds: float = 30

    def __post_init__(self) -> None:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.image) is None:
            raise ValueError("Isolated metadata requires an immutable local Docker image ID")
        if not 0 < self.timeout_seconds <= 30:
            raise ValueError("Invalid metadata deadline")


def container_argv(config: IsolationConfig, sha: str, name: str) -> list[str]:
    return [
        "create",
        "--pull=never",
        "--name",
        name,
        "--interactive",
        "--network=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=32",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--ulimit=nofile=128:128",
        "--ulimit=core=0:0",
        "--log-driver=none",
        "--tmpfs=/work:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700",
        "--workdir=/work",
        "--env=HOME=/work",
        "--env=TMPDIR=/work",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint=/app/.venv/bin/python",
        config.image,
        "-I",
        "-m",
        "bytasm.runner.isolated_metadata_child",
        sha,
    ]


async def _control(docker: str, *args: str) -> tuple[int, bytes]:
    process = await asyncio.create_subprocess_exec(
        docker,
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with asyncio.timeout(10):
            output, overflow = await _drain(process.stdout, 4096)
            code = await process.wait()
        if overflow:
            return 1, b""
        return code, output
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


def validate_metadata(raw: bytes, data: bytes, sha: str) -> AdapterResult:
    result = AdapterResult.model_validate_json(raw)
    if result.input.sha256 != sha or result.input.size_bytes != len(data):
        raise ValueError("Worker input identity mismatch")
    # Independent measurement of every range the parser claimed it measured.
    from bytasm.adapters.entropy import shannon_entropy

    measured_bytes = 0
    for section in result.metadata.sections:
        start, size = section.file_offset, section.file_size
        valid = size > 0 and start + size <= len(data)
        if valid:
            measured_bytes += size
            if measured_bytes > 128 * 1024 * 1024:
                raise ValueError("Independent measurement budget exceeded")
            if section.entropy != shannon_entropy(data[start : start + size]):
                raise ValueError("Worker byte-range measurement mismatch")
            if section.entropy_note is not None:
                raise ValueError("Contradictory range state")
        elif section.entropy is not None:
            raise ValueError("Worker measured an invalid range")
    return result


async def parse_isolated(
    data: bytes,
    policy: InputPolicy,
    config: IsolationConfig,
) -> AdapterOutcome[AdapterResult]:
    start = time.monotonic()
    sha = hashlib.sha256(data).hexdigest()

    def outcome(
        status: Literal["succeeded", "rejected", "failed", "timed_out"],
        reason: str,
        result: AdapterResult | None = None,
        raw: bytes | None = None,
    ) -> AdapterOutcome[AdapterResult]:
        return AdapterOutcome(
            status=status,
            reason=reason,
            exit_code=0 if result else None,
            duration_ms=int((time.monotonic() - start) * 1000),
            result=result,
            result_bytes=raw,
        )

    if len(data) > MAX_INPUT_BYTES or policy.admit(sha) is None:
        return outcome("rejected", "input_policy")
    docker = shutil.which("docker")
    if docker is None:
        return outcome("failed", "isolation_unavailable")
    name = "bytasm-metadata-" + uuid4().hex
    process: asyncio.subprocess.Process | None = None
    tasks: list[asyncio.Task[tuple[bytes, bool]]] = []
    cleanup_ok = False
    result_outcome = outcome("failed", "isolation_unavailable")
    try:
        async with asyncio.timeout(config.timeout_seconds):
            code, _ = await _control(docker, *container_argv(config, sha, name))
            if code != 0:
                return result_outcome
            process = await asyncio.create_subprocess_exec(
                docker,
                "start",
                "--attach",
                "--interactive",
                name,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            tasks = [
                asyncio.create_task(_drain(process.stdout, MAX_OUTPUT)),
                asyncio.create_task(_drain(process.stderr, 4096)),
            ]
            assert process.stdin is not None  # noqa: S101 - created with PIPE
            process.stdin.write(data)
            await process.stdin.drain()
            process.stdin.close()
            code = await process.wait()
            (raw, overflow), (_, stderr_overflow) = await asyncio.gather(*tasks)
            if code == 0 and not overflow and not stderr_overflow:
                parsed = validate_metadata(raw, data, sha)
                result_outcome = outcome("succeeded", "ok", parsed, raw)
            else:
                result_outcome = outcome("failed", "invalid_output")
    except TimeoutError:
        result_outcome = outcome("timed_out", "timeout")
    except (OSError, ValueError, BrokenPipeError):
        result_outcome = outcome("failed", "invalid_output")
    finally:
        # Removing a container kills its PID namespace, including setsid
        # descendants. Never publish success if cleanup cannot be confirmed.
        try:
            code, _ = await asyncio.shield(_control(docker, "rm", "--force", name))
            cleanup_ok = code == 0
        except (OSError, TimeoutError):
            cleanup_ok = False
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
    return result_outcome if cleanup_ok else outcome("failed", "cleanup_failed")
