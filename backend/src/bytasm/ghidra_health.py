"""Bounded provider status, separating API configuration from the offline worker.

The local worker shares application ownership and writes only no-sample health
metadata. Its heartbeat expires this status; each analysis rechecks controls.
"""

import asyncio
import os
import stat
import time
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from bytasm.ghidra import GhidraConfiguration, GhidraDiagnostic, diagnose

if TYPE_CHECKING:
    from bytasm.config import Settings

_CACHE: dict[GhidraConfiguration, tuple[float, GhidraDiagnostic]] = {}


_IN_FLIGHT: dict[tuple[GhidraConfiguration, int], asyncio.Task[GhidraDiagnostic]] = {}


async def _probe(config: GhidraConfiguration, tmp_dir: Path) -> GhidraDiagnostic:
    from bytasm.ghidra_provider import provider_health

    result = GhidraDiagnostic.model_validate(await provider_health(config, tmp_dir))
    if len(_CACHE) >= 32:
        _CACHE.clear()
    _CACHE[config] = (time.monotonic() + (60 if result.available else 10), result)
    return result


async def verified_diagnostic(config: GhidraConfiguration, tmp_dir: Path) -> GhidraDiagnostic:
    metadata = diagnose(config)
    if metadata.status != "execution_unavailable":
        return metadata
    cached = _CACHE.get(config)
    if cached and time.monotonic() < cached[0]:
        return cached[1].model_copy()
    # Concurrent Tools requests share one bounded no-sample process. Request
    # cancellation does not cancel another caller's shared check.
    key = (config, id(asyncio.get_running_loop()))
    pending = _IN_FLIGHT.get(key)
    if pending is None:
        pending = asyncio.create_task(_probe(config, tmp_dir))
        _IN_FLIGHT[key] = pending
        pending.add_done_callback(lambda _: _IN_FLIGHT.pop(key, None))
    return (await asyncio.shield(pending)).model_copy()


def _read_status(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise ValueError("Invalid worker status")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(4097)
    finally:
        os.close(fd)


async def effective_diagnostic(settings: "Settings") -> GhidraDiagnostic:
    """Prefer a live worker's actual status over the online API's installation."""
    try:
        heartbeat = (settings.data_dir / "worker.heartbeat").lstat()
        age = time.time() - heartbeat.st_mtime
        if stat.S_ISREG(heartbeat.st_mode) and -5 <= age < 30:
            raw = _read_status(settings.data_dir / "ghidra-health.json")
            return GhidraDiagnostic.model_validate_json(raw)
    except (OSError, ValueError, ValidationError):
        pass
    diagnostic = await verified_diagnostic(settings.ghidra, settings.tmp_dir)
    if diagnostic.analysis_enabled:
        return diagnostic.model_copy(
            update={
                "analysis_enabled": False,
                "status": "isolation_unavailable",
                "message": (
                    "The provider passed its self-check. "
                    "Start a configured offline worker to enable analysis."
                ),
            }
        )
    return diagnostic
