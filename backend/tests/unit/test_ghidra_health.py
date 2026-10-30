"""Only a fresh bounded worker health record can expose an analysis profile."""

import asyncio
import os
from pathlib import Path

from bytasm.config import Settings
from bytasm.ghidra import GhidraDiagnostic
from bytasm.ghidra_health import effective_diagnostic


def healthy() -> GhidraDiagnostic:
    return GhidraDiagnostic(
        available=True,
        analysis_enabled=True,
        status="available",
        message="Self-check passed.",
        declared_ghidra_version="12.2",
        declared_java_major=25,
        verification="headless_self_check",
        health_check="passed",
    )


def test_only_fresh_regular_worker_status_enables_analysis(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    status = tmp_path / "ghidra-health.json"
    heartbeat = tmp_path / "worker.heartbeat"
    status.write_text(healthy().model_dump_json())
    assert not asyncio.run(effective_diagnostic(settings)).available
    heartbeat.touch()
    assert asyncio.run(effective_diagnostic(settings)).analysis_enabled
    os.utime(heartbeat, (1, 1))
    assert not asyncio.run(effective_diagnostic(settings)).available


def test_hostile_worker_status_is_refused_without_leaking_text(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    (tmp_path / "worker.heartbeat").touch()
    path = tmp_path / "ghidra-health.json"
    for raw in (b"PRIVATE" * 1000, b"not-json", b'{"available":true}'):
        path.write_bytes(raw)
        result = asyncio.run(effective_diagnostic(settings))
        assert not result.available and "PRIVATE" not in result.model_dump_json()
    other = tmp_path / "other"
    other.write_text(healthy().model_dump_json())
    path.unlink()
    path.symlink_to(other)
    assert not asyncio.run(effective_diagnostic(settings)).available


def test_concurrent_tools_requests_share_a_real_health_attempt(
    tmp_path: Path, monkeypatch: object
) -> None:
    from typing import cast

    import pytest

    from bytasm import ghidra_health, ghidra_provider
    from bytasm.ghidra import GhidraConfiguration

    patch = cast(pytest.MonkeyPatch, monkeypatch)
    config = GhidraConfiguration("/trusted-concurrency-test", "/trusted-test-jdk")
    patch.setattr(
        ghidra_health,
        "diagnose",
        lambda _: GhidraDiagnostic(status="execution_unavailable", message="Metadata only."),
    )
    calls = []

    async def check(*args: object) -> dict[str, object]:
        calls.append(args)
        await asyncio.sleep(0.02)
        return healthy().model_dump()

    patch.setattr(ghidra_provider, "provider_health", check)

    async def requests() -> None:
        results = await asyncio.gather(
            *(ghidra_health.verified_diagnostic(config, tmp_path) for _ in range(8))
        )
        assert all(result.available for result in results)
        assert len(calls) == 1
        assert not ghidra_health._IN_FLIGHT

    try:
        asyncio.run(requests())
    finally:
        ghidra_health._CACHE.pop(config, None)
