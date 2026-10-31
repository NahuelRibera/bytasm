"""Protocol, real process supervision and fail-closed provider boundaries."""

import asyncio
import json
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from bytasm import ghidra_provider as provider
from bytasm.ghidra import GhidraConfiguration, GhidraDiagnostic
from bytasm.ghidra_protocol import GhidraResult


def document() -> dict[str, Any]:
    return {
        "schema_version": "ghidra-2",
        "input_sha256": "a" * 64,
        "ghidra_version": "12.2",
        "language_id": "x86:LE:64:default",
        "compiler": "gcc",
        "profile_sha256": provider.profile_digest(),
        "script_sha256": provider.script_digest(),
        "function_count": 1,
        "functions_truncated": False,
        "analysis_timed_out": False,
        "limitations": [],
        "functions": [
            {
                "entry": {"space": "ram", "address": "00100000"},
                "name": "<script>alert(1)</script>",
                "namespace": "Global",
                "body_size": 4,
                "pseudocode": "<img src=x>\nreturn 0;",
                "pseudocode_status": "available",
                "pseudocode_truncated": False,
                "instructions": [
                    {
                        "address": {"space": "ram", "address": "00100000"},
                        "bytes_hex": "c3",
                        "text": "RET",
                    }
                ],
                "instructions_truncated": False,
                "calls": [],
                "calls_truncated": False,
            }
        ],
    }


def test_strict_protocol_keeps_exact_address_space_and_hostile_text() -> None:
    result = GhidraResult.model_validate(document())
    assert result.functions[0].entry.address == "00100000"
    assert result.functions[0].entry.space == "ram"
    assert result.functions[0].name.startswith("<script>")
    assert "file_offset" not in result.model_dump_json()
    assert provider._parse(result.model_dump_json().encode(), "a" * 64) == result


@pytest.mark.parametrize(
    "damage", ["count", "duplicate", "code", "address", "instruction", "extra"]
)
def test_protocol_rejects_inconsistent_or_oversized_results(damage: str) -> None:
    value = document()
    if damage == "count":
        value["function_count"] = 0
    elif damage == "duplicate":
        value["functions"] *= 2
        value["function_count"] = 2
    elif damage == "code":
        value["functions"][0]["pseudocode"] = "a" * 4097
    elif damage == "address":
        value["functions"][0]["entry"]["space"] = ""
    elif damage == "instruction":
        value["functions"][0]["instructions"][0]["bytes_hex"] = "xyz"
    else:
        value["invented_offset"] = 123
    with pytest.raises(ValidationError):
        GhidraResult.model_validate(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("input_sha256", "b" * 64),
        ("profile_sha256", "b" * 64),
        ("script_sha256", "b" * 64),
        ("analysis_timed_out", True),
        ("language_id", "MIPS:BE:32:default"),
    ],
)
def test_provenance_timeout_and_unsupported_language_refused(field: str, value: Any) -> None:
    payload = document()
    payload[field] = value
    assert provider._parse(json.dumps(payload).encode(), "a" * 64) is None


def ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provider,
        "diagnose",
        lambda _: GhidraDiagnostic(
            status="execution_unavailable",
            message="Metadata only",
            declared_ghidra_version="12.2",
            declared_java_major=25,
        ),
    )


def test_no_configuration_never_starts_tool(tmp_path: Path) -> None:
    result = asyncio.run(provider.provider_health(GhidraConfiguration(), tmp_path))
    assert result["status"] == "not_configured"
    assert not list(tmp_path.iterdir())


def test_boundary_failure_precedes_any_sample_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(provider, "isolation_status", lambda: "isolation_unavailable")
    outcome = asyncio.run(
        provider.analyze(GhidraConfiguration(), tmp_path, "a" * 64, lambda: False)
    )
    assert outcome.reason == "isolation_unavailable" and not list(tmp_path.iterdir())


def test_actual_health_child_output_checked_and_private_workspace_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(
        provider,
        "_command",
        lambda *_: [
            sys.executable,
            "-I",
            "-c",
            'import pathlib; pathlib.Path("result.json").write_text('
            '\'{"healthy":true,"version":"12.2"}\')',
        ],
    )
    monkeypatch.setattr(provider, "isolation_status", lambda: "isolation_unavailable")
    result = asyncio.run(provider.provider_health(GhidraConfiguration(), tmp_path))
    assert result["available"] and result["health_check"] == "passed"
    assert not result["analysis_enabled"] and not list(tmp_path.iterdir())


def test_health_child_without_protocol_is_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(provider, "_command", lambda *_: [sys.executable, "-I", "-c", "pass"])
    result = asyncio.run(provider.provider_health(GhidraConfiguration(), tmp_path))
    assert not result["available"] and result["health_check"] == "failed"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "behavior,expected",
    [
        ("import time; time.sleep(3)", "timed_out"),
        ("raise SystemExit(4)", "failed"),
        ("import sys; sys.stdout.write('x' * 100000)", "failed"),
    ],
)
def test_actual_child_timeout_crash_flood(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
    expected: str,
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(provider, "isolation_status", lambda: None)
    monkeypatch.setattr(provider, "_temporary_filesystem_bounded", lambda _: True)
    monkeypatch.setattr(provider, "_command", lambda *_: [sys.executable, "-I", "-c", behavior])
    monkeypatch.setattr(provider, "LIMITS", replace(provider.LIMITS, timeout_seconds=0.2))
    outcome = asyncio.run(
        provider.analyze(GhidraConfiguration(), tmp_path, "a" * 64, lambda: False)
    )
    assert outcome.status == expected and outcome.result is None
    assert len(outcome.stdout) <= 65536


def test_prelaunch_cancel_does_not_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(provider, "isolation_status", lambda: None)
    monkeypatch.setattr(provider, "_temporary_filesystem_bounded", lambda _: True)
    result = asyncio.run(provider.analyze(GhidraConfiguration(), tmp_path, "a" * 64, lambda: True))
    assert result.status == "cancelled" and not list(tmp_path.iterdir())


def test_live_cancel_terminates_actual_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(provider, "isolation_status", lambda: None)
    monkeypatch.setattr(provider, "_temporary_filesystem_bounded", lambda _: True)
    monkeypatch.setattr(
        provider,
        "_command",
        lambda *_: [
            sys.executable,
            "-I",
            "-c",
            "import time; time.sleep(10)",
        ],
    )
    polls = 0

    def cancel() -> bool:
        nonlocal polls
        polls += 1
        return polls > 1

    outcome = asyncio.run(provider.analyze(GhidraConfiguration(), tmp_path, "a" * 64, cancel))
    assert outcome.status == "cancelled" and outcome.duration_ms < 2000


def test_health_cleanup_retries_transient_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(provider, "_command", lambda *_: [sys.executable, "-I", "-c", "pass"])
    remove = shutil.rmtree
    attempts = 0

    def retry(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("transient")
        remove(path)

    monkeypatch.setattr(shutil, "rmtree", retry)
    result = asyncio.run(provider.provider_health(GhidraConfiguration(), tmp_path))
    assert result["health_check"] == "failed" and attempts == 2
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("offline", None),
        ("dormant", None),
        ("up", "isolation_unavailable"),
        ("route", "isolation_unavailable"),
        ("ipv6", "isolation_unavailable"),
        ("caps", "isolation_unavailable"),
        ("CapPrm", "isolation_unavailable"),
        ("CapInh", "isolation_unavailable"),
        ("CapAmb", "isolation_unavailable"),
        ("CapBnd", "isolation_unavailable"),
        ("privs", "isolation_unavailable"),
        ("memory", "resource_constraint"),
        ("pids", "resource_constraint"),
        ("cpu", "resource_constraint"),
    ],
)
def test_isolation_requires_no_egress_privilege_and_bounded_resources(
    monkeypatch: pytest.MonkeyPatch,
    condition: str,
    expected: str | None,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 10001)
    files = {
        "/proc/net/dev": "header\nheader\nlo: 0\n",
        "/sys/class/net/lo/flags": "0x9",
        "/proc/net/route": "header\n",
        "/proc/net/ipv6_route": "",
        "/proc/self/status": (
            "CapEff: 0\nCapPrm: 0\nCapInh: 0\nCapAmb: 0\nCapBnd: 0\nNoNewPrivs: 1\n"
        ),
        "/sys/fs/cgroup/memory.max": str(2 * 1024 * 1024 * 1024),
        "/sys/fs/cgroup/pids.max": "128",
        "/sys/fs/cgroup/cpu.max": "200000 100000",
    }
    if condition in {"dormant", "up"}:
        files["/proc/net/dev"] += "tunl0: 0\n"
        files["/sys/class/net/tunl0/flags"] = "0x80" if condition == "dormant" else "0x81"
    if condition == "route":
        files["/proc/net/route"] += "eth0 00000000\n"
    if condition == "ipv6":
        files["/proc/net/ipv6_route"] = "0 0 eth0\n"
    if condition == "caps":
        files["/proc/self/status"] = files["/proc/self/status"].replace("CapEff: 0", "CapEff: 1")
    if condition in {"CapPrm", "CapInh", "CapAmb", "CapBnd"}:
        files["/proc/self/status"] = files["/proc/self/status"].replace(
            f"{condition}: 0", f"{condition}: 1"
        )
    if condition == "privs":
        files["/proc/self/status"] = "CapEff: 0\nNoNewPrivs: 0\n"
    if condition == "memory":
        files["/sys/fs/cgroup/memory.max"] = "max"
    if condition == "pids":
        files["/sys/fs/cgroup/pids.max"] = "max"
    if condition == "cpu":
        files["/sys/fs/cgroup/cpu.max"] = "max 100000"
    monkeypatch.setattr(Path, "read_text", lambda path, **kwargs: files[str(path)])
    assert provider.isolation_status() == expected


@pytest.mark.parametrize("mode", ["analyze", "health"])
def test_bridge_only_executes_fixed_tool_and_imports_sample_as_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    ready(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["bridge", "--bridge", mode, "/tools/ghidra", "/tools/jdk", "a" * 64]
    )
    monkeypatch.setattr(provider, "isolation_status", lambda: None)
    monkeypatch.setattr(provider, "_temporary_filesystem_bounded", lambda _: True)
    fixture = Path(__file__).resolve().parents[3] / "fixtures/bin/hello_v1-x86_64.elf"
    monkeypatch.setattr(provider, "read_verified_file", lambda *_: fixture.read_bytes())
    import resource

    monkeypatch.setattr(resource, "setrlimit", lambda *_: None)
    recorded: list[str] = []

    def capture(executable: str, argv: list[str], env: dict[str, str]) -> None:
        assert executable == "/tools/ghidra/support/analyzeHeadless"
        assert env["GHIDRA_HEADLESS_MAXMEM"] == "768M"
        assert "PYTHONPATH" not in env
        recorded.extend(argv)
        raise RuntimeError("intercept exec")

    monkeypatch.setattr(os, "execve", capture)
    with pytest.raises(RuntimeError, match="intercept exec"):
        provider._bridge()
    assert recorded[0] != str(tmp_path / "upload.bin")
    if mode == "analyze":
        assert recorded[recorded.index("-import") + 1] == str(tmp_path / "upload.bin")
        assert "BytasmExtract.java" in recorded
    else:
        assert "-import" not in recorded and "BytasmHealth.java" in recorded
