"""Ghidra worker stage: admission-verified data and immutable typed output."""

import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from bytasm.ghidra_protocol import Address
from bytasm.ghidra_provider import analyze, profile_snapshot
from bytasm.jobs.steps import ScanDeps, StepInput, StepOutcome


def supported(data: bytes) -> bool:
    """Reviewed native PE x86/x64 and little-endian ELF x86/x64/AArch64 only."""
    if len(data) >= 52 and data[:4] == b"\x7fELF":
        machine = int.from_bytes(data[18:20], "little")
        return data[5] == 1 and (data[4], machine) in ((1, 3), (2, 62), (2, 183))
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    offset = int.from_bytes(data[60:64], "little")
    if offset + 26 > len(data) or data[offset : offset + 4] != b"PE\x00\x00":
        return False
    machine = int.from_bytes(data[offset + 4 : offset + 6], "little")
    magic = int.from_bytes(data[offset + 24 : offset + 26], "little")
    if (machine, magic) not in ((0x14C, 0x10B), (0x8664, 0x20B)):
        return False
    optional_size = int.from_bytes(data[offset + 20 : offset + 22], "little")
    directory = offset + 24 + (96 if magic == 0x10B else 112)
    if offset + 24 + optional_size > len(data) or directory > offset + 24 + optional_size:
        return False
    count = int.from_bytes(data[directory - 4 : directory], "little")
    if count > 14:
        if directory + 15 * 8 > offset + 24 + optional_size:
            return False
        if any(data[directory + 14 * 8 : directory + 15 * 8]):
            return False
    return True


async def run_ghidra_step(deps: ScanDeps, step: StepInput) -> StepOutcome:
    selection = step.step.get("options", {}).get("selected_entries")
    try:
        selected = [Address.model_validate(a) for a in selection] if selection is not None else None
        current = profile_snapshot(selected)
    except (ValueError, TypeError):
        return StepOutcome(
            "failed",
            "profile_integrity",
            {
                "tool_name": "ghidra",
                "tool_version": "12.2",
                "adapter_name": "ghidra_headless",
                "adapter_version": "1",
                "args": {},
                "exit_code": None,
                "duration_ms": 0,
                "warnings": [],
                "rule_set_id": None,
            },
        )
    expected = current["steps"][0]
    fields: dict[str, Any] = {
        "tool_name": "ghidra",
        "tool_version": "12.2",
        "adapter_name": "ghidra_headless",
        "adapter_version": "1",
        "rule_set_id": None,
        "args": {
            **step.step,
            "provider_host": {"os": sys.platform, "architecture": platform.machine()},
        },
        "exit_code": None,
        "duration_ms": 0,
        "warnings": [
            "Static call relationships do not establish execution. "
            "Decompiler output is pseudocode, not original source code."
        ],
    }
    # A queued run cannot silently change scripts/options after an application update.
    if step.step != expected:
        return StepOutcome("failed", "profile_integrity", fields)
    if not supported(step.data):
        return StepOutcome("unsupported", "unsupported_format", fields)
    if selected is None:
        outcome = await analyze(deps.ghidra, step.workdir, step.sample_sha256, step.should_stop)
    else:
        outcome = await analyze(
            deps.ghidra, step.workdir, step.sample_sha256, step.should_stop, selected
        )
    fields.update(exit_code=outcome.exit_code, duration_ms=outcome.duration_ms)
    if outcome.status != "succeeded" or outcome.result is None:
        status: str = outcome.status if outcome.status in ("cancelled", "timed_out") else "failed"
        if outcome.reason in {
            "not_configured",
            "installation_invalid",
            "unsupported_version",
            "java_missing",
            "java_incompatible",
            "unsupported_host",
            "isolation_unavailable",
            "resource_constraint",
        }:
            status = "unavailable"
        return StepOutcome(status, outcome.reason, fields)
    result = outcome.result
    if (
        result.input_sha256 != step.sample_sha256
        or result.profile_sha256 != expected["profile_sha256"]
        or result.script_sha256 != expected["script_sha256"]
    ):
        return StepOutcome("failed", "invalid_output", fields)
    fields["summary"] = {
        "function_count": result.function_count,
        "stored_functions": len(result.functions),
        "functions_truncated": result.functions_truncated,
        "analysis_timed_out": result.analysis_timed_out,
    }
    return StepOutcome(
        "succeeded", None, fields, raw_output=result.model_dump_json().encode("utf-8")
    )


def cleanup_workdir(path: Path) -> bool:
    """Retry private project cleanup; report a fixed pending state on failure."""
    for _ in range(3):
        try:
            shutil.rmtree(path)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            continue
    return False
