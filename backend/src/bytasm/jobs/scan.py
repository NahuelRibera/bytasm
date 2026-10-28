"""The YARA-X step of an analysis run, as executed by the worker.

The pipeline (bytasm.jobs.pipeline) has just re-checked the input policy and
the stored blob's SHA-256, and written the verified bytes to the step's
private work directory. This step then:

1. Reads the run's rule-set snapshot from the outputs store and verifies its
   SHA-256 (`rules_integrity`, without starting YARA-X).
2. Writes it next to the input (file 0400) and starts the YARA-X child, which
   verifies both hashes again before compiling.
3. Validates the child's result strictly: schema, hashes, the expected rule
   identifiers, every match inside the file, and every excerpt equal to the
   file's bytes at that offset.

It returns a StepOutcome; the pipeline records it. The worker never logs
sample bytes, matched bytes, or rule text.
"""

import hashlib
import logging
import os
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from bytasm.adapters.yara_result import (
    MAX_EVIDENCE_PER_PATTERN,
    MAX_EXCERPT_BYTES,
    MAX_MATCHES_PER_PATTERN,
    YaraAdapterResult,
)
from bytasm.adapters.yara_x_scan import ADAPTER_VERSION
from bytasm.db.models import Base, Evidence, Finding
from bytasm.jobs.steps import ScanDeps, StepInput, StepOutcome
from bytasm.rules import split_snapshot
from bytasm.runner.limits import MAX_INPUT_BYTES, ParserLimits
from bytasm.runner.supervisor import INPUT_NAME, AdapterOutcome, run_child
from bytasm.storage import IntegrityError

__all__ = ["ScanDeps", "run_yara_step"]

log = logging.getLogger("bytasm.worker")

RULES_NAME: Final = "rules.yar"
# YARA-X's own scan timeout, below the parent's wall-clock deadline so a slow
# scan normally ends as a clean "timed_out" result rather than a kill.
SCAN_TIMEOUT_SECONDS: Final = 20


def yara_x_installed_version() -> str:
    """The pinned yara-x package version, read from its metadata (no import)."""
    return package_version("yara-x")


def yara_argv(
    command: list[str],
    limits: ParserLimits,
    rules_sha256: str,
    sample_sha256: str | None,
) -> list[str]:
    argv = [
        *command,
        "--mode",
        "scan" if sample_sha256 is not None else "compile",
        "--rules",
        RULES_NAME,
        "--expected-rules-sha256",
        rules_sha256,
        "--out",
        "result.json",
        "--max-input-bytes",
        str(MAX_INPUT_BYTES),
        "--scan-timeout",
        str(SCAN_TIMEOUT_SECONDS),
        "--max-matches-per-pattern",
        str(MAX_MATCHES_PER_PATTERN),
        "--rlimit-as",
        str(limits.address_space_bytes),
        "--rlimit-cpu",
        str(limits.cpu_seconds),
        "--rlimit-fsize",
        str(limits.file_size_bytes),
    ]
    if sample_sha256 is not None:
        argv += ["--input", INPUT_NAME, "--expected-sha256", sample_sha256]
    return argv


def parse_yara_result(
    raw: bytes, rules_sha256: str, sample_sha256: str | None
) -> YaraAdapterResult | None:
    """Schema-validate the child's result and check it is about these inputs."""
    try:
        result = YaraAdapterResult.model_validate_json(raw)
    except ValidationError:
        return None
    if result.rules.sha256 != rules_sha256:
        return None
    if sample_sha256 is None:
        return result if result.mode == "compile" and result.input is None else None
    if result.mode != "scan" or result.input is None or result.input.sha256 != sample_sha256:
        return None
    return result


def write_rules(workdir: Path, snapshot: bytes) -> None:
    path = workdir / RULES_NAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(snapshot)
    os.chmod(path, 0o400)


def expected_identifiers(snapshot: bytes) -> set[str]:
    return {name.removesuffix(".yar") for name in split_snapshot(snapshot)}


def evidence_is_consistent(result: YaraAdapterResult, data: bytes) -> bool:
    """Every match lies inside the file and its excerpt equals the file's bytes."""
    if result.scan is None:
        return False
    for rule in result.scan.matching_rules:
        for pattern in rule.patterns:
            if pattern.match_count < len(pattern.matches):
                return False
            for match in pattern.matches:
                end = match.offset + match.length
                if end > len(data):
                    return False
                excerpt = data[match.offset : match.offset + min(match.length, MAX_EXCERPT_BYTES)]
                if excerpt.hex() != match.excerpt_hex:
                    return False
    return True


def _finding_rows(
    result: YaraAdapterResult, run_id: str, invocation_id: str, rule_set_id: str
) -> list[Finding]:
    assert result.scan is not None  # noqa: S101 - checked by evidence_is_consistent
    findings = []
    for r_index, rule in enumerate(result.scan.matching_rules):
        description = next(
            (
                value
                for key, value in rule.metadata
                if key == "description" and isinstance(value, str)
            ),
            None,
        )
        evidence = [
            Evidence(
                kind="byte_range",
                pattern_id=pattern.identifier,
                file_offset=match.offset,
                length=match.length,
                xor_key=match.xor_key,
                excerpt_hex=match.excerpt_hex,
                raw_json_pointer=(
                    f"/scan/matching_rules/{r_index}/patterns/{p_index}/matches/{m_index}"
                ),
            )
            for p_index, pattern in enumerate(rule.patterns)
            for m_index, match in enumerate(pattern.matches)
        ]
        findings.append(
            Finding(
                run_id=run_id,
                invocation_id=invocation_id,
                kind="yara_match",
                title=(description or rule.identifier)[:200],
                rule_id=rule.identifier,
                rule_namespace=rule.namespace,
                rule_set_id=rule_set_id,
                tool_reported_attributes={
                    "tags": list(rule.tags),
                    "metadata": [[key, value] for key, value in rule.metadata],
                },
                fingerprint=hashlib.sha256(
                    f"yara-x:{rule.namespace}:{rule.identifier}".encode()
                ).hexdigest(),
                match_count=sum(p.match_count for p in rule.patterns),
                evidence_truncated=any(
                    p.match_count > len(p.matches)
                    or p.match_count >= result.scan.max_matches_per_pattern
                    for p in rule.patterns
                ),
                evidence=evidence,
            )
        )
    return findings


def _invocation_fields(
    rule_set_id: str,
    rule_set_sha256: str,
    outcome: AdapterOutcome[YaraAdapterResult] | None,
) -> dict[str, Any]:
    result = outcome.result if outcome else None
    return {
        "tool_name": "yara-x",
        "tool_version": result.tool_version if result else yara_x_installed_version(),
        "adapter_name": "yara_x_scan",
        "adapter_version": result.adapter_version if result else ADAPTER_VERSION,
        "args": {
            "rule_set_sha256": rule_set_sha256,
            "scan_timeout_seconds": SCAN_TIMEOUT_SECONDS,
            "max_matches_per_pattern": MAX_MATCHES_PER_PATTERN,
            "max_evidence_per_pattern": MAX_EVIDENCE_PER_PATTERN,
            "max_excerpt_bytes": MAX_EXCERPT_BYTES,
            "includes_enabled": False,
            "limits": result.resource_limits.model_dump() if result else None,
        },
        "exit_code": outcome.exit_code if outcome else None,
        "duration_ms": outcome.duration_ms if outcome else 0,
        "rule_set_id": rule_set_id,
        "warnings": (
            [
                f"{w.code}: {w.title}" + (f" ({w.file}:{w.line})" if w.file and w.line else "")
                for w in result.rules.warnings
            ]
            if result
            else []
        ),
    }


async def run_yara_step(deps: ScanDeps, step: StepInput) -> StepOutcome:
    rule_set = step.step["rule_set"]
    rule_set_id, rule_set_sha256 = str(rule_set["id"]), str(rule_set["sha256"])
    try:
        snapshot = deps.outputs.read_verified(rule_set_sha256)
    except IntegrityError:
        return StepOutcome(
            "failed",
            "rules_integrity",
            _invocation_fields(rule_set_id, rule_set_sha256, None),
        )
    write_rules(step.workdir, snapshot)
    outcome = await run_child(
        yara_argv(deps.adapter_command, deps.limits, rule_set_sha256, step.sample_sha256),
        step.workdir,
        deps.limits,
        parse_result=lambda raw: parse_yara_result(raw, rule_set_sha256, step.sample_sha256),
        should_cancel=step.should_stop,
    )
    fields = _invocation_fields(rule_set_id, rule_set_sha256, outcome)
    result = outcome.result
    if outcome.status == "cancelled":
        return StepOutcome("cancelled", "cancel_requested", fields)
    if outcome.status == "timed_out":
        return StepOutcome("timed_out", "timeout", fields)
    if outcome.status != "succeeded" or result is None or outcome.result_bytes is None:
        reason = outcome.reason if outcome.status == "failed" else "nonzero_exit"
        return StepOutcome("failed", reason, fields)
    if not result.rules.compiled or set(result.rules.rule_identifiers) != expected_identifiers(
        snapshot
    ):
        return StepOutcome("failed", "rules_invalid", fields)
    if result.scan is not None and result.scan.status == "timed_out":
        return StepOutcome("timed_out", "timeout", fields)
    if not evidence_is_consistent(result, step.data):
        return StepOutcome("failed", "invalid_output", fields)

    def rows(invocation_id: str) -> list[Base]:
        return list(_finding_rows(result, step.run_id, invocation_id, rule_set_id))

    return StepOutcome(
        "succeeded",
        None,
        fields,
        raw_output=outcome.result_bytes,
        rows=rows,
        log_fields={
            "rule_set_sha256": rule_set_sha256,
            "matching_rules": len(result.scan.matching_rules) if result.scan else 0,
            "duration_ms": outcome.duration_ms,
        },
    )
