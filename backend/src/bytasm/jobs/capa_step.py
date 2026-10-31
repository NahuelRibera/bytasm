"""capa worker stage: verified rules, bounded child, strict result persistence."""

import hashlib
import json
from dataclasses import replace
from importlib.metadata import PackageNotFoundError, version

from pydantic import ValidationError

from bytasm.adapters.capa_result import CapaResult, classifications
from bytasm.adapters.capa_scan import ADAPTER_VERSION
from bytasm.capa_rules import VERSION
from bytasm.db.models import Base, Evidence, Finding
from bytasm.jobs.steps import ScanDeps, StepInput, StepOutcome
from bytasm.runner.supervisor import run_child
from bytasm.storage import IntegrityError


def supported(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    pe = int.from_bytes(data[60:64], "little")
    if pe + 24 + 224 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        return False
    machine = int.from_bytes(data[pe + 4 : pe + 6], "little")
    magic = int.from_bytes(data[pe + 24 : pe + 26], "little")
    directories = pe + 24 + (112 if magic == 0x20B else 96)
    # No .NET backend, shellcode, dynamic formats or plugins in this integration.
    return (
        machine in (0x14C, 0x8664)
        and magic in (0x10B, 0x20B)
        and not any(data[directories + 14 * 8 : directories + 15 * 8])
    )


def parse_result(raw: bytes, step: StepInput, snapshot: bytes) -> CapaResult | None:
    try:
        result = CapaResult.model_validate_json(raw)
        if (
            result.sample_sha256 != step.sample_sha256
            or result.rules_sha256 != step.step["rule_set"]["sha256"]
        ):
            return None
        document = json.loads(result.raw)
        meta = document["meta"]
        if (
            meta["version"] != VERSION
            or meta["flavor"] != "static"
            or meta["sample"]["sha256"] != step.sample_sha256
        ):
            return None
        allowed = set(json.loads(snapshot).values())
        if set(document["rules"]) != {finding.name for finding in result.findings}:
            return None
        for finding in result.findings:
            original = document["rules"][finding.name]
            # Exact packaged rule text, tied to the name capa parsed from it. Authored
            # filenames need not match rule names, so never derive a filename.
            if (
                original["source"] != finding.source
                or finding.source not in allowed
                or original["meta"].get("name") != finding.name
            ):
                return None
            if (
                original["meta"].get("namespace", "") != finding.namespace
                or classifications(original["meta"]) != finding.classifications
                or len(original["matches"]) != finding.match_count
            ):
                return None
            if len(finding.matches) != min(32, finding.match_count):
                return None
            for index, match in enumerate(finding.matches):
                expected = original["matches"][index][0]
                pointer = finding.name.replace("~", "~0").replace("/", "~1")
                if (
                    expected != {"type": "absolute", "value": match.address}
                    or match.pointer != f"/rules/{pointer}/matches/{index}/0"
                ):
                    return None
        return result
    except (ValueError, KeyError, TypeError, ValidationError, RecursionError):
        return None


async def run_capa_step(deps: ScanDeps, step: StepInput) -> StepOutcome:
    ref = step.step["rule_set"]
    fields = {
        "tool_name": "capa",
        "tool_version": VERSION,
        "adapter_name": "capa_scan",
        "adapter_version": ADAPTER_VERSION,
        "rule_set_id": ref["id"],
        "args": {
            "backend": "vivisect",
            "entrypoint": "capa.main.main (private-cache shim)",
            "format": "pe",
            "signatures": "none",
            "rule_set_sha256": ref["sha256"],
            "timeout_seconds": 120,
            "max_matches": 32,
        },
        "exit_code": None,
        "duration_ms": 0,
        "warnings": [
            (
                "capa is static code analysis. Packed files, installers, wrappers "
                "and missing library signatures can yield incomplete or misleading"
                " observations. Only the packaged seven-rule subset is evaluated."
            )
        ],
    }
    if not supported(step.data):
        return StepOutcome("unsupported", "unsupported_format", fields)
    try:
        installed = version("flare-capa")
    except PackageNotFoundError:
        fields["tool_version"] = "unavailable"
        return StepOutcome("unavailable", "tool_unavailable", fields)
    if installed != VERSION:
        fields["tool_version"] = installed
        return StepOutcome("unavailable", "tool_unavailable", fields)
    try:
        snapshot = deps.outputs.read_verified(ref["sha256"])
    except IntegrityError:
        return StepOutcome("failed", "rules_integrity", fields)
    (step.workdir / "capa-rules.json").write_bytes(snapshot)
    limits = replace(
        deps.limits,
        timeout_seconds=min(
            120,
            float(step.step["timeout_seconds"]),
            deps.limits.timeout_seconds if deps.limits.timeout_seconds != 30 else 120,
        ),
        result_bytes=16 * 1024**2,
    )
    outcome = await run_child(
        [
            *deps.capa_command,
            "--expected-sha256",
            step.sample_sha256,
            "--rules-sha256",
            ref["sha256"],
        ],
        step.workdir,
        limits,
        parse_result=lambda raw: parse_result(raw, step, snapshot),
        should_cancel=step.should_stop,
    )
    fields.update(exit_code=outcome.exit_code, duration_ms=outcome.duration_ms)
    if outcome.status != "succeeded" or outcome.result is None:
        status = outcome.status if outcome.status in ("cancelled", "timed_out") else "failed"
        return StepOutcome(
            status,
            "cancel_requested"
            if status == "cancelled"
            else "timeout"
            if status == "timed_out"
            else outcome.reason or "invalid_output",
            fields,
        )
    result = outcome.result

    def rows(invocation_id: str) -> list[Base]:
        return [
            Finding(
                run_id=step.run_id,
                invocation_id=invocation_id,
                kind="capability",
                title=f.name,
                rule_id=f.name,
                rule_namespace=f.namespace,
                rule_set_id=ref["id"],
                tool_reported_attributes={
                    "tool": "capa",
                    "tags": [],
                    "metadata": [
                        ["source", f.source],
                        *[list(label) for label in f.classifications],
                    ],
                    "rule_source": f.source,
                },
                fingerprint=hashlib.sha256(f"capa:{f.namespace}:{f.name}".encode()).hexdigest(),
                match_count=f.match_count,
                evidence_truncated=f.match_count > len(f.matches),
                evidence=[
                    Evidence(
                        kind="virtual_address",
                        pattern_id="function",
                        file_offset=None,
                        length=None,
                        virtual_address=m.address,
                        xor_key=None,
                        excerpt_hex="",
                        raw_json_pointer=m.pointer,
                    )
                    for m in f.matches
                ],
            )
            for f in result.findings
        ]

    return StepOutcome("succeeded", None, fields, raw_output=result.raw.encode("utf-8"), rows=rows)
