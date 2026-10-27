"""Build and export a report for one sample version (blueprint 2 J9).

Order: verify the stored file's SHA-256 (and the stored adapter result's),
build the report from the database rows, validate it against the schema,
serialise it canonically, store it by its own SHA-256, and record it. If a
hash does not match, nothing is generated.

Canonical form: UTF-8 JSON with sorted keys, two-space indent, ASCII escapes,
a trailing newline, lists in a stable order. Two exports of the same data
differ only in `generated_at`.
"""

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from bytasm.db.models import Report, SampleVersion
from bytasm.notices import AUTHORIZATION_NOTICE, INPUT_POLICY_NOTICE, REPORT_LIMITATIONS
from bytasm.provenance import Generator
from bytasm.reports import model
from bytasm.storage import ContentStore


def canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def build_report(
    version: SampleVersion, generator: Generator, generated_at: datetime
) -> dict[str, Any]:
    run = version.runs[0]
    invocation = run.invocations[0]
    header = invocation.header
    computed_by = f"bytasm {invocation.adapter_name} {invocation.adapter_version}"
    sample = version.sample
    authorization = version.authorization

    document: dict[str, Any] = {
        "report_kind": model.REPORT_KIND,
        "schema_version": model.SCHEMA_VERSION,
        "generated_at": _iso(generated_at),
        "generator": {
            "name": "bytasm",
            **{k: v for k, v in asdict(generator).items() if k != "name"},
        },
        "sample": {
            "project_name": sample.project.name,
            "sample_name": sample.name,
            "version_label": version.version_label,
            "sha256": version.sha256,
            "size_bytes": version.size_bytes,
            "format": version.detected_format,
            "format_basis": "identified_from_bytes_and_parsed",
            "declared_filename": {
                "value": version.declared_filename,
                "trust": "untrusted_as_uploaded",
            },
            "blob_sha256_verified_at_export": True,
        },
        "input_policy": {
            "admitted_under": version.admitted_under,
            "manifest_entry": version.manifest_entry,
            "notice": INPUT_POLICY_NOTICE,
        },
        "authorization": {
            "type": "self_attestation",
            "basis": authorization.basis,
            "statement": authorization.statement,
            "terms_reference": authorization.terms_reference,
            "recorded_at": _iso(authorization.recorded_at),
            "notice": AUTHORIZATION_NOTICE,
        },
        "analysis": {
            "run": {
                "status": run.status,
                "profile": run.profile_snapshot,
                "bytasm_version": run.bytasm_version,
                "started_at": _iso(run.started_at),
                "finished_at": _iso(run.finished_at),
            },
            "tool_invocations": [
                {
                    "step_index": inv.step_index,
                    "tool": inv.tool_name,
                    "tool_version": inv.tool_version,
                    "adapter": inv.adapter_name,
                    "adapter_version": inv.adapter_version,
                    "status": inv.status,
                    "exit_code": inv.exit_code,
                    "duration_ms": inv.duration_ms,
                    "result_sha256": inv.raw_output_sha256,
                    "execution": "separate_resource_limited_process",
                }
                for inv in run.invocations
            ],
        },
        "metadata": {
            "declared_in_header": {
                "architecture": header["architecture"],
                "bitness": header["bitness"],
                "endianness": header["endianness"],
                "entry_point": header["entry_point"],
                "fields": dict(header["declared_header"]),
            },
            "sections": [
                {
                    "index": section.index,
                    "name": section.name,
                    "type": section.section_type,
                    "file_offset": section.file_offset,
                    "bytes_in_file": section.raw_size,
                    "virtual_address": section.virtual_address,
                    "declared_size": section.virtual_size,
                    "flags": list(section.flags),
                    "entropy": {
                        "value": section.entropy,
                        "unit": "bits_per_byte",
                        "method": invocation.entropy_method,
                        "computed_by": computed_by,
                        "measured_over": "section_bytes_in_file",
                        "note": section.entropy_note,
                    },
                }
                for section in sorted(invocation.sections, key=lambda s: s.index)
            ],
            "imports": {
                "libraries": sorted(header["imported_libraries"]),
                "functions": sorted(s.name for s in invocation.symbols if s.direction == "import"),
            },
            "exports": sorted(s.name for s in invocation.symbols if s.direction == "export"),
            "warnings": list(invocation.warnings),
        },
        "labels": dict(model.LABELS),
        "limitations": list(REPORT_LIMITATIONS),
    }
    model.Report.model_validate(document)  # never export something off-schema
    return document


def export_report(
    sessions: sessionmaker[Session],
    blobs: ContentStore,
    outputs: ContentStore,
    reports: ContentStore,
    scratch_dir: Path,
    version_id: str,
    generator: Generator,
) -> Report:
    """Verify, build, store, and record a report. Raises storage.IntegrityError
    (nothing generated) if a stored file no longer matches its SHA-256."""
    session = sessions()
    created: str | None = None
    try:
        version = session.get_one(SampleVersion, version_id)
        blobs.verify(version.sha256)
        for invocation in version.runs[0].invocations:
            outputs.verify(invocation.raw_output_sha256)

        generated_at = datetime.now(UTC).replace(microsecond=0)
        data = canonical_json(build_report(version, generator, generated_at))
        sha256 = hashlib.sha256(data).hexdigest()
        if reports.put_bytes(data, sha256, scratch_dir):
            created = sha256
        record = Report(
            sample_version_id=version.id,
            format="json",
            sha256=sha256,
            generated_at=generated_at,
            generator_version=generator.version,
            path=reports.relative_path(sha256),
        )
        session.add(record)
        session.commit()
        return record
    except BaseException:
        session.rollback()
        if created is not None:
            reports.remove(created)
        raise
    finally:
        session.close()
