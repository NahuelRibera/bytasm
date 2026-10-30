"""Build and export a report for one sample version (blueprint 2 J9).

Order: verify the stored file's SHA-256 (and the stored adapter results':
the import's, and those of the analysis run the report includes),
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

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from bytasm.adapters.yara_result import MAX_EXCERPT_BYTES
from bytasm.annotations import current_annotations, resolve_target
from bytasm.compare import CompareOut, compare_versions
from bytasm.db.imported import import_record
from bytasm.db.models import AnalysisRun, Finding, Report, RuleSet, SampleVersion
from bytasm.jobs import runs, summary
from bytasm.notices import (
    AUTHORIZATION_NOTICE,
    FINDING_NOTICES,
    INPUT_POLICY_NOTICE,
    PATTERN_REPORT_LIMITATIONS,
    REPORT_LIMITATIONS,
)
from bytasm.provenance import Generator
from bytasm.reports import model
from bytasm.storage import ContentStore


def canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def pattern_run(version: SampleVersion) -> AnalysisRun | None:
    """The newest analysis run of the version that kept results (blueprint J8, J9)."""
    candidates = [
        run for run in version.runs if run.kind == "analysis" and run.status in runs.WITH_RESULTS
    ]
    return max(candidates, key=lambda r: (r.queued_at or r.started_at, r.id), default=None)


def _pattern_analysis(session: Session, run: AnalysisRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    assert run.queued_at and run.started_at and run.finished_at  # noqa: S101 - finished run
    views = summary.step_views(run)
    rule_step = runs.rule_set_step(run.profile_snapshot)
    rule_set = session.get(RuleSet, rule_step["rule_set"]["id"]) if rule_step else None
    strings_inv = summary.strings_invocation(run)
    strings_params: dict[str, Any] = next(
        (v.step.get("params", {}) for v in views if v.tool == runs.STRINGS_TOOL), {}
    )
    yara_versions = {inv.id: inv.tool_version for inv in run.invocations}
    findings = sorted(
        (f for inv in run.invocations for f in _findings_of(session, inv.id)),
        key=lambda f: (f.rule_namespace, f.rule_id),
    )
    return {
        "run": {
            "id": run.id,
            "status": run.status,
            "failure_reason": run.failure_reason,
            "status_message": summary.run_message(run, views),
            "profile": run.profile_snapshot,
            "bytasm_version": run.bytasm_version,
            "queued_at": _iso(run.queued_at),
            "started_at": _iso(run.started_at),
            "finished_at": _iso(run.finished_at),
        },
        "steps": [
            {
                "index": view.index,
                "tool": view.tool,
                "adapter": view.adapter,
                "status": view.status,
                "message": view.message,
                "tool_version": view.invocation.tool_version if view.invocation else None,
                "adapter_version": view.invocation.adapter_version if view.invocation else None,
                "duration_ms": view.invocation.duration_ms if view.invocation else None,
                "result_sha256": view.invocation.raw_output_sha256 if view.invocation else None,
                "execution": "separate_resource_limited_process",
            }
            for view in views
        ],
        "rule_set": (
            {
                "tool": rule_set.tool,
                "name": rule_set.name,
                "version": rule_set.version,
                "sha256": rule_set.sha256,
                "source": rule_set.source,
                "rule_count": rule_set.rule_count,
            }
            if rule_set
            else None
        ),
        "strings": (
            {
                "encodings": list(strings_params.get("encodings", [])),
                "min_length": strings_params.get("min_length"),
                **(strings_inv.summary or {}),
                "values_included": False,
            }
            if strings_inv is not None and strings_inv.summary is not None
            else None
        ),
        "findings": [
            {
                "kind": finding.kind,
                "rule_set_sha256": session.get_one(RuleSet, finding.rule_set_id).sha256,
                "tool": "capa" if finding.kind == "capability" else "yara-x",
                "tool_version": yara_versions[finding.invocation_id],
                "rule_id": finding.rule_id,
                "rule_namespace": finding.rule_namespace,
                "title": finding.title,
                "tags": [str(t) for t in finding.tool_reported_attributes.get("tags", [])],
                "metadata": [
                    [str(k), v] for k, v in finding.tool_reported_attributes.get("metadata", [])
                ],
                "fingerprint": finding.fingerprint,
                "match_count": finding.match_count,
                "evidence_truncated": finding.evidence_truncated,
                "evidence": [
                    {
                        "kind": item.kind,
                        "pattern_id": item.pattern_id,
                        "file_offset": item.file_offset,
                        "virtual_address": item.virtual_address,
                        "virtual_address_hex": f"{item.virtual_address:#x}"
                        if item.virtual_address is not None
                        else None,
                        "length": item.length,
                        "xor_key": item.xor_key,
                        "excerpt_hex": item.excerpt_hex,
                        "excerpt_truncated": (item.length or 0) > MAX_EXCERPT_BYTES,
                        "raw_json_pointer": item.raw_json_pointer,
                    }
                    for item in sorted(
                        finding.evidence,
                        key=lambda e: (
                            e.file_offset or e.virtual_address or 0,
                            e.pattern_id,
                            e.raw_json_pointer,
                        ),
                    )
                ],
            }
            for finding in findings
        ],
        "notices": list(FINDING_NOTICES),
    }


def _findings_of(session: Session, invocation_id: str) -> list[Finding]:
    return list(session.scalars(select(Finding).where(Finding.invocation_id == invocation_id)))


def build_report(
    version: SampleVersion,
    generator: Generator,
    generated_at: datetime,
    session: Session,
    comparison: CompareOut | None = None,
) -> dict[str, Any]:
    record = import_record(version)
    run = record.run
    invocation = record.invocation
    header = record.header
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
                "started_at": _iso(record.started_at),
                "finished_at": _iso(record.finished_at),
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
                        "method": record.entropy_method,
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
        "pattern_analysis": _pattern_analysis(session, pattern_run(version)),
        "scope": {
            "kind": "comparison" if comparison else "sample_version",
            "version_ids": list(dict.fromkeys([comparison.a.version_id, comparison.b.version_id]))
            if comparison
            else [version.id],
        },
        "annotations": [
            item.model_dump(mode="json")
            for version_id in sorted(
                {comparison.a.version_id, comparison.b.version_id} if comparison else {version.id}
            )
            for item in current_annotations(session, version_id)
        ],
        "comparison": comparison.model_dump(mode="json") if comparison else None,
        "labels": dict(model.LABELS),
        "limitations": list(REPORT_LIMITATIONS)
        + list(PATTERN_REPORT_LIMITATIONS[:-1] if comparison else PATTERN_REPORT_LIMITATIONS)
        + (
            [
                "This comparison report may include changed string values and analyst text. "
                "Review these contents before sharing the report."
            ]
            if comparison
            else []
        ),
    }
    from bytasm.plain_summary import report_summary

    latest = max(
        (r for r in version.runs if r.kind == "analysis"),
        key=lambda r: (r.queued_at or r.started_at, r.id),
        default=None,
    )
    selected = pattern_run(version)
    document["analysis_context"] = (
        {
            "latest_run_id": latest.id,
            "latest_status": latest.status,
            "selected_run_id": selected.id if selected else None,
        }
        if latest
        else None
    )
    document["summary"] = report_summary(document)
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
    compare_with: str | None = None,
) -> Report:
    """Verify, build, store, and record a report. Raises storage.IntegrityError
    (nothing generated) if a stored file no longer matches its SHA-256."""
    session = sessions()
    created: str | None = None
    try:
        # Verification and rendering must see the same SQLite snapshot. This export
        # will insert a report row, so acquire the writer slot before reading.
        session.execute(text("BEGIN IMMEDIATE"))
        version = session.get_one(SampleVersion, version_id)
        comparison = (
            compare_versions(session, compare_with, version_id, limit=200) if compare_with else None
        )
        if comparison is not None:
            # API pages are bounded; a report contains every changed key.
            for name, category_diff in comparison.categories.items():
                while category_diff.next_offset is not None:
                    more = compare_versions(
                        session,
                        compare_with or version_id,
                        version_id,
                        category=name,
                        offset=category_diff.next_offset,
                        limit=200,
                    ).categories[name]
                    category_diff.rows.extend(more.rows)
                    category_diff.next_offset = more.next_offset
        selected_ids = {version_id, compare_with} if compare_with is not None else {version_id}
        checked_runs: set[str] = set()
        for selected_id in sorted(selected_ids):
            selected = session.get_one(SampleVersion, selected_id)
            blobs.verify(selected.sha256)
            outputs.verify(import_record(selected).raw_output_sha256)
            analysis = pattern_run(selected)
            if analysis is not None:
                checked_runs.add(analysis.id)
            for annotation in current_annotations(session, selected.id):
                _, target = resolve_target(session, annotation.target_type, annotation.target_id)
                if target is not None:
                    checked_runs.add(target.run_id)
                checked_runs.update(cite.run_id for cite in annotation.cites)
        for run_id in sorted(checked_runs):
            analysis = session.get_one(AnalysisRun, run_id)
            for invocation in analysis.invocations:
                if invocation.rule_set is not None:
                    outputs.verify(invocation.rule_set.sha256)
                if invocation.raw_output_sha256 is not None:
                    outputs.verify(invocation.raw_output_sha256)
            rule_step = runs.rule_set_step(analysis.profile_snapshot)
            if rule_step:
                rule_set = session.get_one(RuleSet, rule_step["rule_set"]["id"])
                outputs.verify(rule_set.sha256)

        generated_at = datetime.now(UTC).replace(microsecond=0)
        document = build_report(version, generator, generated_at, session, comparison)
        data = canonical_json(document)
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
            scope=document["scope"],
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
