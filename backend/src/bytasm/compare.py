"""Deterministic structural comparison of persisted, successful step outputs.

IDs are references only and never participate in observation equality. Missing or
incompatible steps cannot establish absence, so their rows are not diffed.
"""

import json
from collections import defaultdict
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from bytasm.db.models import AnalysisRun, Finding, SampleVersion, StringOccurrence, ToolInvocation

CATEGORIES = ("metadata", "sections", "imports", "exports", "strings", "findings", "evidence")


class CompareError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class ObservationRef(BaseModel):
    run_id: str
    invocation_id: str
    finding_id: str | None = None
    evidence_id: int | None = None


class DiffRow(BaseModel):
    key: str
    change: Literal["added", "removed", "changed"]
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    before_ref: ObservationRef | None = None
    after_ref: ObservationRef | None = None


class CategoryDiff(BaseModel):
    status: Literal["comparable", "unavailable", "incompatible"]
    reason: str | None = None
    a_status: str = "not_run"
    b_status: str = "not_run"
    added: int = 0
    removed: int = 0
    changed: int = 0
    total_rows: int = 0
    rows: list[DiffRow] = Field(default_factory=list)
    next_offset: int | None = None


class VersionRef(BaseModel):
    version_id: str
    sample_id: str
    project_id: str
    sha256: str
    run_id: str | None
    run_status: str | None


class CompareOut(BaseModel):
    a: VersionRef
    b: VersionRef
    identical_content: bool
    warnings: list[str]
    categories: dict[str, CategoryDiff]


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _run(session: Session, version: str, kind: str, successful: bool = True) -> AnalysisRun | None:
    query = select(AnalysisRun).where(
        AnalysisRun.sample_version_id == version, AnalysisRun.kind == kind
    )
    if successful:
        query = query.where(AnalysisRun.status.in_(("succeeded", "partial")))
    timestamp = func.coalesce(
        AnalysisRun.queued_at, AnalysisRun.started_at, AnalysisRun.finished_at
    )
    # ISO text with optional fractions does not sort chronologically within a
    # second ("00Z" sorts after "00.000001Z"). Preserve microsecond precision.
    chronological = case(
        (func.length(timestamp) == 20, func.substr(timestamp, 1, 19) + ".000000Z"),
        else_=timestamp,
    )
    return session.scalar(
        query.order_by(
            chronological.desc(),
            AnalysisRun.id.desc(),
        ).limit(1)
    )


def _invocation(run: AnalysisRun | None, tool: str) -> ToolInvocation | None:
    if run is None or run.status not in ("succeeded", "partial"):
        return None
    return next(
        (i for i in run.invocations if i.tool_name == tool and i.status == "succeeded"), None
    )


def _provenance(inv: ToolInvocation) -> tuple[Any, ...]:
    rules = inv.rule_set
    return (
        inv.tool_name,
        inv.tool_version,
        inv.adapter_name,
        inv.adapter_version,
        _canonical(inv.args),
        inv.entropy_method,
        (rules.sha256, rules.version) if rules else None,
    )


def _fields(row: Any, *names: str) -> dict[str, Any]:
    return {name: getattr(row, name) for name in names}


def _observations(session: Session, inv: ToolInvocation, category: str) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    references: dict[str, dict[str, Any]] = {}
    if category == "metadata":
        version = inv.run.sample_version
        identity = {
            "sha256": version.sha256,
            "size_bytes": version.size_bytes,
            "detected_format": version.detected_format,
        }
        return {key: {"value": value} for key, value in {**(inv.header or {}), **identity}.items()}
    if category == "sections":
        for row in inv.sections:
            key = _canonical([row.name, sorted(row.flags)])
            grouped[key].append(
                _fields(
                    row,
                    "section_type",
                    "file_offset",
                    "raw_size",
                    "virtual_address",
                    "virtual_size",
                    "entropy",
                    "entropy_note",
                )
            )
    elif category in ("imports", "exports"):
        for symbol in inv.symbols:
            if symbol.direction == ("import" if category == "imports" else "export"):
                key = _canonical([symbol.library, symbol.name])
                grouped[key].append(_fields(symbol, "ordinal", "address"))
        if category == "imports":
            for library in (inv.header or {}).get("imported_libraries", []):
                grouped[_canonical([library, None])].append({"library": library})
    elif category == "strings":
        for occurrence in session.scalars(
            select(StringOccurrence).where(StringOccurrence.invocation_id == inv.id)
        ):
            # Truncated prefixes cannot prove equality of full string values.
            key = occurrence.value
            grouped[key].append(
                _fields(
                    occurrence,
                    "file_offset",
                    "encoding",
                    "length_chars",
                    "byte_length",
                    "value_truncated",
                )
            )
    else:
        for finding in session.scalars(select(Finding).where(Finding.invocation_id == inv.id)):
            key = _canonical([inv.tool_name, finding.rule_namespace, finding.rule_id])
            references[key] = {
                "run_id": inv.run_id,
                "invocation_id": inv.id,
                "finding_id": finding.id,
            }
            if category == "findings":
                grouped[key].append(
                    _fields(
                        finding,
                        "kind",
                        "title",
                        "tool_reported_attributes",
                        "match_count",
                        "evidence_truncated",
                    )
                )
            else:
                for evidence in finding.evidence:
                    evidence_key = _canonical(
                        [key, evidence.pattern_id, evidence.file_offset, evidence.length]
                    )
                    references[evidence_key] = {**references[key], "evidence_id": evidence.id}
                    grouped[evidence_key].append(
                        _fields(evidence, "kind", "xor_key", "excerpt_hex")
                    )
    return {
        key: {
            "occurrences": sorted(values, key=_canonical),
            "_ref": references.get(key, {"run_id": inv.run_id, "invocation_id": inv.id}),
        }
        for key, values in grouped.items()
    }


def _display(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    payload = {k: v for k, v in value.items() if k != "_ref"}
    if "occurrences" in payload:
        occurrences = payload["occurrences"]
        payload = {
            "occurrences": occurrences[:20],
            "occurrences_total": len(occurrences),
            "occurrences_truncated": len(occurrences) > 20,
        }
    return payload


def _equal(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return {k: v for k, v in left.items() if k != "_ref"} == {
        k: v for k, v in right.items() if k != "_ref"
    }


def _diff(before: dict[str, Any], after: dict[str, Any], offset: int, limit: int) -> CategoryDiff:
    rows = []
    change: Literal["added", "removed", "changed"]
    for key in sorted(before.keys() | after.keys()):
        if key not in before:
            change = "added"
        elif key not in after:
            change = "removed"
        elif not _equal(before[key], after[key]):
            change = "changed"
        else:
            continue
        rows.append(
            DiffRow(
                key=key,
                change=change,
                before=_display(before.get(key)),
                after=_display(after.get(key)),
                before_ref=before.get(key, {}).get("_ref"),
                after_ref=after.get(key, {}).get("_ref"),
            )
        )
    return CategoryDiff(
        status="comparable",
        added=sum(r.change == "added" for r in rows),
        removed=sum(r.change == "removed" for r in rows),
        changed=sum(r.change == "changed" for r in rows),
        total_rows=len(rows),
        rows=rows[offset : offset + limit],
        next_offset=offset + limit if offset + limit < len(rows) else None,
    )


def compare_versions(
    session: Session,
    a_id: str,
    b_id: str,
    *,
    category: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> CompareOut:
    if category is not None and category not in CATEGORIES or offset < 0 or not 1 <= limit <= 200:
        raise CompareError("invalid_request", "Invalid comparison category or pagination bounds.")
    a, b = session.get(SampleVersion, a_id), session.get(SampleVersion, b_id)
    if a is None or b is None:
        raise CompareError("not_found", "No sample version with this ID.")
    if a.sample_id != b.sample_id or a.sample.project_id != b.sample.project_id:
        raise CompareError("invalid_request", "Comparison requires versions of the same sample.")
    analysis = [_run(session, v.id, "analysis") for v in (a, b)]
    imports = [_run(session, v.id, "import") for v in (a, b)]
    context = [
        r or _run(session, v.id, "analysis", False) for r, v in zip(analysis, (a, b), strict=True)
    ]
    refs = [
        VersionRef(
            version_id=v.id,
            sample_id=v.sample_id,
            project_id=v.sample.project_id,
            sha256=v.sha256,
            run_id=r.id if r else None,
            run_status=r.status if r else None,
        )
        for v, r in zip((a, b), context, strict=True)
    ]
    warnings = [
        "Imported functions may lack library association in the metadata adapter; "
        "unassociated symbols and imported library names are compared separately."
    ]
    categories = {}
    for name in [category] if category else CATEGORIES:
        tool = "lief" if name in CATEGORIES[:4] else "strings" if name == "strings" else "yara-x"
        source = imports if tool == "lief" else analysis
        left, right = (_invocation(run, tool) for run in source)
        if left is None or right is None:
            categories[name] = CategoryDiff(
                status="unavailable",
                reason="A completed successful step is unavailable for one or both versions.",
            )
        elif _provenance(left) != _provenance(right):
            reason = f"{name}: tool, adapter, parameters, entropy method or rules snapshot differ."
            warnings.append(reason)
            categories[name] = CategoryDiff(status="incompatible", reason=reason)
        else:
            truncated = name == "strings" and any(
                (inv.summary or {}).get("truncated", False)
                or session.scalar(
                    select(StringOccurrence.id)
                    .where(
                        StringOccurrence.invocation_id == inv.id,
                        StringOccurrence.value_truncated.is_(True),
                    )
                    .limit(1)
                )
                is not None
                for inv in (left, right)
            )
            if truncated:
                warnings.append(
                    "Strings are truncated or capped; full string equality is unavailable."
                )
            if truncated and a.sha256 != b.sha256:
                categories[name] = CategoryDiff(
                    status="unavailable",
                    reason="Truncated or capped strings cannot establish equality or absence.",
                )
            else:
                categories[name] = _diff(
                    _observations(session, left, name),
                    _observations(session, right, name),
                    offset,
                    limit,
                )
        for side, source_run in zip(
            ("a_status", "b_status"), imports if tool == "lief" else context, strict=True
        ):
            invocation = (
                next((i for i in source_run.invocations if i.tool_name == tool), None)
                if source_run
                else None
            )
            step_status = (
                invocation.status
                if invocation
                else ("cancelled" if source_run and source_run.status == "cancelled" else "not_run")
            )
            setattr(categories[name], side, step_status)
    return CompareOut(
        a=refs[0],
        b=refs[1],
        identical_content=a.sha256 == b.sha256,
        warnings=warnings,
        categories=categories,
    )
