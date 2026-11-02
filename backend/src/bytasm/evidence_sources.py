"""Load evidence-graph inputs from stored, revalidated records.

Shared by the live evidence API (one pattern run) and pinned reviews, which
may pin each pattern tool from a different run. Every finding and string
keeps the run and invocation it came from, so a composed source never
misattributes a record to another run.
"""

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from bytasm.adapters.result import DeepStructureResult
from bytasm.address_map import DeclaredLayout
from bytasm.db.imported import ImportRecord
from bytasm.db.models import (
    AnalysisRun,
    Finding,
    RuleSet,
    SampleVersion,
    StringOccurrence,
    ToolInvocation,
)
from bytasm.evidence_graph import (
    EvidenceRecord,
    FindingRecord,
    ImportSlot,
    MetadataSource,
    PatternSource,
    StepRecord,
    StringRecord,
)
from bytasm.jobs import summary
from bytasm.storage import ContentStore
from bytasm.structure_source import deep_structure

PATTERN_TOOLS = ("strings", "yara-x", "capa")


def import_slots(tables: DeepStructureResult | None) -> tuple[ImportSlot, ...] | None:
    if tables is None:
        return None
    return tuple(
        ImportSlot(
            name=slot.name,
            library=slot.library,
            slot_virtual_address=slot.slot_virtual_address,
            slot_file_offset=slot.slot_file_offset,
            basis=slot.slot_basis,
            relocation_type=slot.relocation_type,
            pointer=f"/metadata/deep_structure/import_slots/{index}",
        )
        for index, slot in enumerate(tables.import_slots)
    )


def metadata_source(
    version: SampleVersion, record: ImportRecord, outputs: ContentStore | None = None
) -> MetadataSource:
    """The import record as a graph source; `outputs` enables the 0.3.0 import slots."""
    slots = None
    if outputs is not None:
        slots = import_slots(deep_structure(outputs, version, record).tables)
    header = record.header
    return MetadataSource(
        run_id=record.run.id,
        invocation_id=record.invocation.id,
        output_sha256=record.raw_output_sha256,
        tool_version=record.invocation.tool_version,
        file_format=str(header.get("format", version.detected_format)),
        file_size=version.size_bytes,
        entry_point=header.get("entry_point"),
        layout=DeclaredLayout.from_import(header, list(record.invocation.sections)),
        imports=tuple(sorted(s.name for s in record.invocation.symbols if s.direction == "import")),
        imported_libraries=tuple(header.get("imported_libraries", [])),
        import_slots=slots,
    )


def step_record(tool: str, status: str, inv: ToolInvocation | None) -> StepRecord:
    return StepRecord(
        tool=tool,
        status=status,
        invocation_id=inv.id if inv else None,
        tool_version=inv.tool_version if inv else None,
        run_id=inv.run_id if inv else None,
        output_sha256=inv.raw_output_sha256 if inv else None,
        adapter_version=inv.adapter_version if inv else None,
        rule_set_sha256=inv.rule_set.sha256 if inv is not None and inv.rule_set else None,
    )


def _findings(session: Session, inv: ToolInvocation) -> list[FindingRecord]:
    rows = session.execute(
        select(Finding, RuleSet.sha256)
        .join(RuleSet, RuleSet.id == Finding.rule_set_id, isouter=True)
        .where(Finding.invocation_id == inv.id)
        .order_by(Finding.id)
    ).all()
    return [
        FindingRecord(
            id=finding.id,
            tool=str(finding.tool_reported_attributes.get("tool", inv.tool_name)),
            tool_version=inv.tool_version,
            rule_id=finding.rule_id,
            namespace=finding.rule_namespace,
            rule_set_sha256=rule_set_sha256 or "",
            invocation_id=inv.id,
            output_sha256=inv.raw_output_sha256,
            match_count=finding.match_count,
            evidence_truncated=finding.evidence_truncated,
            evidence=tuple(
                EvidenceRecord(
                    id=e.id,
                    kind=e.kind,
                    file_offset=e.file_offset,
                    length=e.length,
                    virtual_address=e.virtual_address,
                    pointer=e.raw_json_pointer,
                )
                for e in finding.evidence
            ),
            run_id=inv.run_id,
        )
        for finding, rule_set_sha256 in rows
    ]


def pattern_from_invocations(
    session: Session,
    *,
    run_id: str,
    status: str,
    profile_id: str,
    steps: Sequence[StepRecord],
    invocations: Sequence[ToolInvocation],
) -> PatternSource:
    """Findings of every succeeded rule invocation plus at most one strings step."""
    findings: list[FindingRecord] = []
    strings_inv = None
    for inv in invocations:
        if inv.status != "succeeded":
            continue
        if inv.tool_name == "strings":
            strings_inv = inv
            continue
        findings.extend(_findings(session, inv))
    strings = None
    truncated = False
    if strings_inv is not None:
        occurrences = session.scalars(
            select(StringOccurrence)
            .where(StringOccurrence.invocation_id == strings_inv.id)
            .order_by(StringOccurrence.file_offset, StringOccurrence.encoding)
        )
        strings = tuple(
            StringRecord(r.id, r.file_offset, r.encoding, r.value, r.value_truncated, r.byte_length)
            for r in occurrences
        )
        truncated = bool((strings_inv.summary or {}).get("truncated"))
    return PatternSource(
        run_id=run_id,
        status=status,
        profile_id=profile_id,
        steps=tuple(steps),
        findings=tuple(findings),
        strings=strings,
        strings_invocation_id=strings_inv.id if strings_inv else None,
        strings_output_sha256=strings_inv.raw_output_sha256 if strings_inv else None,
        strings_truncated=truncated,
        strings_run_id=strings_inv.run_id if strings_inv else None,
    )


def pattern_for_run(session: Session, run: AnalysisRun) -> PatternSource:
    views = summary.step_views(run)
    strings_inv = summary.strings_invocation(run)
    return pattern_from_invocations(
        session,
        run_id=run.id,
        status=run.status,
        profile_id=str(run.profile_snapshot.get("id")),
        steps=[step_record(v.tool, v.status, v.invocation) for v in views],
        invocations=[
            inv
            for inv in run.invocations
            if inv.tool_name != "strings" or (strings_inv is not None and inv.id == strings_inv.id)
        ],
    )


def pattern_for_pinned(session: Session, chosen: dict[str, ToolInvocation]) -> PatternSource | None:
    """Compose the pattern tools a review pinned, possibly from several runs."""
    picked = {tool: chosen[tool] for tool in PATTERN_TOOLS if tool in chosen}
    if not picked:
        return None
    run_ids = sorted({inv.run_id for inv in picked.values()})
    return pattern_from_invocations(
        session,
        run_id=run_ids[0] if len(run_ids) == 1 else "+".join(run_ids),
        status="pinned",
        profile_id="review-pinned-sources",
        steps=[
            step_record(tool, "succeeded", picked[tool])
            if tool in picked
            else step_record(tool, "not_pinned", None)
            for tool in PATTERN_TOOLS
        ],
        invocations=list(picked.values()),
    )
