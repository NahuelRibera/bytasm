"""Versioned, deterministic review contracts. No live selection on snapshot reads."""

import hashlib
import os
import stat
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from bytasm.api.context import AppContext
from bytasm.db.models import (
    AnalysisRun,
    Evidence,
    Finding,
    ReviewSnapshot,
    RuleSet,
    SampleVersion,
    StringOccurrence,
    ToolInvocation,
    new_id,
)
from bytasm.interpretation_catalog import DETAILS
from bytasm.jobs.summary import step_views
from bytasm.reports.generate import canonical_json
from bytasm.review import explanation
from bytasm.storage import ContentStore, IntegrityError

MAX_REVIEW_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
ToolName = Literal["lief", "strings", "yara-x", "capa", "ghidra"]
TOOLS: tuple[ToolName, ...] = ("lief", "strings", "yara-x", "capa", "ghidra")
CATALOG_VERSION = "review-2"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CreateReview(Strict):
    scope: Literal["combined", "exact_run"] = "combined"
    run_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")] | None = None

    @model_validator(mode="after")
    def exact_scope(self) -> "CreateReview":
        if (self.scope == "exact_run") != (self.run_id is not None):
            raise ValueError("Exact run requires a run ID; combined review selects server-side")
        return self


class Identity(Strict):
    version_id: str
    sample_id: str
    sha256: str
    size_bytes: int
    format: str


class Attempt(Strict):
    run_id: str
    invocation_id: str | None
    run_status: str
    status: str


class Selected(Attempt):
    output_sha256: str
    tool_version: str
    adapter: str
    adapter_version: str
    rule_sha256: str | None
    profile: dict[str, Any]
    parameters: dict[str, Any]
    completeness: Literal["bounded_retained_output"] = "bounded_retained_output"
    limits: dict[str, Any] | None
    retention: dict[str, Any]
    warnings: list[str]


class Source(Strict):
    tool: Literal["lief", "strings", "yara-x", "capa", "ghidra"]
    selected: Selected | None
    latest_attempt: Attempt | None
    unavailable_reason: str | None


class Observation(Strict):
    id: str
    title: str
    question: str
    statement: str
    why_it_matters: str
    alternatives: list[str]
    hypothesis: str
    conditions: str
    limitations: list[str]
    next_step: str
    reviewed: bool
    relevance: int
    selection_reason: str
    run_id: str
    invocation_id: str
    output_sha256: str
    tool: str
    rule_id: str
    rule_sha256: str
    finding_id: str
    evidence: list[dict[str, Any]]
    evidence_capped: bool


class TextRecord(Strict):
    id: int
    invocation_id: str
    offset: int
    encoding: str
    value: str
    value_truncated: bool


class ImportObservation(Strict):
    category: str
    title: str
    observation: str
    alternative: str
    next_step: str
    pointers: list[str] = Field(max_length=8)
    supporting_names: list[str] = Field(max_length=8)
    matches_retained: int
    locations_capped: bool
    catalog_version: str
    catalog_sha256: str
    source: str
    limitation: str
    run_id: str
    invocation_id: str
    output_sha256: str


class Snapshot(Strict):
    schema_version: Literal["bytasm-review-1"] = "bytasm-review-1"
    id: str
    supersedes_id: str | None
    created_at: datetime
    sample: Identity
    scope: Literal["combined", "exact_run"]
    exact_run_id: str | None
    source_selection_policy: Literal["latest-completed-step-per-tool-v1"] = (
        "latest-completed-step-per-tool-v1"
    )
    integrity: Literal["verified_at_creation"] = "verified_at_creation"
    catalog_version: Literal["review-2"] = "review-2"
    sources: list[Source] = Field(max_length=5)
    observations: list[Observation] = Field(max_length=48)
    observations_total: int
    observations_capped: bool
    import_observations: list[ImportObservation] = Field(default_factory=list, max_length=16)
    strings: list[TextRecord] = Field(max_length=5000)
    unknowns: list[str]
    selection_explanation: str
    declared_filename: str | None
    function_reviews: list[dict[str, Any]] = Field(default_factory=list, max_length=128)


def bounded_read(store: ContentStore, digest: str, maximum: int) -> bytes:
    try:
        fd = os.open(store.path(digest), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise IntegrityError("Stored output exceeds bound")
            raw = handle.read(maximum + 1)
        if len(raw) > maximum or hashlib.sha256(raw).hexdigest() != digest:
            raise IntegrityError("Stored output changed")
        return raw
    except (OSError, ValueError) as exc:
        raise IntegrityError("Stored output unavailable") from exc


def make_observation(
    finding: Finding,
    inv: ToolInvocation,
    rules: RuleSet,
    evidence: list[Evidence],
) -> Observation:
    statement, hypothesis = explanation(
        inv.tool_name, inv.tool_version, finding.rule_id, rules.sha256
    )
    reviewed = not hypothesis.startswith("There is no reviewed")
    detail = DETAILS.get(finding.rule_id) if reviewed else None
    title, question, why, alternative, score = detail or (
        "Static rule match needs review",
        "Unreviewed observations",
        "Inspect the exact rule before assigning a meaning.",
        "The meaning and benign alternatives have not been reviewed for this provenance.",
        0,
    )
    return Observation(
        id=finding.id,
        title=title,
        question=question,
        statement=statement,
        why_it_matters=why,
        alternatives=[alternative],
        hypothesis=hypothesis,
        conditions="Exact tool version and rule-set digest match the reviewed catalog."
        if reviewed
        else "No catalog conditions were established for this provenance.",
        limitations=[
            "Static evidence does not establish execution, path feasibility or publisher identity.",
            "Missing or contradictory code context has not been evaluated.",
        ],
        next_step="Inspect the linked rule and evidence; then inspect code references.",
        reviewed=reviewed,
        relevance=score,
        selection_reason="Reviewed code feature"
        if score == 30
        else ("Reviewed text or structural context" if reviewed else "Unreviewed provenance"),
        run_id=inv.run_id,
        invocation_id=inv.id,
        output_sha256=inv.raw_output_sha256 or "",
        tool=inv.tool_name,
        rule_id=finding.rule_id,
        rule_sha256=rules.sha256,
        finding_id=finding.id,
        evidence=[
            {
                "id": e.id,
                "kind": e.kind,
                "file_offset": e.file_offset,
                "length": e.length,
                "virtual_address": e.virtual_address,
                "pointer": e.raw_json_pointer,
            }
            for e in evidence[:4]
        ],
        evidence_capped=finding.evidence_truncated or len(evidence) > 4,
    )


def validate_finding_rows(
    tool: str,
    inv: ToolInvocation,
    rows: list[Finding],
    data: dict[str, Any],
    session: Session,
) -> None:
    expected: list[Finding] = []
    if tool == "yara-x":
        from bytasm.adapters.yara_result import YaraAdapterResult
        from bytasm.jobs.scan import _finding_rows

        expected = _finding_rows(
            YaraAdapterResult.model_validate(data), inv.run_id, inv.id, inv.rule_set_id or ""
        )
    else:
        if inv.rule_set is None:
            raise IntegrityError("Rule set missing")
        # Capa raw rule sources bind exact rule text; the snapshot digest is
        # separately verified by the caller. Compare its namespace and addresses.
        for name, source in data["rules"].items():
            matches = source["matches"]
            escaped = name.replace("~", "~0").replace("/", "~1")
            expected.append(
                Finding(
                    rule_id=name,
                    rule_namespace=source["meta"].get("namespace") or "",
                    match_count=len(matches),
                    evidence_truncated=len(matches) > 32,
                    evidence=[
                        Evidence(
                            kind="virtual_address",
                            pattern_id="function",
                            file_offset=None,
                            length=None,
                            virtual_address=m[0]["value"],
                            xor_key=None,
                            excerpt_hex="",
                            raw_json_pointer=f"/rules/{escaped}/matches/{i}/0",
                        )
                        for i, m in enumerate(matches[:32])
                    ],
                )
            )

    def projection(finding: Finding) -> tuple[Any, ...]:
        evidence = (
            finding.evidence
            if finding.id is None
            else list(
                session.scalars(
                    select(Evidence).where(Evidence.finding_id == finding.id).limit(641)
                )
            )
        )
        if len(evidence) > 640:
            raise IntegrityError("Evidence exceeds per-finding bound")
        return (
            finding.rule_namespace,
            finding.rule_id,
            finding.match_count,
            finding.evidence_truncated,
            sorted(
                (
                    e.raw_json_pointer,
                    e.kind,
                    e.pattern_id,
                    e.file_offset,
                    e.length,
                    e.virtual_address,
                    e.xor_key,
                    e.excerpt_hex,
                )
                for e in evidence
            ),
        )

    if len(rows) != len(expected) or sorted(map(projection, rows)) != sorted(
        map(projection, expected)
    ):
        raise IntegrityError("Normalized findings disagree with verified source")


def create_snapshot(
    ctx: AppContext,
    session: Session,
    version: SampleVersion,
    body: CreateReview,
    supersedes_id: str | None = None,
) -> Snapshot:
    import json

    # Bounded queries fail explicitly instead of silently excluding older sources.
    query = select(AnalysisRun).where(AnalysisRun.sample_version_id == version.id)
    if body.scope == "exact_run":
        query = query.where(AnalysisRun.id == body.run_id, AnalysisRun.kind == "analysis")
    runs = list(
        session.scalars(
            query.order_by(AnalysisRun.queued_at.desc(), AnalysisRun.id.desc()).limit(201)
        )
    )
    if len(runs) > 200:
        raise ValueError("Review source scan exceeds 200 runs; use an exact run")
    if body.scope == "exact_run" and not runs:
        raise LookupError("Exact run is not part of this version")
    sample_bytes = bounded_read(ctx.blobs, version.sha256, ctx.settings.max_upload_bytes)
    if len(sample_bytes) != version.size_bytes:
        raise IntegrityError("Sample size changed")
    sources: list[Source] = []
    chosen: dict[ToolName, ToolInvocation] = {}
    verified_data: dict[str, dict[str, Any]] = {}
    unknowns = [
        "No runtime behavior, publisher authenticity or safety verdict was established.",
        "Bundled coverage: five demonstration YARA rules and two capa rules; "
        "not comprehensive screening.",
    ]
    # Exact-run mode includes no import invocation: metadata is separately identified
    # by the sample identity and is not misrepresented as a check in that run.
    for tool in TOOLS:
        candidates: list[tuple[AnalysisRun, ToolInvocation | None, str]] = []
        for run in runs:
            if run.kind == "import":
                candidates.extend(
                    (run, inv, inv.status) for inv in run.invocations if inv.tool_name == tool
                )
            else:
                candidates.extend(
                    (run, v.invocation, v.status) for v in step_views(run) if v.tool == tool
                )
        latest = None
        if candidates:
            r, inv, status = candidates[0]
            latest = Attempt(
                run_id=r.id,
                invocation_id=inv.id if inv else None,
                run_status=r.status,
                status=status,
            )
        selected = None
        for run, inv, _ in candidates:
            if inv is None or inv.status != "succeeded" or run.status in {"queued", "running"}:
                continue
            if inv.run_id != run.id or inv.tool_name != tool:
                raise IntegrityError("Invocation tool/run identity mismatch")
            if not inv.raw_output_sha256:
                raise IntegrityError("Completed output identity is missing")
            raw = bounded_read(ctx.outputs, inv.raw_output_sha256, MAX_SOURCE_BYTES)
            data = json.loads(raw)
            if tool == "ghidra":
                from bytasm.api.ghidra import _read

                ghidra_result = _read(ctx, run, inv)
            elif tool == "capa":
                from bytasm.adapters.capa_result import CapaResult
                from bytasm.adapters.capa_scan import normalize

                if not inv.rule_set or inv.rule_set.tool != "capa":
                    raise IntegrityError("Capa rule source missing")
                parsed_capa = CapaResult.model_validate(
                    normalize(raw.decode(), version.sha256, inv.rule_set.sha256)
                )
                if (
                    parsed_capa.sample_sha256 != version.sha256
                    or parsed_capa.tool_version != inv.tool_version
                ):
                    raise IntegrityError("Capa source identity mismatch")
            else:
                from bytasm.adapters.result import AdapterResult
                from bytasm.adapters.strings_result import StringsAdapterResult
                from bytasm.adapters.yara_result import YaraAdapterResult

                parsed = (
                    AdapterResult.model_validate_json(raw)
                    if tool == "lief"
                    else StringsAdapterResult.model_validate_json(raw)
                    if tool == "strings"
                    else YaraAdapterResult.model_validate_json(raw)
                )
                if (
                    parsed.input is None
                    or parsed.input.sha256 != version.sha256
                    or parsed.input.size_bytes != version.size_bytes
                    or parsed.tool_version != inv.tool_version
                    or parsed.adapter_version != inv.adapter_version
                    or parsed.adapter != inv.adapter_name
                ):
                    raise IntegrityError("Output source identity mismatch")
            rules = session.get(RuleSet, inv.rule_set_id) if inv.rule_set_id else None
            if tool in {"yara-x", "capa"} and (rules is None or rules.tool != tool):
                raise IntegrityError("Rule source missing or tool mismatch")
            if rules is not None:
                profile_ref: dict[str, Any] = next(
                    (
                        v.step.get("rule_set", {})
                        for v in step_views(run)
                        if v.index == inv.step_index and v.tool == tool
                    ),
                    {},
                )
                if (
                    profile_ref.get("id") != rules.id
                    or profile_ref.get("sha256") != rules.sha256
                    or inv.args.get("rule_set_sha256") != rules.sha256
                ):
                    raise IntegrityError("Rule profile/invocation identity mismatch")
            if tool == "yara-x":
                from bytasm.adapters.yara_result import YaraAdapterResult
                from bytasm.jobs.scan import evidence_is_consistent

                parsed_yara = YaraAdapterResult.model_validate_json(raw)
                if (
                    rules is None
                    or parsed_yara.rules.sha256 != rules.sha256
                    or parsed_yara.mode != "scan"
                    or not parsed_yara.rules.compiled
                    or not evidence_is_consistent(parsed_yara, sample_bytes)
                ):
                    raise IntegrityError("YARA rule or evidence identity mismatch")
            if rules and tool == "capa" and parsed_capa.rules_sha256 != rules.sha256:
                raise IntegrityError("Capa rule identity mismatch")
            if rules:
                snapshot_bytes = bounded_read(ctx.outputs, rules.sha256, MAX_SOURCE_BYTES)
                if tool == "capa":
                    packaged = json.loads(snapshot_bytes)
                    for finding_capa in parsed_capa.findings:
                        if (
                            packaged.get(finding_capa.name.replace(" ", "-") + ".yml")
                            != finding_capa.source
                        ):
                            raise IntegrityError("Capa rule source differs from snapshot")
            selected = Selected(
                run_id=run.id,
                invocation_id=inv.id,
                run_status=run.status,
                status=inv.status,
                output_sha256=inv.raw_output_sha256,
                tool_version=inv.tool_version,
                adapter=inv.adapter_name,
                adapter_version=inv.adapter_version,
                rule_sha256=rules.sha256 if rules else None,
                profile=run.profile_snapshot,
                parameters=inv.args,
                limits=inv.summary,
                retention={
                    **(
                        {
                            "function_count": ghidra_result.function_count,
                            "retained_functions": len(ghidra_result.functions),
                            "functions_truncated": ghidra_result.functions_truncated,
                            "analysis_timed_out": ghidra_result.analysis_timed_out,
                            "instructions_capped": any(
                                f.instructions_truncated for f in ghidra_result.functions
                            ),
                            "calls_capped": any(f.calls_truncated for f in ghidra_result.functions),
                            "pseudocode_capped": any(
                                f.pseudocode_truncated for f in ghidra_result.functions
                            ),
                        }
                        if tool == "ghidra"
                        else {}
                    ),
                    **{
                        key: data[key]
                        for key in (
                            "params",
                            "total_found",
                            "truncated",
                            "coverage",
                            "limits",
                            "counts",
                        )
                        if key in data
                    },
                },
                warnings=list(inv.warnings),
            )
            chosen[tool] = inv
            verified_data[tool] = data
            break
        reason = None if selected else "No completed compatible source retained in this scope."
        sources.append(
            Source(tool=tool, selected=selected, latest_attempt=latest, unavailable_reason=reason)
        )
        if reason:
            unknowns.append(f"{tool}: {reason}")
        elif latest and selected and latest.run_id != selected.run_id:
            unknowns.append(f"{tool}: older evidence retained; latest attempt is {latest.status}.")
    observations = []
    total = 0
    for tool, inv in chosen.items():
        if tool not in {"yara-x", "capa"}:
            continue
        rows = list(
            session.scalars(
                select(Finding)
                .where(
                    Finding.invocation_id == inv.id,
                )
                .order_by(Finding.id)
                .limit(49)
            )
        )
        # Reconcile the normalized projection with the verified source document,
        # including omitted/extra finding rows, not just the displayed first four locations.
        validate_finding_rows(tool, inv, rows, verified_data[tool], session)
        total += len(rows)
        for finding in rows[:48]:
            if finding.run_id != inv.run_id or finding.rule_set_id != inv.rule_set_id:
                raise IntegrityError("Finding source mismatch")
            rules = session.get_one(RuleSet, finding.rule_set_id)
            evidence = list(
                session.scalars(
                    select(Evidence)
                    .where(Evidence.finding_id == finding.id)
                    .order_by(Evidence.id)
                    .limit(5)
                )
            )
            observations.append(make_observation(finding, inv, rules, evidence))
    observations.sort(key=lambda o: (-o.relevance, o.tool, o.rule_id, o.id))
    import_observations = []
    if "lief" in chosen:
        from bytasm.import_catalog import classify_imports

        metadata_source = chosen["lief"]
        import_observations = [
            ImportObservation(
                **record,
                run_id=metadata_source.run_id,
                invocation_id=metadata_source.id,
                output_sha256=metadata_source.raw_output_sha256 or "",
            )
            for record in classify_imports(
                verified_data["lief"]["metadata"]["imports"]["functions"],
                metadata_source.tool_version,
                metadata_source.adapter_version,
            )
        ]
    strings = []
    if "strings" in chosen:
        inv = chosen["strings"]
        rows_text = list(
            session.scalars(
                select(StringOccurrence)
                .where(
                    StringOccurrence.invocation_id == inv.id,
                )
                .order_by(StringOccurrence.id)
                .limit(5001)
            )
        )
        if len(rows_text) > 5000:
            raise IntegrityError("Retained text exceeds contract")
        from bytasm.adapters.strings_result import StringsAdapterResult
        from bytasm.jobs.strings_step import strings_are_consistent

        expected_text = StringsAdapterResult.model_validate(verified_data["strings"])
        if not strings_are_consistent(expected_text, sample_bytes):
            raise IntegrityError("Text is not supported by sample bytes")
        actual_text = sorted(
            (r.file_offset, r.encoding, r.value, r.length_chars, r.byte_length, r.value_truncated)
            for r in rows_text
        )
        wanted_text = sorted(
            (r.offset, r.encoding, r.value, r.length_chars, r.byte_length, r.value_truncated)
            for r in expected_text.strings
        )
        if actual_text != wanted_text:
            raise IntegrityError("Normalized text does not match verified output")
        strings = [
            TextRecord(
                id=r.id,
                invocation_id=inv.id,
                offset=r.file_offset,
                encoding=r.encoding,
                value=r.value,
                value_truncated=r.value_truncated,
            )
            for r in rows_text
        ]
    function_reviews = []
    if "ghidra" in chosen:
        # Select latest immutable revision per exact function scope at pin time.
        from sqlalchemy import func

        from bytasm.db.models import FunctionReviewRevision

        latest_revisions = (
            select(
                FunctionReviewRevision.scope_sha256,
                func.max(FunctionReviewRevision.revision).label("revision"),
            )
            .where(FunctionReviewRevision.invocation_id == chosen["ghidra"].id)
            .group_by(FunctionReviewRevision.scope_sha256)
            .subquery()
        )
        overlays = list(
            session.scalars(
                select(FunctionReviewRevision)
                .join(
                    latest_revisions,
                    (FunctionReviewRevision.scope_sha256 == latest_revisions.c.scope_sha256)
                    & (FunctionReviewRevision.revision == latest_revisions.c.revision),
                )
                .limit(129)
            )
        )
        if len(overlays) > 128:
            raise ValueError("Review exceeds 128 function overlays")
        from bytasm.function_review import validated_overlay

        for row in overlays:
            document = validated_overlay(row)
            identity = document["identity"]
            if (
                identity["sample_sha256"] != version.sha256
                or identity["run_id"] != chosen["ghidra"].run_id
                or identity["output_sha256"] != chosen["ghidra"].raw_output_sha256
            ):
                raise IntegrityError("Overlay source identity changed")
            function_reviews.append(document)
    result = Snapshot(
        id=new_id(),
        supersedes_id=supersedes_id,
        created_at=datetime.now(UTC),
        sample=Identity(
            version_id=version.id,
            sample_id=version.sample_id,
            sha256=version.sha256,
            size_bytes=version.size_bytes,
            format=version.detected_format,
        ),
        scope=body.scope,
        exact_run_id=body.run_id,
        sources=sources,
        observations=observations[:48],
        observations_total=total,
        observations_capped=total > 48,
        import_observations=import_observations,
        strings=strings,
        unknowns=unknowns,
        selection_explanation=(
            "Reviewed code features precede text and structural context, then unreviewed matches. "
            "Repeated locations do not increase relevance. "
            "Scores are reading order, not threat probability. "
            "Each selected source is the newest completed step of its tool in a terminal run. "
            "Tools need not have run together. Refresh creates a new snapshot."
        ),
        declared_filename=version.declared_filename,
        function_reviews=function_reviews,
    )
    raw = canonical_json(result.model_dump(mode="json"))
    if len(raw) > MAX_REVIEW_BYTES:
        raise ValueError("Review exceeds 4 MiB; nothing was saved")
    session.add(
        ReviewSnapshot(
            id=result.id,
            version_id=version.id,
            supersedes_id=supersedes_id,
            created_at=result.created_at,
            sha256=hashlib.sha256(raw).hexdigest(),
            canonical=raw.decode(),
        )
    )
    return result


def read_snapshot(session: Session, review_id: str) -> tuple[Snapshot, str]:
    row = session.get(ReviewSnapshot, review_id)
    if row is None:
        raise LookupError("No review")
    raw = row.canonical.encode()
    if len(raw) > MAX_REVIEW_BYTES or hashlib.sha256(raw).hexdigest() != row.sha256:
        raise IntegrityError("Review changed")
    result = Snapshot.model_validate_json(raw)
    if result.id != row.id or result.sample.version_id != row.version_id:
        raise IntegrityError("Review identity changed")
    return result, row.sha256


if __name__ == "__main__":
    import json

    print(json.dumps(Snapshot.model_json_schema(), indent=2, sort_keys=True))
