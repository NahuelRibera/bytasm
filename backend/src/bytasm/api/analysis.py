"""v0.2 endpoints: the bundled rule set, analysis runs, and findings (blueprint 7.2).

The API never runs YARA-X on a sample. Creating a run only records it as
`queued` (after checking the input policy and the stored file's SHA-256, so an
obviously unusable run is refused at once); the worker process executes it
(bytasm.jobs). The one YARA-X child the API starts itself is the rule-set
check, which compiles Bytasm's own rules and sees no sample bytes; it uses the
same single parser slot as imports.

All rule text, rule metadata, identifiers and match excerpts in responses are
data for the UI to display as escaped text.
"""

import json
import logging
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from bytasm.adapters.strings_result import ENCODINGS, MAX_STRINGS, MIN_LENGTH
from bytasm.adapters.yara_result import MAX_EXCERPT_BYTES
from bytasm.api.context import AppContext
from bytasm.api.problems import problem
from bytasm.api.schemas import (
    DiagnosticOut,
    EvidenceOut,
    FindingOut,
    FindingsFilterOut,
    FindingsOut,
    RuleFileOut,
    RuleSetOut,
    RuleSetRef,
    RuleValidationOut,
    RunCounts,
    RunCreate,
    RunLogEntryOut,
    RunLogOut,
    RunOut,
    RunSampleOut,
    RunsOut,
    RunStepOut,
    StringOut,
    StringsOut,
    StringsSummaryOut,
)
from bytasm.db.models import (
    AnalysisRun,
    Evidence,
    Finding,
    RuleSet,
    SampleVersion,
    StringOccurrence,
    ToolInvocation,
)
from bytasm.jobs import messages, runs, summary
from bytasm.jobs.scan import (
    expected_identifiers,
    parse_yara_result,
    write_rules,
    yara_argv,
    yara_x_installed_version,
)
from bytasm.notices import FINDING_NOTICES, STRINGS_NOTICES
from bytasm.rules import RuleSetError, load_rule_set, split_snapshot
from bytasm.runner import workspace
from bytasm.runner.supervisor import run_child
from bytasm.storage import IntegrityError

router = APIRouter()
log = logging.getLogger("bytasm.analysis")

MAX_LISTED_RUNS = 50
# Every finding so far comes from the YARA-X step.
FINDING_TOOL = "yara-x"


def _ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def _rid(request: Request) -> str:
    request_id: str = request.state.request_id
    return request_id


def _not_found(request: Request, what: str) -> JSONResponse:
    return problem("not_found", detail=f"No {what} with this ID.", request_id=_rid(request))


# --- rule set ---------------------------------------------------------------


@router.get("/rule-sets/current", response_model=RuleSetOut)
def current_rule_set(request: Request) -> RuleSetOut | JSONResponse:
    ctx = _ctx(request)
    try:
        rule_set = load_rule_set(ctx.settings.rules_dir)
    except RuleSetError as error:
        log.error(json.dumps({"event": "rules_unavailable", "error": str(error)}))
        return problem("rules_unavailable", request_id=_rid(request))
    with ctx.sessions() as session:
        stored_id = session.scalar(select(RuleSet.id).where(RuleSet.sha256 == rule_set.sha256))
    return RuleSetOut(
        id=stored_id,
        tool="yara-x",
        name=rule_set.name,
        version=rule_set.version,
        label=rule_set.label,
        sha256=rule_set.sha256,
        source="bytasm-repo",
        current=True,
        rule_count=len(rule_set.files),
        files=[
            RuleFileOut(name=f.name, identifier=f.identifier, text=f.text) for f in rule_set.files
        ],
        installed_yara_x_version=yara_x_installed_version(),
    )


@router.get("/rule-sets/{rule_set_id}", response_model=RuleSetOut)
def stored_rule_set(request: Request, rule_set_id: str) -> RuleSetOut | JSONResponse:
    """A rule set some run used, with the exact text from its stored snapshot."""
    ctx = _ctx(request)
    with ctx.sessions() as session:
        row = session.get(RuleSet, rule_set_id)
        if row is None:
            return _not_found(request, "rule set")
        name, version, sha256 = row.name, row.version, row.sha256
    try:
        snapshot = ctx.outputs.read_verified(sha256)
    except IntegrityError:
        return problem(
            "integrity_error",
            detail="The stored copy of this rule set no longer matches its SHA-256.",
            request_id=_rid(request),
        )
    try:
        current_sha = load_rule_set(ctx.settings.rules_dir).sha256
    except RuleSetError:
        current_sha = None
    files = split_snapshot(snapshot)
    return RuleSetOut(
        id=rule_set_id,
        tool="yara-x",
        name=name,
        version=version,
        label=f"{name}@{version}",
        sha256=sha256,
        source="bytasm-repo",
        current=current_sha == sha256,
        rule_count=len(files),
        files=[
            RuleFileOut(name=n, identifier=n.removesuffix(".yar"), text=t) for n, t in files.items()
        ],
        installed_yara_x_version=yara_x_installed_version(),
    )


@router.post("/rule-sets/current/validation", response_model=RuleValidationOut)
async def validate_rule_set(request: Request) -> RuleValidationOut | JSONResponse:
    """Compile the bundled rule set with the pinned YARA-X, in a child process."""
    ctx = _ctx(request)
    try:
        rule_set = load_rule_set(ctx.settings.rules_dir)
    except RuleSetError as error:
        log.error(json.dumps({"event": "rules_unavailable", "error": str(error)}))
        return problem("rules_unavailable", request_id=_rid(request))
    if not ctx.parser_slot.try_acquire():
        return problem("parser_busy", request_id=_rid(request), headers={"Retry-After": "5"})
    try:
        workdir = workspace.create_workdir(ctx.tmp_dir)
        try:
            write_rules(workdir, rule_set.snapshot)
            outcome = await run_child(
                yara_argv(ctx.yara_command, ctx.settings.limits, rule_set.sha256, None),
                workdir,
                ctx.settings.limits,
                parse_result=lambda raw: parse_yara_result(raw, rule_set.sha256, None),
            )
        finally:
            workspace.remove_workdir(workdir)
    finally:
        ctx.parser_slot.release()
    result = outcome.result
    if result is None:
        log.warning(
            json.dumps({"event": "rule_check", "status": outcome.status, "reason": outcome.reason})
        )
        return problem("rule_check_failed", request_id=_rid(request))
    compiled = set(result.rules.rule_identifiers)
    problems = (
        [
            f"{name}.yar: no rule named {name!r} was compiled from this file"
            for name in sorted(expected_identifiers(rule_set.snapshot) - compiled)
        ]
        if result.rules.compiled
        else []
    )
    return RuleValidationOut(
        rule_set_sha256=rule_set.sha256,
        label=rule_set.label,
        yara_x_version=result.tool_version,
        compiled=result.rules.compiled and not problems,
        rule_identifiers=sorted(compiled),
        problems=problems,
        errors=[DiagnosticOut(**d.model_dump()) for d in result.rules.errors],
        warnings=[DiagnosticOut(**d.model_dump()) for d in result.rules.warnings],
        duration_ms=outcome.duration_ms,
    )


# --- runs -------------------------------------------------------------------


def _strings_summary(invocation: ToolInvocation | None) -> StringsSummaryOut | None:
    if invocation is None or invocation.summary is None or invocation.status != "succeeded":
        return None
    return StringsSummaryOut(**invocation.summary)


def run_out(session: Session, run: AnalysisRun) -> RunOut:
    version = run.sample_version
    sample = version.sample
    rule_step = runs.rule_set_step(run.profile_snapshot) or {}
    rule_set = rule_step.get("rule_set", {"id": "", "label": "", "sha256": ""})
    finding_count = session.scalar(
        select(func.count()).select_from(Finding).where(Finding.run_id == run.id)
    )
    evidence_count = session.scalar(
        select(func.count())
        .select_from(Evidence)
        .join(Finding, Evidence.finding_id == Finding.id)
        .where(Finding.run_id == run.id)
    )
    string_count = session.scalar(
        select(func.count())
        .select_from(StringOccurrence)
        .join(ToolInvocation, StringOccurrence.invocation_id == ToolInvocation.id)
        .where(ToolInvocation.run_id == run.id)
    )
    views = summary.step_views(run)
    return RunOut(
        id=run.id,
        status=run.status,  # type: ignore[arg-type]  # constrained by the lifecycle
        failure_reason=run.failure_reason,
        failure_message=summary.run_message(run, views),
        cancel_requested=run.cancel_requested,
        queued_at=run.queued_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        bytasm_version=run.bytasm_version,
        profile_id=str(run.profile_snapshot.get("id", runs.PROFILE_ID)),
        profile_name=str(run.profile_snapshot.get("name", "")),
        rule_set=RuleSetRef(
            id=str(rule_set["id"]), label=str(rule_set["label"]), sha256=str(rule_set["sha256"])
        ),
        sample=RunSampleOut(
            project_id=sample.project_id,
            project_name=sample.project.name,
            sample_id=sample.id,
            sample_name=sample.name,
            version_id=version.id,
            version_label=version.version_label,
            sha256=version.sha256,
            size_bytes=version.size_bytes,
            detected_format=version.detected_format,
            admitted_under=version.admitted_under,
        ),
        steps=[
            RunStepOut(
                index=view.index,
                tool=view.tool,
                adapter=view.adapter,
                status=view.status,  # type: ignore[arg-type]  # from the lifecycle
                message=view.message,
                invocation_id=view.invocation.id if view.invocation else None,
                tool_version=view.invocation.tool_version if view.invocation else None,
                adapter_version=view.invocation.adapter_version if view.invocation else None,
                started_at=view.invocation.started_at if view.invocation else None,
                finished_at=view.invocation.finished_at if view.invocation else None,
                duration_ms=view.invocation.duration_ms if view.invocation else None,
                timeout_seconds=float(view.step.get("timeout_seconds", 0)),
                failure_reason=view.invocation.failure_reason if view.invocation else None,
                raw_output_sha256=view.invocation.raw_output_sha256 if view.invocation else None,
                strings=_strings_summary(view.invocation),
                warnings=list(view.invocation.warnings) if view.invocation else [],
            )
            for view in views
        ],
        counts=RunCounts(
            findings=finding_count or 0, evidence=evidence_count or 0, strings=string_count or 0
        ),
    )


def _get_run(session: Session, run_id: str) -> AnalysisRun | None:
    run = session.get(AnalysisRun, run_id)
    return run if run is not None and run.kind == "analysis" else None


class _Refused(Exception):
    def __init__(
        self, code: str, detail: str | None = None, extra: dict[str, object] | None = None
    ):
        super().__init__(code)
        self.code, self.detail, self.extra = code, detail, extra


def _create_run(ctx: AppContext, version_id: str) -> str:
    """Check, then record a queued run in one transaction. Returns its ID."""
    with ctx.sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            raise _Refused("not_found", "No sample version with this ID.")
        sha256 = version.sha256
        if runs.active_run_id(session, version_id) is not None:
            raise _Refused("run_active", extra={"run_id": runs.active_run_id(session, version_id)})
    # The same checks the worker repeats right before YARA-X sees the bytes.
    if ctx.policy.admit(sha256) is None:
        raise _Refused(
            "input_policy",
            "The current input policy does not admit this sample, so it cannot be analysed.",
        )
    try:
        ctx.blobs.verify(sha256)
    except IntegrityError as exc:
        raise _Refused(
            "integrity_error",
            "The stored sample no longer matches its recorded SHA-256, so it cannot be "
            "analysed. Re-import the original file into a new sample.",
        ) from exc
    try:
        rule_set = load_rule_set(ctx.settings.rules_dir)
    except RuleSetError as exc:
        log.error(json.dumps({"event": "rules_unavailable", "error": str(exc)}))
        raise _Refused("rules_unavailable") from exc

    scratch = workspace.create_workdir(ctx.tmp_dir)
    created_snapshot = False
    session = ctx.sessions()
    try:
        created_snapshot = ctx.outputs.put_bytes(rule_set.snapshot, rule_set.sha256, scratch)
        row = session.scalar(select(RuleSet).where(RuleSet.sha256 == rule_set.sha256))
        if row is None:
            row = RuleSet(
                tool="yara-x",
                name=rule_set.name,
                version=rule_set.version,
                sha256=rule_set.sha256,
                source="bytasm-repo",
                snapshot_path=ctx.outputs.relative_path(rule_set.sha256),
                rule_count=len(rule_set.files),
            )
            session.add(row)
            session.flush()
        # Checked again inside the write transaction (SQLite serialises writers).
        active = runs.active_run_id(session, version_id)
        if active is not None:
            raise _Refused("run_active", extra={"run_id": active})
        # Microseconds kept, so runs queued in the same second keep their order.
        run = runs.new_queued_run(
            version_id,
            runs.profile_snapshot(row, ctx.settings.limits.timeout_seconds),
            datetime.now(UTC),
        )
        session.add(run)
        session.commit()
        return run.id
    except BaseException:
        session.rollback()
        still_used = session.scalar(select(RuleSet.id).where(RuleSet.sha256 == rule_set.sha256))
        if created_snapshot and still_used is None:
            ctx.outputs.remove(rule_set.sha256)
        raise
    finally:
        session.close()
        workspace.remove_workdir(scratch)


@router.post("/sample-versions/{version_id}/runs", response_model=RunOut, status_code=202)
async def create_run(request: Request, version_id: str, body: RunCreate) -> RunOut | JSONResponse:
    ctx = _ctx(request)
    try:
        run_id = await run_in_threadpool(_create_run, ctx, version_id)
    except _Refused as refusal:
        log.info(
            json.dumps({"event": "run_create", "outcome": refusal.code, "version": version_id})
        )
        return problem(
            refusal.code, detail=refusal.detail, extra=refusal.extra, request_id=_rid(request)
        )
    log.info(json.dumps({"event": "run_create", "outcome": "queued", "run_id": run_id}))
    with ctx.sessions() as session:
        return run_out(session, session.get_one(AnalysisRun, run_id))


@router.get("/sample-versions/{version_id}/runs", response_model=RunsOut)
def list_runs(request: Request, version_id: str) -> RunsOut | JSONResponse:
    with _ctx(request).sessions() as session:
        if session.get(SampleVersion, version_id) is None:
            return _not_found(request, "sample version")
        rows = session.scalars(
            select(AnalysisRun)
            .where(AnalysisRun.sample_version_id == version_id, AnalysisRun.kind == "analysis")
            .order_by(AnalysisRun.queued_at.desc(), AnalysisRun.id.desc())
            .limit(MAX_LISTED_RUNS)
        )
        return RunsOut(runs=[run_out(session, run) for run in rows])


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(request: Request, run_id: str) -> RunOut | JSONResponse:
    with _ctx(request).sessions() as session:
        run = _get_run(session, run_id)
        if run is None:
            return _not_found(request, "run")
        return run_out(session, run)


@router.post("/runs/{run_id}/cancel", response_model=RunOut, status_code=202)
def cancel_run(request: Request, run_id: str) -> RunOut | JSONResponse:
    with _ctx(request).sessions() as session:
        outcome = runs.request_cancel(session, run_id)
        if outcome == "not_found":
            return _not_found(request, "run")
        if outcome == "finished":
            return problem("run_finished", request_id=_rid(request))
        log.info(json.dumps({"event": "run_cancel", "outcome": outcome, "run_id": run_id}))
        session.expire_all()
        return run_out(session, session.get_one(AnalysisRun, run_id))


def _finding_out(finding: Finding) -> FindingOut:
    attributes = finding.tool_reported_attributes
    return FindingOut(
        id=finding.id,
        kind="yara_match",
        title=finding.title,
        rule_id=finding.rule_id,
        rule_namespace=finding.rule_namespace,
        rule_set_id=finding.rule_set_id,
        tags=[str(tag) for tag in attributes.get("tags", [])],
        metadata=[(str(key), value) for key, value in attributes.get("metadata", [])],
        fingerprint=finding.fingerprint,
        match_count=finding.match_count,
        evidence_truncated=finding.evidence_truncated,
        evidence=[
            EvidenceOut(
                id=item.id,
                kind="byte_range",
                pattern_id=item.pattern_id,
                file_offset=item.file_offset,
                length=item.length,
                xor_key=item.xor_key,
                excerpt_hex=item.excerpt_hex,
                excerpt_truncated=item.length > MAX_EXCERPT_BYTES,
                raw_json_pointer=item.raw_json_pointer,
            )
            for item in finding.evidence
        ],
    )


MAX_QUERY = 128


@router.get("/runs/{run_id}/findings", response_model=FindingsOut)
def run_findings(
    request: Request,
    run_id: str,
    tool: Annotated[Literal["yara-x"] | None, Query()] = None,
    kind: Annotated[Literal["yara_match"] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=MAX_QUERY)] = None,
) -> FindingsOut | JSONResponse:
    """A run's findings, optionally filtered by tool, kind, and a text search.

    `q` matches, case-insensitively, the rule identifier, title, or a tag.
    There is no review-state filter: review states arrive with annotations (v0.3).
    """
    needle = (q or "").strip().casefold()
    with _ctx(request).sessions() as session:
        run = _get_run(session, run_id)
        if run is None:
            return _not_found(request, "run")
        findings = list(
            session.scalars(
                select(Finding)
                .where(Finding.run_id == run_id)
                .order_by(Finding.rule_namespace, Finding.rule_id)
            )
        )
        tools = {f.id: FINDING_TOOL for f in findings}

        def keep(finding: Finding) -> bool:
            if tool is not None and tools[finding.id] != tool:
                return False
            if kind is not None and finding.kind != kind:
                return False
            if not needle:
                return True
            tags = [str(t) for t in finding.tool_reported_attributes.get("tags", [])]
            haystack = [finding.rule_id, finding.title, *tags]
            return any(needle in text.casefold() for text in haystack)

        views = summary.step_views(run)
        return FindingsOut(
            run_id=run_id,
            run_status=run.status,
            run_message=summary.run_message(run, views),
            total=len(findings),
            filters=FindingsFilterOut(tool=tool, kind=kind, q=needle or None),
            available_tools=sorted(set(tools.values())),
            available_kinds=sorted({f.kind for f in findings}),
            findings=[_finding_out(f) for f in findings if keep(f)],
            notices=list(FINDING_NOTICES),
        )


# --- strings (observations) -------------------------------------------------

MAX_STRINGS_PAGE = 200


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/sample-versions/{version_id}/strings", response_model=StringsOut)
def version_strings(
    request: Request,
    version_id: str,
    query: Annotated[str | None, Query(max_length=MAX_QUERY)] = None,
    encoding: Annotated[Literal["ascii", "utf-16le"] | None, Query()] = None,
    run_id: Annotated[str | None, Query(max_length=32)] = None,
    offset: Annotated[int, Query(ge=0, le=MAX_STRINGS)] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_STRINGS_PAGE)] = 100,
) -> StringsOut | JSONResponse:
    """Strings found by the newest run whose strings step succeeded (or by `run_id`).

    `query` is a case-insensitive substring of the stored value. Values are
    untrusted text; the UI shows them as plain text.
    """
    needle = (query or "").strip()
    with _ctx(request).sessions() as session:
        if session.get(SampleVersion, version_id) is None:
            return _not_found(request, "sample version")
        conditions = [
            AnalysisRun.sample_version_id == version_id,
            AnalysisRun.kind == "analysis",
            ToolInvocation.tool_name == runs.STRINGS_TOOL,
            ToolInvocation.status == "succeeded",
        ]
        if run_id is not None:
            conditions.append(AnalysisRun.id == run_id)
        invocation = session.scalar(
            select(ToolInvocation)
            .join(AnalysisRun, ToolInvocation.run_id == AnalysisRun.id)
            .where(*conditions)
            .order_by(AnalysisRun.queued_at.desc(), AnalysisRun.id.desc())
            .limit(1)
        )
        if invocation is None and run_id is not None:
            return _not_found(request, "strings for this run")
        items: list[StringOut] = []
        matched = 0
        if invocation is not None:
            filters = [StringOccurrence.invocation_id == invocation.id]
            if needle:
                filters.append(
                    StringOccurrence.value.ilike(f"%{_escape_like(needle)}%", escape="\\")
                )
            if encoding is not None:
                filters.append(StringOccurrence.encoding == encoding)
            matched = (
                session.scalar(select(func.count()).select_from(StringOccurrence).where(*filters))
                or 0
            )
            rows = session.scalars(
                select(StringOccurrence)
                .where(*filters)
                .order_by(StringOccurrence.file_offset, StringOccurrence.encoding)
                .offset(offset)
                .limit(limit)
            )
            items = [
                StringOut(
                    offset=row.file_offset,
                    encoding=row.encoding,  # type: ignore[arg-type]  # checked by the worker
                    length_chars=row.length_chars,
                    byte_length=row.byte_length,
                    value=row.value,
                    value_truncated=row.value_truncated,
                )
                for row in rows
            ]
        return StringsOut(
            version_id=version_id,
            run_id=invocation.run_id if invocation else None,
            run_status=invocation.run.status if invocation else None,
            invocation_id=invocation.id if invocation else None,
            tool_version=invocation.tool_version if invocation else None,
            min_length=MIN_LENGTH,
            encodings=list(ENCODINGS),
            summary=_strings_summary(invocation),
            query=needle or None,
            encoding=encoding,
            matched=matched,
            offset=offset,
            limit=limit,
            items=items,
            notices=list(STRINGS_NOTICES),
        )


# --- raw tool output and technical log --------------------------------------


@router.get("/invocations/{invocation_id}/raw")
def invocation_raw_output(request: Request, invocation_id: str) -> Response:
    """The tool's validated result document, as stored, as a JSON attachment.

    It is the bounded `result.json` the adapter child wrote and the parent
    validated (never sample bytes, never stdout/stderr), re-hashed before it
    is served; a mismatch is 409 and nothing is sent.
    """
    ctx = _ctx(request)
    with ctx.sessions() as session:
        invocation = session.get(ToolInvocation, invocation_id)
        if invocation is None or invocation.raw_output_sha256 is None:
            return _not_found(request, "stored raw output for this tool invocation")
        sha256, tool = invocation.raw_output_sha256, invocation.tool_name
    try:
        data = ctx.outputs.read_verified(sha256)
    except IntegrityError:
        return problem(
            "integrity_error",
            detail="The stored tool output no longer matches its SHA-256, so it was not sent.",
            request_id=_rid(request),
        )
    safe_tool = "".join(ch for ch in tool if ch.isalnum() or ch == "-")[:16] or "tool"
    filename = f"bytasm-{safe_tool}-output-{invocation_id[:12]}-{sha256[:8]}.json"
    return Response(
        data,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Bytasm-Raw-SHA256": sha256,
        },
    )


def _log_entries(run: AnalysisRun, views: list[summary.StepView]) -> list[RunLogEntryOut]:
    """The run's technical log, rebuilt from recorded times and fixed texts."""
    entries: list[tuple[datetime | None, int | None, str]] = [
        (run.queued_at, None, f"Run queued with profile {run.profile_snapshot.get('id', '')}.")
    ]
    if run.started_at is not None:
        entries.append((run.started_at, None, "A worker claimed the run."))
    for view in views:
        label = f"Step {view.index + 1} ({messages.short_label(view.tool)})"
        inv = view.invocation
        if inv is not None:
            entries.append(
                (
                    inv.started_at,
                    view.index,
                    f"{label} started: {inv.tool_name} "
                    f"{inv.tool_version}, adapter {inv.adapter_name} {inv.adapter_version}.",
                )
            )
            text = f"{label} {inv.status.replace('_', ' ')} after {inv.duration_ms} ms"
            text += f" (exit code {inv.exit_code})." if inv.exit_code is not None else "."
            if inv.raw_output_sha256:
                text += f" Raw output SHA-256 {inv.raw_output_sha256}."
            if view.message:
                text += f" {view.message}"
            entries.append((inv.finished_at, view.index, text))
        elif view.status == "running":
            entries.append((None, view.index, f"{label} is running."))
        elif view.status == "skipped" and view.message:
            entries.append((run.finished_at, view.index, view.message))
    # Entries are in the order things happen in the lifecycle; stored times have
    # one-second resolution, so they label entries but do not order them.
    if run.cancel_requested_at is not None:
        position = next(
            (
                i
                for i, (at, step, _) in enumerate(entries)
                if step is not None and at is not None and at > run.cancel_requested_at
            ),
            len(entries),
        )
        entries.insert(position, (run.cancel_requested_at, None, "Cancel requested."))
    if run.status in runs.TERMINAL:
        entries.append((run.finished_at, None, f"Run finished: {run.status}."))
    ordered = list(enumerate(entries))
    return [
        RunLogEntryOut(seq=seq, at=at, step_index=step, message=message)
        for seq, (at, step, message) in ordered
    ]


@router.get("/runs/{run_id}/log", response_model=RunLogOut)
def run_log(
    request: Request,
    run_id: str,
    after: Annotated[int, Query(ge=-1, le=10_000)] = -1,
) -> RunLogOut | JSONResponse:
    """Technical log: what happened when, from fixed texts. No tool output is echoed."""
    with _ctx(request).sessions() as session:
        run = _get_run(session, run_id)
        if run is None:
            return _not_found(request, "run")
        entries = _log_entries(run, summary.step_views(run))
        return RunLogOut(
            run_id=run_id,
            entries=[entry for entry in entries if entry.seq > after],
            next_cursor=entries[-1].seq if entries else -1,
            complete=run.status in runs.TERMINAL,
        )
