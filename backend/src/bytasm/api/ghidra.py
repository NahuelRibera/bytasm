"""Run-scoped Ghidra evidence views. Stored outputs are revalidated before use."""

import hashlib
import json
import os
import stat
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from bytasm.api.context import AppContext
from bytasm.api.problems import problem
from bytasm.db.models import AnalysisRun, ToolInvocation
from bytasm.ghidra_protocol import Address, Function, GhidraResult
from bytasm.jobs import summary
from bytasm.reports.ghidra import canonical_json, html_export
from bytasm.storage import IntegrityError

router = APIRouter()
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


class ClaimOut(BaseModel):
    text: str
    citation: str


class ExplanationOut(BaseModel):
    observations: list[ClaimOut]
    hypotheses: list[str]
    analyst_notes: list[str]
    recommendations: list[str]
    limitations: list[str]


class CoverageOut(BaseModel):
    completed: int
    total: Literal[1] = 1


class ProvenanceOut(BaseModel):
    tool: Literal["ghidra"] = "ghidra"
    tool_version: str
    adapter_version: str
    profile_sha256: str
    script_sha256: str
    raw_output_sha256: str
    language_id: str
    compiler: str
    provider_host: dict[str, str]


class GhidraOverviewOut(BaseModel):
    run_id: str
    project_id: str
    version_id: str
    input_sha256: str
    run_status: str
    step_status: str
    invocation_id: str | None
    available: bool
    provenance: ProvenanceOut | None
    summary: ExplanationOut
    coverage: CoverageOut
    function_count: int | None
    stored_functions: int
    functions_truncated: bool


class FunctionItemOut(BaseModel):
    index: int
    entry: Address
    name: str
    name_truncated: bool = False
    namespace: str
    namespace_truncated: bool = False
    body_size: int | None
    external: bool = False
    pseudocode_status: Literal["available", "not_selected", "failed"]
    pseudocode_truncated: bool
    instructions_truncated: bool
    calls_truncated: bool


class FunctionDetailRecord(Function):
    limitations: list[str] = []


class FunctionPageOut(BaseModel):
    run_id: str
    matched: int
    total: int
    offset: int
    limit: int
    items: list[FunctionItemOut]


class FunctionDetailOut(BaseModel):
    run_id: str
    invocation_id: str
    index: int
    citation: str
    function: FunctionDetailRecord


def _ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def _failure(request: Request, code: str = "not_found") -> JSONResponse:
    return problem(code, request_id=request.state.request_id)


def _run(session: Session, run_id: str) -> AnalysisRun | None:
    run = session.get(AnalysisRun, run_id)
    return (
        run
        if run is not None
        and run.kind == "analysis"
        and run.profile_snapshot.get("id") == "ghidra-static"
        else None
    )


def _invocation(run: AnalysisRun) -> ToolInvocation | None:
    return next((inv for inv in run.invocations if inv.tool_name == "ghidra"), None)


def _read(ctx: AppContext, run: AnalysisRun, inv: ToolInvocation) -> GhidraResult:
    """Bound before allocation, reject links/FIFOs, hash and validate provenance."""
    if inv.status != "succeeded" or inv.raw_output_sha256 is None:
        raise IntegrityError("No completed Ghidra output")
    path = ctx.outputs.path(inv.raw_output_sha256)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DOCUMENT_BYTES:
                raise IntegrityError("Invalid Ghidra output")
            raw = handle.read(MAX_DOCUMENT_BYTES + 1)
        if (
            len(raw) > MAX_DOCUMENT_BYTES
            or hashlib.sha256(raw).hexdigest() != inv.raw_output_sha256
        ):
            raise IntegrityError("Invalid Ghidra output")
        result = GhidraResult.model_validate_json(raw)
        if (
            result.input_sha256 != run.sample_version.sha256
            or result.ghidra_version != inv.tool_version
            or result.profile_sha256 != inv.args.get("profile_sha256")
            or result.script_sha256 != inv.args.get("script_sha256")
        ):
            raise IntegrityError("Invalid Ghidra provenance")
        return result
    except (OSError, ValidationError, ValueError) as exc:
        raise IntegrityError("Invalid Ghidra output") from exc


def _overview(
    run: AnalysisRun, inv: ToolInvocation | None, result: GhidraResult | None
) -> GhidraOverviewOut:
    views = summary.step_views(run)
    status = views[0].status if views else "skipped"
    observations: list[ClaimOut] = []
    limits = [
        "The analysis did not inspect runtime behavior.",
        "Static call relationships do not prove that a call executes.",
        "Decompiler pseudocode is not original source code; missing output does not prove absence.",
        (
            "Compiler identifies Ghidra's selected compiler specification, "
            "not a verified original toolchain."
        ),
    ]
    provenance = None
    incomplete_details = False
    if result is not None and inv is not None:
        citation = f"/api/v1/invocations/{inv.id}/raw"
        produced = sum(f.pseudocode_status == "available" for f in result.functions)
        observations.append(
            ClaimOut(
                text=f"Ghidra identified {result.function_count} functions and stored "
                f"{len(result.functions)} function records. "
                f"Pseudocode is available for {produced} functions.",
                citation=citation + "#/functions",
            )
        )
        limits.extend(result.limitations)
        failed_details = sum(f.pseudocode_status == "failed" for f in result.functions)
        capped_details = sum(
            f.pseudocode_truncated or f.instructions_truncated or f.calls_truncated
            for f in result.functions
        )
        incomplete_details = bool(failed_details or capped_details)
        if failed_details:
            limits.append(f"Pseudocode was unavailable for {failed_details} selected functions.")
        if capped_details:
            limits.append(f"Detail output was capped for {capped_details} functions.")
        if result.functions_truncated:
            limits.append(
                "The function inventory was capped; additional functions were not retained."
            )
        if result.analysis_timed_out:
            limits.append(
                "Ghidra's analysis deadline was reached; retained records are "
                "incomplete static observations."
            )
        provenance = ProvenanceOut(
            tool_version=inv.tool_version,
            adapter_version=inv.adapter_version,
            profile_sha256=result.profile_sha256,
            script_sha256=result.script_sha256,
            raw_output_sha256=inv.raw_output_sha256 or "",
            language_id=result.language_id,
            compiler=result.compiler,
            provider_host=inv.args.get("provider_host", {}),
        )
    else:
        limits.append(
            f"The Ghidra step is {status.replace('_', ' ')}; "
            "no completed Ghidra records are available."
        )
    recommendations = [
        "Preserve the original file and review the linked function evidence "
        "before drawing conclusions.",
        "If you do not recognize the file, do not run it on your everyday computer; "
        "seek qualified review.",
    ]
    if (
        result is None
        or result.functions_truncated
        or result.analysis_timed_out
        or incomplete_details
    ):
        recommendations.insert(
            0, "Complete the missing supported static analysis before relying on this review."
        )
    return GhidraOverviewOut(
        run_id=run.id,
        project_id=run.sample_version.sample.project_id,
        version_id=run.sample_version_id,
        input_sha256=run.sample_version.sha256,
        run_status=run.status,
        step_status=status,
        invocation_id=inv.id if inv else None,
        available=result is not None,
        provenance=provenance,
        summary=ExplanationOut(
            observations=observations,
            hypotheses=[],
            analyst_notes=[],
            recommendations=recommendations,
            limitations=limits,
        ),
        coverage=CoverageOut(completed=int(result is not None)),
        function_count=result.function_count if result else None,
        stored_functions=len(result.functions) if result else 0,
        functions_truncated=result.functions_truncated if result else False,
    )


@router.get("/runs/{run_id}/ghidra", response_model=GhidraOverviewOut)
def overview(request: Request, run_id: str) -> GhidraOverviewOut | JSONResponse:
    ctx = _ctx(request)
    with ctx.sessions() as session:
        run = _run(session, run_id)
        if run is None:
            return _failure(request)
        inv = _invocation(run)
        try:
            result = _read(ctx, run, inv) if inv and inv.status == "succeeded" else None
        except IntegrityError:
            return _failure(request, "integrity_error")
        return _overview(run, inv, result)


@router.get("/runs/{run_id}/ghidra/functions", response_model=FunctionPageOut)
def functions(
    request: Request,
    run_id: str,
    q: Annotated[str, Query(max_length=128)] = "",
    offset: Annotated[int, Query(ge=0, le=256)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> FunctionPageOut | JSONResponse:
    ctx = _ctx(request)
    with ctx.sessions() as session:
        run = _run(session, run_id)
        inv = _invocation(run) if run else None
        if run is None or inv is None or inv.status != "succeeded":
            return _failure(request)
        try:
            result = _read(ctx, run, inv)
        except IntegrityError:
            return _failure(request, "integrity_error")
        selected = [
            (i, f) for i, f in enumerate(result.functions) if q.casefold() in f.name.casefold()
        ]
        return FunctionPageOut(
            run_id=run_id,
            matched=len(selected),
            total=len(result.functions),
            offset=offset,
            limit=limit,
            items=[
                FunctionItemOut.model_validate(
                    {
                        "index": i,
                        **f.model_dump(exclude={"pseudocode", "instructions", "calls"}),
                    }
                )
                for i, f in selected[offset : offset + limit]
            ],
        )


@router.get("/runs/{run_id}/ghidra/functions/{index}", response_model=FunctionDetailOut)
def function_detail(request: Request, run_id: str, index: int) -> FunctionDetailOut | JSONResponse:
    if not 0 <= index < 256:
        return _failure(request)
    ctx = _ctx(request)
    with ctx.sessions() as session:
        run = _run(session, run_id)
        inv = _invocation(run) if run else None
        if run is None or inv is None or inv.status != "succeeded":
            return _failure(request)
        try:
            result = _read(ctx, run, inv)
        except IntegrityError:
            return _failure(request, "integrity_error")
        if index >= len(result.functions):
            return _failure(request)
        return FunctionDetailOut(
            run_id=run_id,
            invocation_id=inv.id,
            index=index,
            citation=f"/api/v1/invocations/{inv.id}/raw#/functions/{index}",
            function=FunctionDetailRecord.model_validate(result.functions[index].model_dump()),
        )


@router.get("/runs/{run_id}/ghidra/export")
def export(
    request: Request,
    run_id: str,
    format: Annotated[Literal["json", "html"], Query()] = "json",
) -> Response:
    ctx = _ctx(request)
    with ctx.sessions() as session:
        run = _run(session, run_id)
        inv = _invocation(run) if run else None
        if run is None or inv is None or inv.status != "succeeded":
            return _failure(request)
        try:
            result = _read(ctx, run, inv)
        except IntegrityError:
            return _failure(request, "integrity_error")
        document = {
            "schema_version": "bytasm-ghidra-report-1",
            "overview": _overview(run, inv, result).model_dump(mode="json"),
            "analysis": result.model_dump(mode="json"),
        }
    canonical = canonical_json(document)
    content = canonical if format == "json" else html_export(json.loads(canonical))
    return Response(
        content,
        media_type="application/json" if format == "json" else "text/html",
        headers={
            "Content-Disposition": f'attachment; filename="bytasm-ghidra-{run_id}.{format}"',
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )
