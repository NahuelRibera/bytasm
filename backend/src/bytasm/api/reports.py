"""JSON report endpoints (blueprint 7.2, M5).

POST creates a report: the stored file's SHA-256 is re-verified first, and a
mismatch returns 409 with nothing generated. GET downloads it as an attachment
after re-verifying the report file's own SHA-256.
"""

import json
import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from bytasm.annotations import AnnotationError
from bytasm.api.context import AppContext
from bytasm.api.problems import problem
from bytasm.api.schemas import ReportCreated
from bytasm.compare import CompareError
from bytasm.db.models import Report, SampleVersion
from bytasm.reports.generate import export_report
from bytasm.reports.model import ReportScope
from bytasm.review import ReviewOut, report_review
from bytasm.runner import workspace
from bytasm.storage import IntegrityError

router = APIRouter()
log = logging.getLogger("bytasm.reports")


def _version_exists(ctx: AppContext, version_id: str) -> bool:
    with ctx.sessions() as session:
        return session.get(SampleVersion, version_id) is not None


@router.post("/sample-versions/{version_id}/reports", response_model=ReportCreated, status_code=201)
async def create_report(
    request: Request,
    version_id: str,
    compare_with: Annotated[str | None, Query(pattern=r"^[0-9a-f]{32}$")] = None,
) -> ReportCreated | JSONResponse:
    ctx: AppContext = request.app.state.ctx
    request_id: str = request.state.request_id
    if not await run_in_threadpool(_version_exists, ctx, version_id):
        return problem("not_found", detail="No sample version with this ID.", request_id=request_id)
    scratch = workspace.create_workdir(ctx.tmp_dir)
    try:
        record = await run_in_threadpool(
            export_report,
            ctx.sessions,
            ctx.blobs,
            ctx.outputs,
            ctx.reports,
            scratch,
            version_id,
            ctx.generator,
            compare_with,
        )
    except (CompareError, AnnotationError) as error:
        return problem(error.code, request_id=request_id)
    except IntegrityError:
        log.warning(
            json.dumps({"event": "report", "outcome": "integrity_error", "version": version_id})
        )
        return problem("integrity_error", request_id=request_id)
    finally:
        workspace.remove_workdir(scratch)
    log.info(json.dumps({"event": "report", "outcome": "created", "sha256": record.sha256}))
    return ReportCreated(
        id=record.id,
        sample_version_id=record.sample_version_id,
        format="json",
        sha256=record.sha256,
        generated_at=record.generated_at,
        download_url=f"/api/v1/reports/{record.id}/download",
    )


@router.get("/reports/{report_id}/download")
def download_report(request: Request, report_id: str) -> Response:
    ctx: AppContext = request.app.state.ctx
    request_id: str = request.state.request_id
    with ctx.sessions() as session:
        record = session.get(Report, report_id)
        if record is None:
            return problem("not_found", detail="No report with this ID.", request_id=request_id)
        version_sha = session.get_one(SampleVersion, record.sample_version_id).sha256
        sha256 = record.sha256
    try:
        data = ctx.reports.read_verified(sha256)
    except IntegrityError:
        return problem("integrity_error", request_id=request_id)
    filename = f"bytasm-report-{version_sha[:16]}-{sha256[:8]}.json"
    return Response(
        data,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Bytasm-Report-SHA256": sha256,
        },
    )


@router.get("/reports/{report_id}/html")
def html_report(request: Request, report_id: str, download: bool = True) -> Response:
    """Render a verified JSON snapshot; no live data or remote assets enter HTML."""
    from bytasm.reports.html import CSP, render
    from bytasm.reports.model import Report as ReportDocument

    ctx: AppContext = request.app.state.ctx
    with ctx.sessions() as session:
        row = session.get(Report, report_id)
        if row is None:
            return problem("not_found", request_id=request.state.request_id)
        sha = row.sha256
    try:
        document = json.loads(ctx.reports.read_verified(sha))
        if document.get("schema_version") != 4:
            return problem(
                "invalid_request",
                detail=(
                    "HTML rendering is available for schema 4 snapshots. Existing JSON"
                    " downloads are unchanged."
                ),
                request_id=request.state.request_id,
            )
        ReportDocument.model_validate(document)
        data = render(document)
    except (IntegrityError, ValueError):
        return problem("integrity_error", request_id=request.state.request_id)
    return Response(
        data,
        media_type="text/html",
        headers={
            "Content-Security-Policy": CSP,
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": ("attachment" if download else "inline")
            + f'; filename="bytasm-report-{sha[:16]}.html"',
        },
    )


@router.get("/reports/{report_id}/review", response_model=ReviewOut)
def review_report(request: Request, report_id: str) -> ReviewOut | JSONResponse:
    """An explanatory view of the verified snapshot, never of later live data."""
    from bytasm.reports.model import Report as ReportDocument

    ctx: AppContext = request.app.state.ctx
    with ctx.sessions() as session:
        row = session.get(Report, report_id)
        if row is None:
            return problem("not_found", request_id=request.state.request_id)
        sha = row.sha256
    try:
        document = json.loads(ctx.reports.read_verified(sha))
        if not isinstance(document, dict):
            raise ValueError("Invalid stored report")
        if document.get("schema_version") != 4:
            return problem(
                "invalid_request",
                detail="Explanatory views require schema 4; legacy JSON downloads are unchanged.",
                request_id=request.state.request_id,
            )
        ReportDocument.model_validate(document)
        return report_review(document)
    except (IntegrityError, ValueError):
        return problem("integrity_error", request_id=request.state.request_id)


class ReportHistoryItem(BaseModel):
    id: str
    sha256: str
    generated_at: datetime
    scope: ReportScope | None
    format: str


class ReportHistoryOut(BaseModel):
    items: list[ReportHistoryItem]
    next_offset: int | None


@router.get("/sample-versions/{version_id}/reports", response_model=ReportHistoryOut)
def report_history(
    request: Request,
    version_id: str,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> ReportHistoryOut | JSONResponse:
    from sqlalchemy import select

    ctx: AppContext = request.app.state.ctx
    with ctx.sessions() as session:
        if session.get(SampleVersion, version_id) is None:
            return problem("not_found", request_id=request.state.request_id)
        rows = session.scalars(
            select(Report)
            .where(Report.sample_version_id == version_id)
            .order_by(Report.generated_at.desc(), Report.id.desc())
            .offset(offset)
            .limit(limit + 1)
        ).all()
        return ReportHistoryOut.model_validate(
            {
                "items": [
                    {
                        "id": row.id,
                        "sha256": row.sha256,
                        "generated_at": row.generated_at,
                        "scope": row.scope,
                        "format": row.format,
                    }
                    for row in rows[:limit]
                ],
                "next_offset": offset + limit if len(rows) > limit else None,
            }
        )
