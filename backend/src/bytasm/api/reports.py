"""JSON report endpoints (blueprint 7.2, M5).

POST creates a report: the stored file's SHA-256 is re-verified first, and a
mismatch returns 409 with nothing generated. GET downloads it as an attachment
after re-verifying the report file's own SHA-256.
"""

import json
import logging

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from bytasm.api.context import AppContext
from bytasm.api.problems import problem
from bytasm.api.schemas import ReportCreated
from bytasm.db.models import Report, SampleVersion
from bytasm.reports.generate import export_report
from bytasm.runner import workspace
from bytasm.storage import IntegrityError

router = APIRouter()
log = logging.getLogger("bytasm.reports")


def _version_exists(ctx: AppContext, version_id: str) -> bool:
    with ctx.sessions() as session:
        return session.get(SampleVersion, version_id) is not None


@router.post("/sample-versions/{version_id}/reports", response_model=ReportCreated, status_code=201)
async def create_report(request: Request, version_id: str) -> ReportCreated | JSONResponse:
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
        )
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
