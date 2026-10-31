"""`POST /api/v1/projects/{project_id}/imports` (blueprint 5.4.1 request lifecycle).

Order of operations, each step refusing before the next can run:

 1. Guards (middleware): loopback, Host, Origin, X-Bytasm-Request.
 2. X-Bytasm-Import metadata validated; project and sample checked. No body
    byte has been read yet.
 3. Content-Type must be application/octet-stream; Content-Length, if given,
    must be within the limit.
 4. The single parser slot is taken without waiting, or 503.
 5. The raw body is streamed into data/tmp/<random>/upload.bin with a hard
    limit, an early signature check, and SHA-256 over exactly those bytes.
 6. Input policy on that SHA-256: in `fixtures` mode an unlisted file is
    refused here and the parser is never started.
 7. Duplicate check within the sample.
 8. Bytasm's own header checks (identify_format) on the admitted bytes.
 9. The LIEF adapter runs in a resource-limited child on those bytes, which
    it re-hashes before parsing.
10. Only a fully successful parse is persisted, all or nothing.
11. `finally`: the child's process group is gone (runner), the temp directory
    is deleted, and the parser slot is released, on every path.

If the client disconnects while the file is being parsed, the parse still runs
to completion or timeout and a success is committed (blueprint 5.4.1).
"""

import json
import logging
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import select

from bytasm.api.context import AppContext
from bytasm.api.problems import problem
from bytasm.api.views import sample_version_out
from bytasm.db.models import Project, Sample, SampleVersion
from bytasm.errors import InspectError, outcome_error
from bytasm.intake.identify import identify_format
from bytasm.intake.import_metadata import (
    HEADER_NAME,
    ImportMetadata,
    InvalidImportMetadata,
    parse_import_header,
)
from bytasm.intake.persist import SuccessfulParse, persist_import
from bytasm.intake.upload import UploadError, receive_upload
from bytasm.runner import workspace
from bytasm.runner.supervisor import run_adapter
from bytasm.storage import IntegrityError

router = APIRouter()
log = logging.getLogger("bytasm.imports")


class Refused(Exception):
    """End the import with a problem response. `code` selects the fixed message."""

    def __init__(
        self, code: str, detail: str | None = None, extra: dict[str, object] | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.extra = extra


def _log(outcome: str, reason: str, started: float, **fields: object) -> None:
    """One structured line per import attempt: hashes, sizes, codes; never file content."""
    record = {
        "event": "import",
        "outcome": outcome,
        "reason": reason,
        "duration_ms": int((time.monotonic() - started) * 1000),
        **fields,
    }
    log.info(json.dumps(record, sort_keys=True))


def _check_targets(ctx: AppContext, project_id: str, meta: ImportMetadata) -> None:
    with ctx.sessions() as session:
        if session.get(Project, project_id) is None:
            raise Refused("not_found", "No project with this ID.")
        if meta.sample_id is not None:
            sample = session.get(Sample, meta.sample_id)
            if sample is None or sample.project_id != project_id:
                raise Refused("not_found", "No sample with this ID in this project.")
        else:
            existing = session.scalar(
                select(Sample.id).where(
                    Sample.project_id == project_id, Sample.name == meta.sample_name
                )
            )
            if existing is not None:
                raise Refused("sample_exists", extra={"sample_id": existing})


def _check_duplicate(ctx: AppContext, meta: ImportMetadata, sha256: str) -> None:
    if meta.sample_id is None:
        return  # a new sample has no versions yet
    with ctx.sessions() as session:
        existing = session.scalar(
            select(SampleVersion).where(
                SampleVersion.sample_id == meta.sample_id, SampleVersion.sha256 == sha256
            )
        )
        if existing is not None:
            label = existing.version_label or "an unlabelled version"
            raise Refused(
                "duplicate_version",
                f"This exact file is already in this sample as {label}. Nothing new was imported.",
                {"existing_version_id": existing.id},
            )


def _content_length(request: Request, limit: int) -> int | None:
    value = request.headers.get("content-length")
    if value is None:
        return None
    if not value.isdigit():
        raise Refused("upload_incomplete")
    length = int(value)
    if length > limit:
        raise Refused("upload_too_large")
    return length


@router.post("/projects/{project_id}/imports", status_code=201)
async def create_import(project_id: str, request: Request) -> JSONResponse:
    ctx: AppContext = request.app.state.ctx
    request_id: str = request.state.request_id
    started = time.monotonic()
    sha256: str | None = None
    size: int | None = None
    body_read = False

    try:
        try:
            meta = parse_import_header(request.headers.get(HEADER_NAME))
        except InvalidImportMetadata as exc:
            raise Refused("invalid_import_metadata") from exc
        await run_in_threadpool(_check_targets, ctx, project_id, meta)
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/octet-stream":
            raise Refused("unsupported_media_type")
        content_length = _content_length(request, ctx.settings.max_upload_bytes)
    except Refused as refusal:
        _log("rejected", refusal.code, started)
        return _refusal_response(refusal, request_id, body_read=False)

    if not ctx.parser_slot.try_acquire():
        _log("rejected", "parser_busy", started)
        return problem("parser_busy", request_id=request_id, headers={"Retry-After": "5"})

    try:
        workdir = workspace.create_workdir(ctx.tmp_dir)
    except OSError:
        # Without a work directory nothing was received; free the slot, or
        # every later import would be refused as busy.
        ctx.parser_slot.release()
        _log("failed", "workdir_unavailable", started)
        return problem("internal_error", request_id=request_id)
    try:
        upload_path = workspace.input_path(workdir)
        try:
            upload = await receive_upload(
                request.receive, upload_path, ctx.settings.max_upload_bytes, content_length
            )
        except UploadError as error:
            raise Refused(error.code, error.detail) from error
        body_read = True
        sha256, size = upload.sha256, upload.size_bytes

        admission = ctx.policy.admit(sha256)
        if admission is None:
            raise Refused("input_policy")  # the parser is never started
        await run_in_threadpool(_check_duplicate, ctx, meta, sha256)

        data = upload_path.read_bytes()
        try:
            file_format = identify_format(data)
        except InspectError as error:
            raise Refused(error.code, error.message) from error
        del data
        workspace.seal_input(upload_path)

        parse_started = datetime.now(UTC).replace(microsecond=0)
        if ctx.settings.metadata_isolation_image:
            from bytasm.runner.isolated_metadata import IsolationConfig, parse_isolated

            outcome = await parse_isolated(
                upload_path.read_bytes(),
                ctx.policy,
                IsolationConfig(ctx.settings.metadata_isolation_image),
            )
        else:
            outcome = await run_adapter(ctx.adapter_command, workdir, sha256, ctx.settings.limits)
        parse_finished = datetime.now(UTC).replace(microsecond=0)
        if outcome.result is None or outcome.result_bytes is None:
            failure = outcome_error(outcome.status, outcome.reason)
            _log(
                "rejected",
                failure.code,
                started,
                sha256=sha256,
                size_bytes=size,
                adapter_status=outcome.status,
                adapter_reason=outcome.reason,
            )
            return problem(failure.code, request_id=request_id)
        if outcome.result.metadata.format != file_format:
            raise Refused("parse_failed")

        parsed = SuccessfulParse(
            sha256=sha256,
            size_bytes=size,
            input_path=upload_path,
            admission=admission,
            result=outcome.result,
            result_bytes=outcome.result_bytes,
            exit_code=outcome.exit_code or 0,
            duration_ms=outcome.duration_ms,
            started_at=parse_started,
            finished_at=parse_finished,
            limits=outcome.result.resource_limits.model_dump(),
            isolation={
                "profile": "disposable-docker-metadata-1",
                "image_id": ctx.settings.metadata_isolation_image,
                "transport": "stdin-exact-bytes",
                "host_mounts": False,
                "external_admission_enabled": False,
            }
            if ctx.settings.metadata_isolation_image
            else None,
        )
        version_id = await run_in_threadpool(
            persist_import, ctx.sessions, ctx.blobs, ctx.outputs, workdir, project_id, meta, parsed
        )
        body = await run_in_threadpool(_created_body, ctx, version_id)
        _log(
            "imported",
            "ok",
            started,
            sha256=sha256,
            size_bytes=size,
            admitted_under=admission.admitted_under,
            parse_ms=outcome.duration_ms,
        )
        return JSONResponse(body, status_code=201)
    except Refused as refusal:
        _log("rejected", refusal.code, started, sha256=sha256, size_bytes=size)
        return _refusal_response(refusal, request_id, body_read=body_read)
    except IntegrityError:
        _log("failed", "integrity_error", started, sha256=sha256, size_bytes=size)
        return problem("internal_error", request_id=request_id)
    finally:
        workspace.remove_workdir(workdir)
        ctx.parser_slot.release()


def _refusal_response(refusal: Refused, request_id: str, *, body_read: bool) -> JSONResponse:
    # If the body was not read to the end, close the connection after the
    # response instead of reading (and discarding) the rest of the upload.
    headers = None if body_read else {"Connection": "close"}
    return problem(
        refusal.code,
        detail=refusal.detail,
        request_id=request_id,
        extra=refusal.extra,
        headers=headers,
    )


def _created_body(ctx: AppContext, version_id: str) -> dict[str, object]:
    with ctx.sessions() as session:
        version = session.get_one(SampleVersion, version_id)
        return {"sample_version": sample_version_out(version).model_dump(mode="json")}
