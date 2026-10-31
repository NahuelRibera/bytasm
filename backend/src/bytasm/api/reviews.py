"""Append-only reviews and exports; viewing never starts an analysis."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from sqlalchemy import select

from bytasm.api.analysis import _ctx, _not_found, _rid
from bytasm.api.problems import problem
from bytasm.db.models import ReviewSnapshot, SampleVersion
from bytasm.review_export import ExportPolicy, derivative, digest, export_bytes
from bytasm.review_snapshot import (
    CreateReview,
    Snapshot,
    create_snapshot,
    read_snapshot,
)
from bytasm.storage import IntegrityError

router = APIRouter()


def failure(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, LookupError):
        return _not_found(request, "review or source")
    return problem(
        "integrity_error" if isinstance(exc, IntegrityError) else "invalid_request",
        request_id=_rid(request),
    )


@router.post("/sample-versions/{version_id}/reviews", response_model=Snapshot, status_code=201)
def create(request: Request, version_id: str, body: CreateReview) -> Snapshot | JSONResponse:
    ctx = _ctx(request)
    try:
        with ctx.sessions() as session, session.begin():
            version = session.get(SampleVersion, version_id)
            if version is None:
                return _not_found(request, "sample version")
            return create_snapshot(ctx, session, version, body)
    except (LookupError, IntegrityError, ValueError, OSError) as exc:
        return failure(request, exc)


@router.get("/sample-versions/{version_id}/reviews")
def history(
    request: Request, version_id: str, offset: Annotated[int, Query(ge=0, le=100_000)] = 0
) -> JSONResponse:
    with _ctx(request).sessions() as session:
        if session.get(SampleVersion, version_id) is None:
            return _not_found(request, "sample version")
        rows = list(
            session.scalars(
                select(ReviewSnapshot)
                .where(
                    ReviewSnapshot.version_id == version_id,
                )
                .order_by(ReviewSnapshot.created_at.desc(), ReviewSnapshot.id.desc())
                .offset(offset)
                .limit(26)
            )
        )
        return JSONResponse(
            {
                "items": [
                    {"id": r.id, "sha256": r.sha256, "created_at": r.created_at.isoformat()}
                    for r in rows[:25]
                ],
                "next_offset": offset + 25 if len(rows) > 25 else None,
            }
        )


@router.get("/reviews/{review_id}", response_model=Snapshot)
def get(request: Request, review_id: str) -> Snapshot | JSONResponse:
    try:
        with _ctx(request).sessions() as session:
            return read_snapshot(session, review_id)[0]
    except (LookupError, IntegrityError, ValidationError) as exc:
        return failure(request, exc)


@router.post("/reviews/{review_id}/refresh", response_model=Snapshot, status_code=201)
def refresh(request: Request, review_id: str) -> Snapshot | JSONResponse:
    ctx = _ctx(request)
    try:
        with ctx.sessions() as session, session.begin():
            old, _ = read_snapshot(session, review_id)
            version = session.get_one(SampleVersion, old.sample.version_id)
            if version.sha256 != old.sample.sha256 or version.size_bytes != old.sample.size_bytes:
                raise IntegrityError("Sample identity changed")
            return create_snapshot(
                ctx,
                session,
                version,
                CreateReview(scope=old.scope, run_id=old.exact_run_id),
                old.id,
            )
    except (LookupError, IntegrityError, ValueError, OSError) as exc:
        return failure(request, exc)


@router.post("/reviews/{review_id}/export/{format}")
def export(
    request: Request,
    review_id: str,
    format: Literal["preview", "json", "html"],
    policy: ExportPolicy,
) -> Response:
    try:
        with _ctx(request).sessions() as session:
            review, source_digest = read_snapshot(session, review_id)
        document = derivative(review, source_digest, policy)
        raw_json = export_bytes(document, "json")
        if len(raw_json) > 8 * 1024 * 1024:
            return problem("report_too_large", request_id=_rid(request))
        if format == "preview":
            return JSONResponse(
                {"document": document, "sha256": digest(raw_json), "size_bytes": len(raw_json)}
            )
        raw = raw_json if format == "json" else export_bytes(document, "html")
        if len(raw) > 16 * 1024 * 1024:
            return problem("report_too_large", request_id=_rid(request))
        return Response(
            raw,
            media_type="application/json" if format == "json" else "text/html",
            headers={
                "Content-Disposition": f'attachment; filename="bytasm-review-{review.id}.{format}"',
                "X-Bytasm-Export-SHA256": digest(raw),
            },
        )
    except (LookupError, IntegrityError, ValidationError) as exc:
        return failure(request, exc)


@router.get("/sample-versions/{version_id}/bytes")
def byte_window(
    request: Request,
    version_id: str,
    offset: Annotated[int, Query(ge=0, le=64 * 1024 * 1024)] = 0,
    length: Annotated[int, Query(ge=1, le=4096)] = 256,
) -> Response:
    from bytasm.review_snapshot import bounded_read

    ctx = _ctx(request)
    with ctx.sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            return _not_found(request, "sample version")
        sha, size = version.sha256, version.size_bytes
    if offset > size:
        return problem("invalid_request", request_id=_rid(request))
    try:
        # Bounded by admission's 64 MiB hard maximum. The full-file digest is
        # verified before serving even a single byte; never trust a partial hash.
        raw = bounded_read(ctx.blobs, sha, ctx.settings.max_upload_bytes)
        if len(raw) != size:
            raise IntegrityError("Sample size changed")
    except IntegrityError as exc:
        return failure(request, exc)
    window = raw[offset : offset + length]
    return JSONResponse(
        {
            "version_id": version_id,
            "sha256": sha,
            "size_bytes": size,
            "offset": offset,
            "length": len(window),
            "hex": window.hex(),
            "printable": "".join(chr(b) if 32 <= b < 127 else "." for b in window),
            "eof": offset + len(window) == size,
            "coordinate": "file_offset_bytes",
        }
    )
