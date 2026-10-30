"""Bounded annotation reads and atomic append-only writes."""

from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.responses import JSONResponse

from bytasm.annotations import (
    AnnotationError,
    AnnotationIn,
    AnnotationOut,
    CitationOut,
    RevisionRequest,
    TargetType,
    annotation_out,
    current_query,
    resolve_target,
    save_annotation,
)
from bytasm.api.problems import problem
from bytasm.db.models import AnalysisRun, Annotation, Evidence, Finding, ToolInvocation

router = APIRouter()
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Limit = Annotated[int, Query(ge=1, le=100)]


class AnnotationPage(BaseModel):
    items: list[AnnotationOut]
    next_offset: int | None


class CitationPage(BaseModel):
    items: list[CitationOut]
    next_offset: int | None


def _error(request: Request, exc: AnnotationError) -> JSONResponse:
    return problem(exc.code, request_id=request.state.request_id)


def _save(
    request: Request, body: AnnotationIn | RevisionRequest, root_id: str | None = None
) -> AnnotationOut | JSONResponse:
    try:
        with request.app.state.ctx.sessions() as session, session.begin():
            if isinstance(body, AnnotationIn):
                return save_annotation(
                    session, body, target_type=body.target_type, target_id=body.target_id
                )
            return save_annotation(
                session, body, root_id=root_id, expected_revision=body.expected_revision
            )
    except AnnotationError as exc:
        return _error(request, exc)
    except IntegrityError as exc:
        if (
            isinstance(body, AnnotationIn)
            and body.request_id is not None
            and "UNIQUE constraint failed: annotation.id" in str(exc.orig)
        ):
            # The other transaction committed this request token while we validated it.
            return _save(request, body)
        # Only concurrent revisions can violate the root/revision or supersedes indexes.
        if root_id is not None and (
            "UNIQUE constraint failed: annotation.supersedes_id" in str(exc.orig)
            or "UNIQUE constraint failed: annotation.root_id, annotation.revision" in str(exc.orig)
        ):
            return problem("annotation_stale", request_id=request.state.request_id)
        raise
    except OperationalError as exc:
        if root_id is not None and "locked" in str(exc).lower():
            return problem("annotation_stale", request_id=request.state.request_id)
        raise


@router.post("/annotations", response_model=AnnotationOut, status_code=201)
def create_annotation(request: Request, body: AnnotationIn) -> AnnotationOut | JSONResponse:
    return _save(request, body)


@router.post(
    "/annotations/{annotation_id}/revisions", response_model=AnnotationOut, status_code=201
)
def revise_annotation(
    request: Request, annotation_id: str, body: RevisionRequest
) -> AnnotationOut | JSONResponse:
    return _save(request, body, annotation_id)


@router.get("/annotations", response_model=AnnotationPage)
def list_annotations(
    request: Request, target_type: TargetType, target_id: str, offset: Offset = 0, limit: Limit = 25
) -> AnnotationPage | JSONResponse:
    try:
        with request.app.state.ctx.sessions() as session:
            resolve_target(session, target_type, target_id)
            rows = session.scalars(
                current_query()
                .where(Annotation.target_type == target_type, Annotation.target_id == target_id)
                .order_by(Annotation.created_at, Annotation.root_id)
                .offset(offset)
                .limit(limit + 1)
            ).all()
            return AnnotationPage(
                items=[annotation_out(session, row) for row in rows[:limit]],
                next_offset=offset + limit if len(rows) > limit else None,
            )
    except AnnotationError as exc:
        return _error(request, exc)


@router.get("/annotations/{annotation_id}/revisions", response_model=AnnotationPage)
def annotation_history(
    request: Request, annotation_id: str, offset: Offset = 0, limit: Limit = 25
) -> AnnotationPage | JSONResponse:
    try:
        with request.app.state.ctx.sessions() as session:
            root = session.get(Annotation, annotation_id)
            if root is None or root.root_id != annotation_id:
                raise AnnotationError("not_found")
            rows = session.scalars(
                select(Annotation)
                .where(Annotation.root_id == annotation_id)
                .order_by(Annotation.revision)
                .offset(offset)
                .limit(limit + 1)
            ).all()
            return AnnotationPage(
                items=[annotation_out(session, row) for row in rows[:limit]],
                next_offset=offset + limit if len(rows) > limit else None,
            )
    except AnnotationError as exc:
        return _error(request, exc)


@router.get("/sample-versions/{version_id}/citation-targets", response_model=CitationPage)
def citation_targets(
    request: Request, version_id: str, offset: Offset = 0, limit: Limit = 25
) -> CitationPage | JSONResponse:
    try:
        with request.app.state.ctx.sessions() as session:
            resolve_target(session, "sample_version", version_id)
            # SQL UNION keeps pagination bounded without materializing every evidence item.
            finding_ids = (
                select(Finding.id.label("target_id"))
                .join(AnalysisRun, Finding.run_id == AnalysisRun.id)
                .join(ToolInvocation, Finding.invocation_id == ToolInvocation.id)
                .where(
                    AnalysisRun.sample_version_id == version_id,
                    ToolInvocation.run_id == AnalysisRun.id,
                    ToolInvocation.status == "succeeded",
                )
            )
            from sqlalchemy import String, cast, literal, union_all

            findings = finding_ids.add_columns(literal("finding").label("target_type"))
            evidence = (
                select(
                    cast(Evidence.id, String).label("target_id"),
                    literal("evidence").label("target_type"),
                )
                .join(Finding, Evidence.finding_id == Finding.id)
                .join(AnalysisRun, Finding.run_id == AnalysisRun.id)
                .join(ToolInvocation, Finding.invocation_id == ToolInvocation.id)
                .where(
                    AnalysisRun.sample_version_id == version_id,
                    ToolInvocation.run_id == AnalysisRun.id,
                    ToolInvocation.status == "succeeded",
                )
            )
            targets = union_all(findings, evidence).subquery()
            rows = session.execute(
                select(targets)
                .order_by(targets.c.target_type, targets.c.target_id)
                .offset(offset)
                .limit(limit + 1)
            ).all()
            items = []
            for row in rows[:limit]:
                _, citation = resolve_target(session, row.target_type, row.target_id)
                if citation is None:
                    raise AnnotationError("integrity_error")
                items.append(citation)
            return CitationPage(
                items=items, next_offset=offset + limit if len(rows) > limit else None
            )
    except AnnotationError as exc:
        return _error(request, exc)
