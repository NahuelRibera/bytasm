"""Read-only, bounded projection of a project's activity; payloads stay private."""

from datetime import datetime
from typing import Annotated, cast

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from bytasm.annotations import AnnotationError, TargetType, resolve_target
from bytasm.api.context import AppContext
from bytasm.api.problems import problem
from bytasm.db.models import ActivityEvent, AnalysisRun, Annotation, Project, Sample, SampleVersion
from bytasm.jobs.runs import ACTIVITY_REASONS, TRANSITIONS

router = APIRouter()
EVENTS = frozenset(
    {
        "project.created",
        "sample_version.imported",
        "analysis_run.cancel_requested",
        "annotation.created",
        "annotation.revised",
    }
) | frozenset(f"analysis_run.{status}" for status in TRANSITIONS)


class ActivityItem(BaseModel):
    id: str
    type: str
    at: datetime
    sample_version_id: str | None = None
    run_id: str | None = None
    status: str | None = None
    reason: str | None = None
    annotation_id: str | None = None
    revision_id: str | None = None
    annotation_target_type: TargetType | None = None
    annotation_target_id: str | None = None


class ActivityPage(BaseModel):
    items: list[ActivityItem]
    next_offset: int | None


def _item(session: Session, event: ActivityEvent) -> ActivityItem:
    item = ActivityItem(
        id=event.id, type=event.type if event.type in EVENTS else "other", at=event.at
    )
    payload = event.payload
    if not isinstance(payload, dict):
        return item
    version_id = payload.get("sample_version_id")
    if not isinstance(version_id, str) or len(version_id) != 32:
        return item
    version = session.scalar(
        select(SampleVersion)
        .join(Sample)
        .where(
            SampleVersion.id == version_id,
            Sample.project_id == event.project_id,
        )
    )
    if version is None:
        return item
    if event.type == "sample_version.imported":
        if payload.get("sample_id") == version.sample_id:
            item.sample_version_id = version.id
    elif event.type in ("annotation.created", "annotation.revised"):
        identity, revision_id = payload.get("annotation_id"), payload.get("revision_id")
        if isinstance(identity, str) and isinstance(revision_id, str):
            row = session.scalar(
                select(Annotation).where(
                    Annotation.id == revision_id,
                    Annotation.root_id == identity,
                    Annotation.version_id == version.id,
                )
            )
            if row is not None and row.revision == payload.get("revision"):
                try:
                    target_version, target = resolve_target(session, row.target_type, row.target_id)
                except AnnotationError:
                    return item
                if target_version.id != version.id:
                    return item
                item.sample_version_id = version.id
                item.annotation_id, item.revision_id = identity, revision_id
                item.annotation_target_type = cast(TargetType, row.target_type)
                item.annotation_target_id = row.target_id
                item.run_id = target.run_id if target is not None else None
    elif event.type.startswith("analysis_run.") and event.type in EVENTS:
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or len(run_id) != 32:
            return item
        run = session.scalar(
            select(AnalysisRun).where(
                AnalysisRun.id == run_id,
                AnalysisRun.sample_version_id == version.id,
                AnalysisRun.kind == "analysis",
            )
        )
        if run is not None:
            item.sample_version_id, item.run_id = version.id, run.id
            expected = event.type.removeprefix("analysis_run.")
            item.status = "running" if expected == "cancel_requested" else expected
            reason = payload.get("reason")
            if isinstance(reason, str) and reason in ACTIVITY_REASONS:
                item.reason = reason
    return item


@router.get("/projects/{project_id}/activity", response_model=ActivityPage)
def project_activity(
    request: Request,
    project_id: str,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> ActivityPage | JSONResponse:
    ctx: AppContext = request.app.state.ctx
    with ctx.sessions() as session:
        if session.get(Project, project_id) is None:
            return problem(
                "not_found", detail="No project with this ID.", request_id=request.state.request_id
            )
        rows = session.scalars(
            select(ActivityEvent)
            .where(ActivityEvent.project_id == project_id)
            # UtcDateTime uses ISO text with optional fractional seconds.
            # Pad whole seconds so "...00Z" sorts before "...00.000001Z".
            .order_by(
                case(
                    (
                        func.length(ActivityEvent.at) == 20,
                        func.substr(ActivityEvent.at, 1, 19) + ".000000Z",
                    ),
                    else_=ActivityEvent.at,
                ),
                ActivityEvent.id,
            )
            .offset(offset)
            .limit(limit + 1)
        ).all()
        return ActivityPage(
            items=[_item(session, row) for row in rows[:limit]],
            next_offset=offset + limit if len(rows) > limit else None,
        )
