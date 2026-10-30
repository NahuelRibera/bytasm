"""Human annotations, immutable revisions and validated provenance references."""

from datetime import datetime
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import Select, exists, select
from sqlalchemy.orm import Session, aliased

from bytasm.db.models import (
    ActivityEvent,
    AnalysisRun,
    Analyst,
    Annotation,
    AnnotationCitation,
    Evidence,
    Finding,
    Sample,
    SampleVersion,
    ToolInvocation,
    new_id,
    utcnow,
)

TargetType = Literal["sample_version", "finding", "evidence"]
Kind = Literal["note", "interpretation", "conclusion"]
Confidence = Literal["tentative", "likely", "well-supported"]


class AnnotationError(Exception):
    def __init__(self, code: str = "invalid_request"):
        self.code = code
        super().__init__(code)


class CitationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_type: Literal["finding", "evidence"]
    target_id: str = Field(min_length=1, max_length=32)


class RevisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Kind
    body: str = Field(min_length=1, max_length=4000)
    confidence: Confidence | None = None
    cites: list[CitationIn] = Field(default_factory=list, max_length=20)

    @field_validator("body", mode="before")
    @classmethod
    def trim_body(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def valid_conclusion(self) -> "RevisionIn":
        if self.kind == "conclusion":
            if self.confidence is None or not self.cites:
                raise ValueError("Conclusions require confidence and citations")
        elif self.confidence is not None:
            raise ValueError("Confidence is for conclusions")
        if len({(c.target_type, c.target_id) for c in self.cites}) != len(self.cites):
            raise ValueError("Duplicate citations")
        return self


class AnnotationIn(RevisionIn):
    request_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    target_type: TargetType
    target_id: str = Field(min_length=1, max_length=32)


class RevisionRequest(RevisionIn):
    expected_revision: int = Field(ge=1, strict=True)


class CitationOut(BaseModel):
    target_type: Literal["finding", "evidence"]
    target_id: str
    run_id: str
    version_id: str
    label: str


class AuthorOut(BaseModel):
    id: str
    display_name: str


class AnnotationOut(BaseModel):
    id: str
    revision_id: str
    revision: int
    target_type: TargetType
    target_id: str
    version_id: str
    kind: Kind
    body: str
    confidence: Confidence | None
    author: AuthorOut
    created_at: datetime
    cites: list[CitationOut]


def resolve_target(
    session: Session, target_type: str, target_id: str
) -> tuple[SampleVersion, CitationOut | None]:
    if not 1 <= len(target_id) <= 32:
        raise AnnotationError()
    if target_type == "sample_version":
        version = session.get(SampleVersion, target_id)
        if version is None:
            raise AnnotationError("not_found")
        return version, None
    evidence = None
    if target_type == "evidence":
        if not target_id.isascii() or not target_id.isdecimal() or str(int(target_id)) != target_id:
            raise AnnotationError()
        if int(target_id) > (1 << 63) - 1:
            raise AnnotationError()
        evidence = session.get(Evidence, int(target_id))
        finding = session.get(Finding, evidence.finding_id) if evidence else None
    elif target_type == "finding":
        finding = session.get(Finding, target_id)
    else:
        raise AnnotationError()
    if finding is None:
        raise AnnotationError("not_found")
    invocation = session.get(ToolInvocation, finding.invocation_id)
    run = session.get(AnalysisRun, finding.run_id)
    if (
        invocation is None
        or run is None
        or invocation.run_id != run.id
        or invocation.status != "succeeded"
    ):
        raise AnnotationError()
    version = session.get(SampleVersion, run.sample_version_id)
    if version is None:
        raise AnnotationError()
    label = (
        finding.title
        if evidence is None
        else (
            f"{evidence.pattern_id} at virtual address {evidence.virtual_address:#x}"
            if evidence.virtual_address is not None
            else f"{evidence.pattern_id} at file offset {evidence.file_offset}"
        )
    )
    return version, CitationOut(
        target_type="finding" if target_type == "finding" else "evidence",
        target_id=target_id,
        run_id=run.id,
        version_id=version.id,
        label=label,
    )


def annotation_out(session: Session, row: Annotation) -> AnnotationOut:
    try:
        version, _ = resolve_target(session, row.target_type, row.target_id)
    except AnnotationError as exc:
        raise AnnotationError("integrity_error") from exc
    if version.id != row.version_id:
        raise AnnotationError("integrity_error")
    citations = []
    for cite in session.scalars(
        select(AnnotationCitation)
        .where(AnnotationCitation.annotation_id == row.id)
        .order_by(AnnotationCitation.position)
    ):
        try:
            cited_version, resolved = resolve_target(session, cite.target_type, cite.target_id)
        except AnnotationError as exc:
            raise AnnotationError("integrity_error") from exc
        if cited_version.id != row.version_id or resolved is None:
            raise AnnotationError("integrity_error")
        citations.append(resolved)
    try:
        RevisionIn.model_validate(
            {
                "kind": row.kind,
                "body": row.body,
                "confidence": row.confidence,
                "cites": [c.model_dump(include={"target_type", "target_id"}) for c in citations],
            }
        )
    except ValueError as exc:
        raise AnnotationError("integrity_error") from exc
    if row.kind == "conclusion" and not citations:
        raise AnnotationError("integrity_error")
    author = session.get(Analyst, row.author_id)
    if author is None:
        raise AnnotationError("integrity_error")
    return AnnotationOut(
        id=row.root_id,
        revision_id=row.id,
        revision=row.revision,
        target_type=cast(TargetType, row.target_type),
        target_id=row.target_id,
        version_id=row.version_id,
        kind=cast(Kind, row.kind),
        body=row.body,
        confidence=cast(Confidence | None, row.confidence),
        author=AuthorOut(id=author.id, display_name=author.display_name),
        created_at=row.created_at,
        cites=citations,
    )


def current_query() -> Select[Annotation]:
    successor = aliased(Annotation)
    return select(Annotation).where(~exists().where(successor.supersedes_id == Annotation.id))


def current_annotations(session: Session, version_id: str) -> list[AnnotationOut]:
    rows = session.scalars(
        current_query()
        .where(Annotation.version_id == version_id)
        .order_by(Annotation.created_at, Annotation.root_id)
    )
    return [annotation_out(session, row) for row in rows]


def save_annotation(
    session: Session,
    body: RevisionIn,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    root_id: str | None = None,
    expected_revision: int | None = None,
) -> AnnotationOut:
    request_id = body.request_id if isinstance(body, AnnotationIn) else None
    if request_id is not None:
        existing = session.get(Annotation, request_id)
        if existing is not None:
            original = annotation_out(session, existing)
            expected_cites = [(cite.target_type, cite.target_id) for cite in body.cites]
            actual_cites = [(cite.target_type, cite.target_id) for cite in original.cites]
            if (
                existing.root_id != request_id
                or existing.revision != 1
                or original.target_type != target_type
                or original.target_id != target_id
                or original.kind != body.kind
                or original.body != body.body
                or original.confidence != body.confidence
                or actual_cites != expected_cites
            ):
                raise AnnotationError("annotation_stale")
            return original
    previous = None
    if root_id is not None:
        root = session.get(Annotation, root_id)
        if root is None or root.root_id != root_id:
            raise AnnotationError("not_found")
        previous = session.scalar(current_query().where(Annotation.root_id == root_id))
        if previous is None or previous.revision != expected_revision:
            raise AnnotationError("annotation_stale")
        target_type, target_id = root.target_type, root.target_id
    if target_type is None or target_id is None:
        raise AnnotationError()
    version, _ = resolve_target(session, target_type, target_id)
    validated = []
    for cite in body.cites:
        cited_version, _ = resolve_target(session, cite.target_type, cite.target_id)
        if cited_version.id != version.id:
            raise AnnotationError()
        validated.append(cite)
    revision_id = request_id or new_id()
    row = Annotation(
        id=revision_id,
        root_id=root_id or revision_id,
        supersedes_id=previous.id if previous else None,
        revision=previous.revision + 1 if previous else 1,
        version_id=version.id,
        target_type=target_type,
        target_id=target_id,
        finding_id=target_id if target_type == "finding" else None,
        evidence_id=int(target_id) if target_type == "evidence" else None,
        kind=body.kind,
        body=body.body,
        confidence=body.confidence,
        author_id="local",
        created_at=utcnow(),
    )
    session.add(row)
    session.flush()
    for position, cite in enumerate(validated):
        session.add(
            AnnotationCitation(
                annotation_id=row.id,
                position=position,
                target_type=cite.target_type,
                target_id=cite.target_id,
                finding_id=cite.target_id if cite.target_type == "finding" else None,
                evidence_id=int(cite.target_id) if cite.target_type == "evidence" else None,
            )
        )
    sample = session.get(Sample, version.sample_id)
    if sample is None:
        raise AnnotationError("integrity_error")
    session.add(
        ActivityEvent(
            project_id=sample.project_id,
            actor_id="local",
            type="annotation.revised" if previous else "annotation.created",
            payload={
                "annotation_id": row.root_id,
                "revision_id": row.id,
                "sample_version_id": version.id,
                "revision": row.revision,
            },
            at=row.created_at,
        )
    )
    session.flush()
    return annotation_out(session, row)
