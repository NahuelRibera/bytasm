"""Analyst overlays never alter original Ghidra records or imply harmlessness."""

import hashlib
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError as DatabaseConflict
from sqlalchemy.orm import Session

from bytasm.api.analysis import _ctx, _not_found, _rid
from bytasm.api.ghidra import _invocation, _read, _run
from bytasm.api.problems import problem
from bytasm.db.models import FunctionReviewRevision, new_id, utcnow
from bytasm.function_review import validated_overlay
from bytasm.reports.generate import canonical_json
from bytasm.review_snapshot import Strict
from bytasm.storage import IntegrityError

router = APIRouter()
Text = Annotated[str, Field(max_length=4000)]


class Citation(Strict):
    text_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    start_line: Annotated[int, Field(ge=1, le=4096)]
    end_line: Annotated[int, Field(ge=1, le=4096)]


class RevisionInput(Strict):
    expected_revision: Annotated[int, Field(ge=0)]
    alias: Annotated[str, Field(max_length=128)] = ""
    bookmarked: bool = False
    collections: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=16
    )
    state: Literal["unreviewed", "in_progress", "reviewed"] = "unreviewed"
    note: Text = ""
    citation: Citation | None = None


def scope(
    request: Request, session: Session, run_id: str, index: int
) -> tuple[dict[str, Any], str, str | None]:
    run = _run(session, run_id)
    if run is None:
        raise LookupError("No run")
    invocation = _invocation(run)
    if invocation is None:
        raise LookupError("No invocation")
    document = _read(_ctx(request), run, invocation)
    if index < 0 or index >= len(document.functions):
        raise LookupError("No retained function")
    fn = document.functions[index]
    identity = {
        "sample_sha256": run.sample_version.sha256,
        "version_id": run.sample_version_id,
        "run_id": run.id,
        "invocation_id": invocation.id,
        "output_sha256": invocation.raw_output_sha256,
        "entry": fn.entry.model_dump(),
        "record_pointer": f"/functions/{index}",
    }
    digest = hashlib.sha256(canonical_json(identity)).hexdigest()
    return identity, digest, fn.pseudocode


def view(session: Session, identity: dict[str, Any], digest: str) -> dict[str, Any]:
    rows = list(
        session.scalars(
            select(FunctionReviewRevision)
            .where(
                FunctionReviewRevision.scope_sha256 == digest,
            )
            .order_by(FunctionReviewRevision.revision.desc())
            .limit(26)
        )
    )
    documents = [validated_overlay(row) for row in rows]
    if any(doc["identity"] != identity for doc in documents):
        raise IntegrityError("Overlay identity mismatch")
    return {
        "identity": identity,
        "scope_sha256": digest,
        "current": documents[0] if documents else None,
        "revisions": documents[:25],
        "history_capped": len(rows) > 25,
        "notice": (
            "Analyst overlay bound to this exact output; it does not "
            "transfer to a new run. Reviewed does not mean harmless."
        ),
    }


@router.get("/runs/{run_id}/ghidra/functions/{index}/review")
def get(request: Request, run_id: str, index: int) -> JSONResponse:
    try:
        with _ctx(request).sessions() as session:
            identity, digest, _ = scope(request, session, run_id, index)
            return JSONResponse(view(session, identity, digest))
    except LookupError:
        return _not_found(request, "function review source")
    except IntegrityError:
        return problem("integrity_error", request_id=_rid(request))


@router.post("/runs/{run_id}/ghidra/functions/{index}/review", status_code=201)
def revise(request: Request, run_id: str, index: int, body: RevisionInput) -> JSONResponse:
    try:
        with _ctx(request).sessions() as session, session.begin():
            identity, digest, text = scope(request, session, run_id, index)
            old = view(session, identity, digest)["current"]
            if (old["revision"] if old else 0) != body.expected_revision:
                return problem("annotation_stale", request_id=_rid(request))
            if body.citation:
                citation = body.citation
                if (
                    text is None
                    or hashlib.sha256(text.encode()).hexdigest() != citation.text_sha256
                    or not citation.start_line <= citation.end_line <= len(text.splitlines())
                ):
                    return problem("invalid_request", request_id=_rid(request))
            now = utcnow()
            document = {
                **body.model_dump(exclude={"expected_revision"}),
                "id": new_id(),
                "identity": identity,
                "revision": body.expected_revision + 1,
                "created_at": now.isoformat(),
                "authorship": "local analyst",
                "source_stale": False,
            }
            session.add(
                FunctionReviewRevision(
                    id=document["id"],
                    version_id=identity["version_id"],
                    invocation_id=identity["invocation_id"],
                    scope_sha256=digest,
                    revision=document["revision"],
                    created_at=now,
                    document=document,
                    document_sha256=hashlib.sha256(canonical_json(document)).hexdigest(),
                )
            )
            session.flush()
            return JSONResponse(view(session, identity, digest), status_code=201)
    except DatabaseConflict:
        return problem("annotation_stale", request_id=_rid(request))
    except LookupError:
        return _not_found(request, "function review source")
    except IntegrityError:
        return problem("integrity_error", request_id=_rid(request))
