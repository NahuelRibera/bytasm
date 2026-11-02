"""Pinned evidence and evidence comparison endpoints (v0.11).

* `/reviews/{id}/evidence[...]` reads the immutable evidence snapshot a review
  pinned. Nothing is recomputed: historical reviews without a snapshot say so.
* `/evidence/compare` compares two evidence states. Each side is either a
  version's current graph (`version:<id>`, built with the live selection
  policy) or a pinned review (`review:<id>`, its stored snapshot).
"""

import hashlib
import json
import time
from collections import OrderedDict
from threading import Lock
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from bytasm.api.context import AppContext
from bytasm.api.evidence import (
    EDGE_TYPES,
    MAX_NEIGHBOR_EDGES,
    MAX_RESPONSE_BYTES,
    GraphFailure,
    _cursor_binding,
    _decode,
    _encode,
    load_graph,
)
from bytasm.api.problems import problem
from bytasm.db.models import SampleVersion
from bytasm.evidence_compare import (
    CHANGE_ORDER,
    ChangeOut,
    Comparison,
    ComparisonOut,
    compare_snapshots,
)
from bytasm.evidence_graph import NODE_ORDER
from bytasm.evidence_snapshot import (
    AddressMapping,
    EvidenceSnapshot,
    SnapshotBounds,
    SnapshotEdge,
    SnapshotJoin,
    SnapshotNode,
    SnapshotSample,
    SnapshotSource,
    build_snapshot,
    verify,
)
from bytasm.review_snapshot import Snapshot, evidence_availability, read_snapshot
from bytasm.storage import IntegrityError

router = APIRouter()
COMPARISON_CACHE_SIZE = 4
_comparisons: "OrderedDict[str, Comparison]" = OrderedDict()
_comparison_lock = Lock()

ReviewId = Annotated[str, Query(max_length=32, pattern=r"^[0-9a-f]{32}$")]
SideRef = Annotated[str, Query(max_length=40, pattern=r"^(?:version|review):[0-9a-f]{32}$")]
RunParam = Annotated[str | None, Query(max_length=32, pattern=r"^[0-9a-f]{32}$")]


class AvailabilityOut(BaseModel):
    state: Literal["captured", "unavailable", "not_captured_historical"]
    reason: str | None


class ReviewEvidenceOut(BaseModel):
    review_id: str
    review_schema: str
    evidence: AvailabilityOut
    snapshot_schema: str | None = None
    algorithm: str | None = None
    content_sha256: str | None = None
    content_verified: bool | None = None
    scope_sha256: str | None = None
    sample: SnapshotSample | None = None
    sources: list[SnapshotSource] = []
    address_mapping: AddressMapping | None = None
    coverage: list[SnapshotJoin] = []
    counts: dict[str, dict[str, int]] = {}
    bounds: SnapshotBounds | None = None
    limitations: list[str] = []


class SnapshotNodePageOut(BaseModel):
    review_id: str
    content_sha256: str
    kind: str | None
    matched: int
    offset: int
    limit: int
    items: list[SnapshotNode]
    next_cursor: str | None


class SnapshotEdgePageOut(BaseModel):
    review_id: str
    content_sha256: str
    type: str | None
    matched: int
    offset: int
    limit: int
    items: list[SnapshotEdge]
    next_cursor: str | None


class SnapshotNodeDetailOut(BaseModel):
    review_id: str
    content_sha256: str
    node: SnapshotNode
    edges: list[SnapshotEdge]
    edges_total: int
    edges_truncated: bool
    neighbors: list[SnapshotNode]


class ChangePageOut(BaseModel):
    filters: dict[str, str | None]
    matched: int
    offset: int
    limit: int
    items: list[ChangeOut]
    next_cursor: str | None


class EvidenceComparisonOut(BaseModel):
    comparison: ComparisonOut
    changes: ChangePageOut
    build_ms: int


def _ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def _fail(request: Request, code: str = "not_found", **extra: Any) -> JSONResponse:
    return problem(code, request_id=request.state.request_id, extra=extra or None)


def _review(request: Request, review_id: str) -> Snapshot | JSONResponse:
    if len(review_id) != 32 or any(c not in "0123456789abcdef" for c in review_id):
        return _fail(request)
    try:
        with _ctx(request).sessions() as session:
            return read_snapshot(session, review_id)[0]
    except LookupError:
        return _fail(request)
    except (IntegrityError, ValidationError):
        return _fail(request, "integrity_error")


def _pinned(request: Request, review_id: str) -> tuple[Snapshot, EvidenceSnapshot] | JSONResponse:
    review = _review(request, review_id)
    if isinstance(review, JSONResponse):
        return review
    if review.evidence is None:
        return _fail(request, "evidence_not_captured", evidence=evidence_availability(review))
    if not verify(review.evidence):
        return _fail(request, "integrity_error")
    return review, review.evidence


def counts(snapshot: EvidenceSnapshot) -> dict[str, dict[str, int]]:
    nodes: dict[str, int] = {}
    edges: dict[str, int] = {}
    strengths: dict[str, int] = {}
    for node in snapshot.nodes:
        nodes[node.kind] = nodes.get(node.kind, 0) + 1
    for edge in snapshot.edges:
        edges[edge.type] = edges.get(edge.type, 0) + 1
        strengths[edge.strength] = strengths.get(edge.strength, 0) + 1
    return {
        "nodes": dict(sorted(nodes.items())),
        "edges": dict(sorted(edges.items())),
        "strengths": dict(sorted(strengths.items())),
    }


@router.get("/reviews/{review_id}/evidence", response_model=ReviewEvidenceOut)
def review_evidence(request: Request, review_id: str) -> ReviewEvidenceOut | JSONResponse:
    review = _review(request, review_id)
    if isinstance(review, JSONResponse):
        return review
    availability = AvailabilityOut.model_validate(evidence_availability(review))
    snapshot = review.evidence
    if snapshot is None:
        return ReviewEvidenceOut(
            review_id=review.id, review_schema=review.schema_version, evidence=availability
        )
    return ReviewEvidenceOut(
        review_id=review.id,
        review_schema=review.schema_version,
        evidence=availability,
        snapshot_schema=snapshot.schema_version,
        algorithm=snapshot.algorithm,
        content_sha256=snapshot.content_sha256,
        content_verified=verify(snapshot),
        scope_sha256=snapshot.scope_sha256,
        sample=snapshot.sample,
        sources=snapshot.sources,
        address_mapping=snapshot.address_mapping,
        coverage=snapshot.coverage,
        counts=counts(snapshot),
        bounds=snapshot.bounds,
        limitations=snapshot.limitations,
    )


@router.get("/reviews/{review_id}/evidence/nodes", response_model=SnapshotNodePageOut)
def review_evidence_nodes(
    request: Request,
    review_id: str,
    kind: Literal[NODE_ORDER] | None = None,  # type: ignore[valid-type]
    q: Annotated[str, Query(max_length=128)] = "",
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> SnapshotNodePageOut | JSONResponse:
    pinned = _pinned(request, review_id)
    if isinstance(pinned, JSONResponse):
        return pinned
    review, snapshot = pinned
    text = q.casefold()
    selected = [
        n
        for n in snapshot.nodes
        if (kind is None or n.kind == kind)
        and (
            not text
            or text in n.label.casefold()
            or (n.address is not None and text in n.address.address.casefold())
        )
    ]
    binding = _cursor_binding(snapshot.content_sha256, "review-nodes", review.id, kind, q, limit)
    try:
        start = _decode(cursor, offset, binding, len(selected))
    except ValueError:
        return _fail(request, "invalid_request")
    end = start + limit
    return SnapshotNodePageOut(
        review_id=review.id,
        content_sha256=snapshot.content_sha256,
        kind=kind,
        matched=len(selected),
        offset=start,
        limit=limit,
        items=selected[start:end],
        next_cursor=_encode(end, len(selected), binding),
    )


@router.get("/reviews/{review_id}/evidence/edges", response_model=SnapshotEdgePageOut)
def review_evidence_edges(
    request: Request,
    review_id: str,
    type: Literal[EDGE_TYPES] | None = None,  # type: ignore[valid-type]
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> SnapshotEdgePageOut | JSONResponse:
    pinned = _pinned(request, review_id)
    if isinstance(pinned, JSONResponse):
        return pinned
    review, snapshot = pinned
    selected = [e for e in snapshot.edges if type is None or e.type == type]
    binding = _cursor_binding(snapshot.content_sha256, "review-edges", review.id, type, limit)
    try:
        start = _decode(cursor, offset, binding, len(selected))
    except ValueError:
        return _fail(request, "invalid_request")
    end = start + limit
    return SnapshotEdgePageOut(
        review_id=review.id,
        content_sha256=snapshot.content_sha256,
        type=type,
        matched=len(selected),
        offset=start,
        limit=limit,
        items=selected[start:end],
        next_cursor=_encode(end, len(selected), binding),
    )


@router.get("/reviews/{review_id}/evidence/nodes/{node_id}", response_model=SnapshotNodeDetailOut)
def review_evidence_node(
    request: Request,
    review_id: str,
    node_id: str,
    edge_type: Literal[EDGE_TYPES] | None = None,  # type: ignore[valid-type]
) -> SnapshotNodeDetailOut | JSONResponse:
    if len(node_id) > 64:
        return _fail(request)
    pinned = _pinned(request, review_id)
    if isinstance(pinned, JSONResponse):
        return pinned
    review, snapshot = pinned
    nodes = {n.id: n for n in snapshot.nodes}
    node = nodes.get(node_id)
    if node is None:
        return _fail(request)
    edges = [
        e
        for e in snapshot.edges
        if node_id in (e.source, e.target) and (edge_type is None or e.type == edge_type)
    ]
    kept = edges[:MAX_NEIGHBOR_EDGES]
    order = {n.id: i for i, n in enumerate(snapshot.nodes)}
    neighbor_ids = sorted(
        {e.target if e.source == node_id else e.source for e in kept} - {node_id},
        key=lambda n: order.get(n, 0),
    )
    response = SnapshotNodeDetailOut(
        review_id=review.id,
        content_sha256=snapshot.content_sha256,
        node=node,
        edges=kept,
        edges_total=len(edges),
        edges_truncated=len(edges) > len(kept),
        neighbors=[nodes[n] for n in neighbor_ids if n in nodes],
    )
    if len(response.model_dump_json().encode()) > MAX_RESPONSE_BYTES:
        return _fail(request, "report_too_large")
    return response


# --------------------------------------------------------------------------- compare


def _side(
    ctx: AppContext,
    ref: str,
    ghidra_run_id: str | None,
    analysis_run_id: str | None,
) -> tuple[EvidenceSnapshot, dict[str, Any], str] | str:
    """Resolve a side to (snapshot, side descriptor, project ID) or a problem code."""
    kind, _, identifier = ref.partition(":")
    with ctx.sessions() as session:
        if kind == "review":
            if ghidra_run_id or analysis_run_id:
                return "invalid_request"  # a pinned side never selects live runs
            try:
                review, _ = read_snapshot(session, identifier)
            except LookupError:
                return "not_found"
            except (IntegrityError, ValidationError):
                return "integrity_error"
            if review.evidence is None:
                return "evidence_not_captured"
            if not verify(review.evidence):
                return "integrity_error"
            version = session.get(SampleVersion, review.sample.version_id)
            if version is None:
                return "not_found"
            return (
                review.evidence,
                {"kind": "pinned_review", "review_id": review.id},
                version.sample.project_id,
            )
        version = session.get(SampleVersion, identifier)
        if version is None:
            return "not_found"
        try:
            graph, _ = load_graph(ctx, session, version, ghidra_run_id, analysis_run_id)
        except GraphFailure as failure:
            return failure.code
        sample = SnapshotSample(
            version_id=version.id,
            sample_id=version.sample_id,
            sha256=version.sha256,
            size_bytes=version.size_bytes,
            format=version.detected_format,
        )
        project_id = version.sample.project_id
    try:
        snapshot = build_snapshot(graph, sample)
    except ValueError:
        return "report_too_large"
    return snapshot, {"kind": "version_current", "review_id": None}, project_id


@router.get("/evidence/compare", response_model=EvidenceComparisonOut)
def compare_evidence(
    request: Request,
    a: SideRef,
    b: SideRef,
    a_ghidra_run_id: RunParam = None,
    a_analysis_run_id: RunParam = None,
    b_ghidra_run_id: RunParam = None,
    b_analysis_run_id: RunParam = None,
    category: Literal["node", "edge"] | None = None,
    change: Literal[CHANGE_ORDER] | None = None,  # type: ignore[valid-type]
    kind: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_]+$")] = None,
    attribution: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_]+$")] = None,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EvidenceComparisonOut | JSONResponse:
    ctx = _ctx(request)
    started = time.monotonic()
    left = _side(ctx, a, a_ghidra_run_id, a_analysis_run_id)
    if isinstance(left, str):
        return _fail(request, left)
    right = _side(ctx, b, b_ghidra_run_id, b_analysis_run_id)
    if isinstance(right, str):
        return _fail(request, right)
    snap_a, side_a, project_a = left
    snap_b, side_b, project_b = right
    if project_a != project_b:
        # Evidence never crosses project boundaries.
        return _fail(request, "invalid_request")
    key = hashlib.sha256(
        json.dumps(
            [
                snap_a.scope_sha256,
                snap_a.content_sha256,
                side_a,
                snap_b.scope_sha256,
                snap_b.content_sha256,
                side_b,
            ],
            sort_keys=True,
        ).encode()
    ).hexdigest()
    with _comparison_lock:
        comparison = _comparisons.get(key)
        if comparison is not None:
            _comparisons.move_to_end(key)
    if comparison is None:
        comparison = compare_snapshots(snap_a, snap_b, side_a, side_b)
        with _comparison_lock:
            _comparisons[key] = comparison
            while len(_comparisons) > COMPARISON_CACHE_SIZE:
                _comparisons.popitem(last=False)
    selected = [
        c
        for c in comparison.changes
        if (category is None or c.category == category)
        and (change is None or c.change == change)
        and (kind is None or c.kind == kind)
        and (attribution is None or c.attribution == attribution)
    ]
    binding = _cursor_binding(
        comparison.summary.comparison_sha256, "changes", category, change, kind, attribution, limit
    )
    try:
        start = _decode(cursor, offset, binding, len(selected))
    except ValueError:
        return _fail(request, "invalid_request")
    end = start + limit
    response = EvidenceComparisonOut(
        comparison=comparison.summary,
        changes=ChangePageOut(
            filters={
                "category": category,
                "change": change,
                "kind": kind,
                "attribution": attribution,
            },
            matched=len(selected),
            offset=start,
            limit=limit,
            items=selected[start:end],
            next_cursor=_encode(end, len(selected), binding),
        ),
        build_ms=int((time.monotonic() - started) * 1000),
    )
    if len(response.model_dump_json().encode()) > 4 * MAX_RESPONSE_BYTES:
        return _fail(request, "report_too_large")
    return response
