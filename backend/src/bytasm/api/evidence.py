"""Evidence correlation endpoints (v0.10): one graph, two readings.

`/evidence` returns the Understand view (claims, coverage, layout) and
`/evidence/nodes`, `/evidence/nodes/{id}` and `/evidence/edges` the Investigate
view. Both are computed from the same graph, built from stored, revalidated
outputs of exactly one import record, at most one Ghidra run and at most one
pattern run of the same sample version.
"""

import base64
import hashlib
import json
import time
from collections import OrderedDict
from threading import Lock
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from bytasm.address_map import DeclaredLayout
from bytasm.api.context import AppContext
from bytasm.api.ghidra import _read as read_ghidra
from bytasm.api.problems import problem
from bytasm.db.imported import ImportRecordMissing, import_record
from bytasm.db.models import AnalysisRun, Finding, RuleSet, SampleVersion, StringOccurrence
from bytasm.evidence_graph import (
    GRAPH_SCHEMA,
    NODE_ORDER,
    EdgeOut,
    EvidenceRecord,
    FindingRecord,
    GhidraSource,
    Graph,
    MetadataSource,
    NodeOut,
    PatternSource,
    StepRecord,
    StringRecord,
    build_graph,
    scope_digest,
    sort_key,
)
from bytasm.evidence_understand import (
    ClaimOut,
    CoverageOut,
    LayoutOut,
    build_claims,
    build_coverage,
    build_layout,
)
from bytasm.jobs import summary
from bytasm.storage import IntegrityError

router = APIRouter()
TERMINAL = ("succeeded", "partial")
CACHE_SIZE = 8
MAX_NEIGHBOR_EDGES = 256
MAX_RESPONSE_BYTES = 1024 * 1024
SELECTION_POLICY = "latest-completed-per-source-v1"

_cache: "OrderedDict[str, Graph]" = OrderedDict()
_cache_lock = Lock()


class SourceOut(BaseModel):
    source: Literal["metadata", "ghidra", "pattern"]
    run_id: str | None
    status: str | None
    profile_id: str | None
    selected_by: Literal["explicit", "latest_completed", "import_record", "none"]
    newer_unselected_run_ids: list[str]
    unavailable_reason: str | None


class ScopeOut(BaseModel):
    schema_version: str
    scope_sha256: str
    project_id: str
    version_id: str
    sha256: str
    file_format: str
    selection_policy: str
    sources: list[SourceOut]


class CountsOut(BaseModel):
    nodes: dict[str, int]
    edges: dict[str, int]
    strengths: dict[str, int]


class EvidenceSummaryOut(BaseModel):
    scope: ScopeOut
    counts: CountsOut
    coverage: CoverageOut
    claims: list[ClaimOut]
    claims_total: int
    claims_truncated: bool
    layout: LayoutOut
    limitations: list[str]
    build_ms: int


class NodePageOut(BaseModel):
    scope_sha256: str
    kind: str | None
    matched: int
    offset: int
    limit: int
    items: list[NodeOut]
    next_cursor: str | None


class EdgePageOut(BaseModel):
    scope_sha256: str
    type: str | None
    matched: int
    offset: int
    limit: int
    items: list[EdgeOut]
    next_cursor: str | None


class NodeDetailOut(BaseModel):
    scope_sha256: str
    node: NodeOut
    edges: list[EdgeOut]
    edges_total: int
    edges_truncated: bool
    neighbors: list[NodeOut]
    claims: list[str]


def _ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def _fail(request: Request, code: str = "not_found") -> JSONResponse:
    return problem(code, request_id=request.state.request_id)


def _ordered(session: Session, version_id: str) -> list[AnalysisRun]:
    return list(
        session.scalars(
            select(AnalysisRun)
            .where(AnalysisRun.sample_version_id == version_id, AnalysisRun.kind == "analysis")
            .order_by(AnalysisRun.queued_at.desc(), AnalysisRun.id.desc())
        )
    )


def _is_ghidra(run: AnalysisRun) -> bool:
    return run.profile_snapshot.get("id") == "ghidra-static"


def _select(
    session: Session,
    version: SampleVersion,
    explicit: str | None,
    ghidra: bool,
) -> tuple[AnalysisRun | None, SourceOut] | None:
    source: Literal["ghidra", "pattern"] = "ghidra" if ghidra else "pattern"
    candidates = [r for r in _ordered(session, version.id) if _is_ghidra(r) == ghidra]

    def usable(run: AnalysisRun) -> bool:
        if run.status not in TERMINAL:
            return False
        if ghidra:
            return any(i.tool_name == "ghidra" and i.status == "succeeded" for i in run.invocations)
        return True

    if explicit is not None:
        run = next((r for r in candidates if r.id == explicit), None)
        # Cross-version or wrong-profile identifiers are refused, never substituted.
        if run is None or not usable(run):
            return None
        selected_by: Literal["explicit", "latest_completed", "import_record", "none"] = "explicit"
    else:
        run = next((r for r in candidates if usable(r)), None)
        selected_by = "latest_completed" if run else "none"
    newer = []
    for candidate in candidates:
        if run is not None and candidate.id == run.id:
            break
        newer.append(candidate.id)
    return run, SourceOut(
        source=source,
        run_id=run.id if run else None,
        status=run.status if run else None,
        profile_id=str(run.profile_snapshot.get("id")) if run else None,
        selected_by=selected_by,
        newer_unselected_run_ids=newer[:16] if run else [],
        unavailable_reason=None
        if run
        else (
            "No completed Ghidra run exists for this version."
            if ghidra
            else "No completed pattern run exists for this version."
        ),
    )


def _pattern(session: Session, run: AnalysisRun) -> PatternSource:
    views = summary.step_views(run)
    steps = tuple(
        StepRecord(
            tool=v.tool,
            status=v.status,
            invocation_id=v.invocation.id if v.invocation else None,
            tool_version=v.invocation.tool_version if v.invocation else None,
        )
        for v in views
    )
    findings: list[FindingRecord] = []
    for inv in run.invocations:
        if inv.status != "succeeded":
            continue
        rows = session.execute(
            select(Finding, RuleSet.sha256)
            .join(RuleSet, RuleSet.id == Finding.rule_set_id, isouter=True)
            .where(Finding.invocation_id == inv.id)
            .order_by(Finding.id)
        ).all()
        for finding, rule_set_sha256 in rows:
            findings.append(
                FindingRecord(
                    id=finding.id,
                    tool=str(finding.tool_reported_attributes.get("tool", inv.tool_name)),
                    tool_version=inv.tool_version,
                    rule_id=finding.rule_id,
                    namespace=finding.rule_namespace,
                    rule_set_sha256=rule_set_sha256 or "",
                    invocation_id=inv.id,
                    output_sha256=inv.raw_output_sha256,
                    match_count=finding.match_count,
                    evidence_truncated=finding.evidence_truncated,
                    evidence=tuple(
                        EvidenceRecord(
                            id=e.id,
                            kind=e.kind,
                            file_offset=e.file_offset,
                            length=e.length,
                            virtual_address=e.virtual_address,
                            pointer=e.raw_json_pointer,
                        )
                        for e in finding.evidence
                    ),
                )
            )
    strings_inv = summary.strings_invocation(run)
    strings = None
    truncated = False
    if strings_inv is not None:
        occurrences = session.scalars(
            select(StringOccurrence)
            .where(StringOccurrence.invocation_id == strings_inv.id)
            .order_by(StringOccurrence.file_offset, StringOccurrence.encoding)
        )
        strings = tuple(
            StringRecord(r.id, r.file_offset, r.encoding, r.value, r.value_truncated)
            for r in occurrences
        )
        truncated = bool((strings_inv.summary or {}).get("truncated"))
    return PatternSource(
        run_id=run.id,
        status=run.status,
        profile_id=str(run.profile_snapshot.get("id")),
        steps=steps,
        findings=tuple(findings),
        strings=strings,
        strings_invocation_id=strings_inv.id if strings_inv else None,
        strings_output_sha256=strings_inv.raw_output_sha256 if strings_inv else None,
        strings_truncated=truncated,
    )


def _graph(
    request: Request,
    version_id: str,
    ghidra_run_id: str | None,
    analysis_run_id: str | None,
) -> tuple[Graph, ScopeOut, int] | JSONResponse:
    ctx = _ctx(request)
    started = time.monotonic()
    with ctx.sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            return _fail(request)
        try:
            record = import_record(version)
        except ImportRecordMissing:
            return _fail(request, "integrity_error")
        ghidra_sel = _select(session, version, ghidra_run_id, ghidra=True)
        pattern_sel = _select(session, version, analysis_run_id, ghidra=False)
        if ghidra_sel is None or pattern_sel is None:
            return _fail(request)
        ghidra_run, ghidra_out = ghidra_sel
        pattern_run, pattern_out = pattern_sel
        header = record.header
        metadata = MetadataSource(
            run_id=record.run.id,
            invocation_id=record.invocation.id,
            output_sha256=record.raw_output_sha256,
            tool_version=record.invocation.tool_version,
            file_format=str(header.get("format", version.detected_format)),
            file_size=version.size_bytes,
            entry_point=header.get("entry_point"),
            layout=DeclaredLayout.from_import(header, list(record.invocation.sections)),
            imports=tuple(
                sorted(s.name for s in record.invocation.symbols if s.direction == "import")
            ),
            imported_libraries=tuple(header.get("imported_libraries", [])),
        )
        ghidra_source = None
        if ghidra_run is not None:
            inv = next(i for i in ghidra_run.invocations if i.tool_name == "ghidra")
            try:
                result = read_ghidra(ctx, ghidra_run, inv)
            except IntegrityError:
                return _fail(request, "integrity_error")
            ghidra_source = GhidraSource(ghidra_run.id, inv.id, inv.raw_output_sha256 or "", result)
        pattern = _pattern(session, pattern_run) if pattern_run is not None else None
        scope = scope_digest(version.id, version.sha256, metadata, ghidra_source, pattern)
        with _cache_lock:
            graph = _cache.get(scope)
            if graph is not None:
                _cache.move_to_end(scope)
        if graph is None:
            graph = build_graph(version.id, version.sha256, metadata, ghidra_source, pattern)
            # Only terminal runs reach this point, so the inputs cannot change.
            with _cache_lock:
                _cache[scope] = graph
                while len(_cache) > CACHE_SIZE:
                    _cache.popitem(last=False)
        scope_out = ScopeOut(
            schema_version=GRAPH_SCHEMA,
            scope_sha256=graph.scope_sha256,
            project_id=version.sample.project_id,
            version_id=version.id,
            sha256=version.sha256,
            file_format=metadata.file_format,
            selection_policy=SELECTION_POLICY,
            sources=[
                SourceOut(
                    source="metadata",
                    run_id=record.run.id,
                    status=record.run.status,
                    profile_id=None,
                    selected_by="import_record",
                    newer_unselected_run_ids=[],
                    unavailable_reason=None,
                ),
                ghidra_out,
                pattern_out,
            ],
        )
    return graph, scope_out, int((time.monotonic() - started) * 1000)


RunParam = Annotated[str | None, Query(max_length=32, pattern=r"^[0-9a-f]{32}$")]


@router.get("/sample-versions/{version_id}/evidence", response_model=EvidenceSummaryOut)
def evidence_summary(
    request: Request,
    version_id: str,
    ghidra_run_id: RunParam = None,
    analysis_run_id: RunParam = None,
) -> EvidenceSummaryOut | JSONResponse:
    built = _graph(request, version_id, ghidra_run_id, analysis_run_id)
    if isinstance(built, JSONResponse):
        return built
    graph, scope, build_ms = built
    claims, total = build_claims(graph, version_id)
    counts = CountsOut(nodes={}, edges={}, strengths={})
    for node in graph.nodes.values():
        counts.nodes[node.kind] = counts.nodes.get(node.kind, 0) + 1
    for edge in graph.edges.values():
        counts.edges[edge.type] = counts.edges.get(edge.type, 0) + 1
        counts.strengths[edge.strength] = counts.strengths.get(edge.strength, 0) + 1
    counts.nodes = dict(sorted(counts.nodes.items()))
    counts.edges = dict(sorted(counts.edges.items()))
    counts.strengths = dict(sorted(counts.strengths.items()))
    return EvidenceSummaryOut(
        scope=scope,
        counts=counts,
        coverage=build_coverage(graph),
        claims=claims,
        claims_total=total,
        claims_truncated=total > len(claims),
        layout=build_layout(graph),
        limitations=graph.limitations,
        build_ms=build_ms,
    )


def _cursor_binding(scope: str, *parts: object) -> str:
    return hashlib.sha256(json.dumps([scope, *parts], sort_keys=True).encode()).hexdigest()


def _decode(cursor: str | None, offset: int, binding: str, maximum: int) -> int:
    if cursor is None:
        return offset
    if offset:
        raise ValueError("Cursor cannot be combined with offset")
    try:
        position, supplied = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("Invalid cursor") from exc
    if type(position) is not int or not 0 <= position <= maximum or supplied != binding:
        raise ValueError("Invalid cursor")
    return position


def _encode(end: int, total: int, binding: str) -> str | None:
    if end >= total:
        return None
    return base64.urlsafe_b64encode(json.dumps([end, binding]).encode()).decode()


@router.get("/sample-versions/{version_id}/evidence/nodes", response_model=NodePageOut)
def evidence_nodes(
    request: Request,
    version_id: str,
    kind: Literal[NODE_ORDER] | None = None,  # type: ignore[valid-type]
    q: Annotated[str, Query(max_length=128)] = "",
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ghidra_run_id: RunParam = None,
    analysis_run_id: RunParam = None,
) -> NodePageOut | JSONResponse:
    built = _graph(request, version_id, ghidra_run_id, analysis_run_id)
    if isinstance(built, JSONResponse):
        return built
    graph, _, _ = built
    text = q.casefold()
    selected = sorted(
        (
            n
            for n in graph.nodes.values()
            if (kind is None or n.kind == kind)
            and (
                not text
                or text in n.label.casefold()
                or (n.address is not None and text in n.address.address.casefold())
            )
        ),
        key=sort_key,
    )
    binding = _cursor_binding(graph.scope_sha256, "nodes", kind, q, limit)
    try:
        start = _decode(cursor, offset, binding, len(selected))
    except ValueError:
        return _fail(request, "invalid_request")
    end = start + limit
    return NodePageOut(
        scope_sha256=graph.scope_sha256,
        kind=kind,
        matched=len(selected),
        offset=start,
        limit=limit,
        items=selected[start:end],
        next_cursor=_encode(end, len(selected), binding),
    )


EDGE_TYPES = (
    "calls",
    "references_string",
    "references_data",
    "references_external_symbol",
    "target_is_string_occurrence",
    "capa_match_at_function_entry",
    "yara_match_in_function_body",
    "entry_point_is_function",
    "located_in_section",
    "external_symbol_named_as_import",
)


@router.get("/sample-versions/{version_id}/evidence/edges", response_model=EdgePageOut)
def evidence_edges(
    request: Request,
    version_id: str,
    type: Literal[EDGE_TYPES] | None = None,  # type: ignore[valid-type]
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ghidra_run_id: RunParam = None,
    analysis_run_id: RunParam = None,
) -> EdgePageOut | JSONResponse:
    built = _graph(request, version_id, ghidra_run_id, analysis_run_id)
    if isinstance(built, JSONResponse):
        return built
    graph, _, _ = built
    selected = sorted(
        (e for e in graph.edges.values() if type is None or e.type == type),
        key=lambda e: (e.type, sort_key(graph.nodes[e.source]), sort_key(graph.nodes[e.target])),
    )
    binding = _cursor_binding(graph.scope_sha256, "edges", type, limit)
    try:
        start = _decode(cursor, offset, binding, len(selected))
    except ValueError:
        return _fail(request, "invalid_request")
    end = start + limit
    return EdgePageOut(
        scope_sha256=graph.scope_sha256,
        type=type,
        matched=len(selected),
        offset=start,
        limit=limit,
        items=selected[start:end],
        next_cursor=_encode(end, len(selected), binding),
    )


@router.get("/sample-versions/{version_id}/evidence/nodes/{node_id}", response_model=NodeDetailOut)
def evidence_node(
    request: Request,
    version_id: str,
    node_id: str,
    edge_type: Literal[EDGE_TYPES] | None = None,  # type: ignore[valid-type]
    ghidra_run_id: RunParam = None,
    analysis_run_id: RunParam = None,
) -> NodeDetailOut | JSONResponse:
    if len(node_id) > 64:
        return _fail(request)
    built = _graph(request, version_id, ghidra_run_id, analysis_run_id)
    if isinstance(built, JSONResponse):
        return built
    graph, _, _ = built
    node = graph.nodes.get(node_id)
    if node is None:
        return _fail(request)
    edges = [e for e in graph.edges_of(node_id) if edge_type is None or e.type == edge_type]
    edges.sort(
        key=lambda e: (e.type, sort_key(graph.nodes[e.source]), sort_key(graph.nodes[e.target]))
    )
    kept = edges[:MAX_NEIGHBOR_EDGES]
    neighbor_ids = sorted(
        {e.target if e.source == node_id else e.source for e in kept} - {node_id},
        key=lambda n: sort_key(graph.nodes[n]),
    )
    claims, _ = build_claims(graph, version_id)
    response = NodeDetailOut(
        scope_sha256=graph.scope_sha256,
        node=node,
        edges=kept,
        edges_total=len(edges),
        edges_truncated=len(edges) > len(kept),
        neighbors=[graph.nodes[n] for n in neighbor_ids],
        claims=[c.id for c in claims if node_id in c.subjects],
    )
    if len(response.model_dump_json().encode()) > MAX_RESPONSE_BYTES:
        return _fail(request, "report_too_large")
    return response
