"""Immutable, bounded evidence snapshots (v0.11).

A snapshot is a normalized copy of one evidence graph: its nodes, typed
edges, join coverage, address-mapping provenance and the exact identity of
every source that produced it. Pinned reviews embed one. A snapshot is never
recomputed after it is written; a later tool upgrade, rule change, new run or
algorithm change cannot alter it.

Two digests are kept, for two different questions:

* `scope_sha256` is the graph's scope digest. It includes database run and
  invocation identifiers, so it answers "were these exact stored records
  used?".
* `content_sha256` excludes every database identifier (run, invocation,
  finding and string row IDs) and raw-output digests, which stay recorded as
  provenance. It answers "did the same evidence result from the same inputs
  and tool identities?": two databases that analyzed identical bytes with
  identical tools produce the same content digest.

Snapshots are bounded. When a graph exceeds the bounds, nodes are retained
in a fixed kind priority and canonical order, edges only between retained
nodes, and everything omitted is counted per kind or type. Nothing is
silently dropped.
"""

import hashlib
import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from bytasm.evidence_graph import (
    EdgeOut,
    Graph,
    LocatorOut,
    NodeOut,
    sort_key,
)

SNAPSHOT_SCHEMA = "bytasm-evidence-snapshot-1"
MAX_NODES = 4096
MAX_EDGES = 8192
MAX_LOCATORS = 4
MAX_SOURCES_PER_NODE = 4
MAX_TEXT = 256
MAX_LIST = 64
MAX_SNAPSHOT_BYTES = 1536 * 1024
MIN_NODE_BUDGET = 16
# Retention priority when a graph exceeds the bounds. Structure and findings
# come first because comparisons and claims depend on them most.
RETENTION_ORDER: tuple[str, ...] = (
    "entry_point",
    "section",
    "finding",
    "function",
    "import",
    "external_symbol",
    "program_data",
    "string",
)
STRENGTH_ORDER: tuple[str, ...] = (
    "exact_reference",
    "exact_offset_equality",
    "address_containment",
    "offset_containment",
    "structural_containment",
    "name_equality",
)
# Database row identifiers that differ between databases for identical inputs.
DATABASE_IDENTITY_KEYS = frozenset({"finding_id", "string_id"})

SourceName = Literal["lief", "ghidra", "strings", "yara-x", "capa"]
Text = Annotated[str, Field(max_length=MAX_TEXT)]
Scalar = str | int | bool | None


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SnapshotSample(Strict):
    version_id: str
    sample_id: str
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: int = Field(ge=0)
    format: Text


class SnapshotSource(Strict):
    """One tool's contribution, or the exact reason it contributed nothing."""

    source: SourceName
    state: Literal["available", "unavailable"]
    unavailable_reason: Text | None = None
    status: Text | None = None
    run_id: str | None = None
    invocation_id: str | None = None
    output_sha256: str | None = None
    tool_version: Text | None = None
    adapter_version: Text | None = None
    protocol_version: Text | None = None
    rule_set_sha256: str | None = None
    profile_sha256: str | None = None
    script_sha256: str | None = None
    # Whether the source's own retained window was capped (never a guess).
    retention: dict[Text, Scalar] = Field(default_factory=dict)


class SnapshotLocator(Strict):
    tool: Text
    tool_version: Text
    run_id: str
    invocation_id: str
    output_sha256: str | None
    pointer: Annotated[str, Field(max_length=512)]


class SnapshotAddress(Strict):
    space: Annotated[str, Field(max_length=64)]
    address: Annotated[str, Field(max_length=128)]


class SnapshotNode(Strict):
    id: Annotated[str, Field(max_length=64)]
    kind: Text
    # Untrusted text from the file or a tool. Render escaped.
    label: Text
    label_truncated: bool
    identity: dict[Text, Scalar]
    address: SnapshotAddress | None
    file_offset: int | None
    file_offset_basis: Text | None
    file_offset_state: Text | None
    attributes: dict[Text, Any]
    sources: Annotated[list[SnapshotLocator], Field(max_length=MAX_SOURCES_PER_NODE)]
    sources_total: int = Field(ge=0)


class SnapshotEdge(Strict):
    id: Annotated[str, Field(max_length=64)]
    type: Text
    strength: Text
    source: Annotated[str, Field(max_length=64)]
    target: Annotated[str, Field(max_length=64)]
    basis: Annotated[list[Text], Field(max_length=8)]
    locators: Annotated[list[SnapshotLocator], Field(max_length=MAX_LOCATORS)]
    locator_count: int = Field(ge=0)
    locators_truncated: bool
    attributes: dict[Text, Any]


class SnapshotJoin(Strict):
    join: Text
    performed: bool
    reason: Annotated[str, Field(max_length=512)] | None
    candidates: int = Field(ge=0)
    joined: int = Field(ge=0)
    not_joined: dict[Text, int]


class AddressMapping(Strict):
    """How addresses were related to file offsets when the graph was built."""

    declared_image_base: int | None
    declared_basis: Literal["lief_section_declaration"] = "lief_section_declaration"
    ghidra_protocol: Text | None
    ghidra_memory_map: Literal["available", "unavailable", "not_selected"]
    ghidra_memory_map_reason: Annotated[str, Field(max_length=512)] | None
    ghidra_image_base: SnapshotAddress | None
    ghidra_rejected_file_ranges: int = Field(ge=0)
    ghidra_map_truncated: bool
    ghidra_basis: Literal["ghidra_memory_block_file_bytes"] = "ghidra_memory_block_file_bytes"


class SnapshotBounds(Strict):
    max_nodes: int
    max_edges: int
    max_bytes: int
    nodes_total: int = Field(ge=0)
    edges_total: int = Field(ge=0)
    nodes_retained: int = Field(ge=0)
    edges_retained: int = Field(ge=0)
    truncated: bool
    omitted_nodes_by_kind: dict[Text, int]
    omitted_edges_by_type: dict[Text, int]
    retention_order: list[Text]


class EvidenceSnapshot(Strict):
    schema_version: Literal["bytasm-evidence-snapshot-1"] = "bytasm-evidence-snapshot-1"
    algorithm: Text
    sample: SnapshotSample
    scope_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    content_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    sources: Annotated[list[SnapshotSource], Field(max_length=5)]
    address_mapping: AddressMapping
    coverage: Annotated[list[SnapshotJoin], Field(max_length=32)]
    nodes: Annotated[list[SnapshotNode], Field(max_length=MAX_NODES)]
    edges: Annotated[list[SnapshotEdge], Field(max_length=MAX_EDGES)]
    bounds: SnapshotBounds
    limitations: Annotated[list[Annotated[str, Field(max_length=1024)]], Field(max_length=32)]


class EvidenceStatus(Strict):
    """Whether a review carries an evidence snapshot, and why not."""

    state: Literal["captured", "unavailable"]
    reason: Annotated[str, Field(max_length=512)] | None = None


# --------------------------------------------------------------------------- normalize


def _text(value: str, limit: int = MAX_TEXT) -> str:
    return value[:limit]


def _value(value: Any, depth: int = 0) -> Any:
    """Bound one attribute value: scalars, short lists, shallow string-keyed maps."""
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        # Floats never reach graph attributes today; keep exact text if one does.
        return repr(value)
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, list | tuple):
        return [_value(v, depth + 1) for v in list(value)[:MAX_LIST]] if depth < 2 else None
    if isinstance(value, dict):
        if depth >= 2:
            return None
        return {_text(str(k)): _value(v, depth + 1) for k, v in sorted(value.items())[:MAX_LIST]}
    return _text(str(value))


def _locator(loc: LocatorOut) -> SnapshotLocator:
    return SnapshotLocator(
        tool=_text(loc.tool),
        tool_version=_text(loc.tool_version),
        run_id=loc.run_id,
        invocation_id=loc.invocation_id,
        output_sha256=loc.output_sha256,
        pointer=loc.pointer[:512],
    )


def _node(node: NodeOut) -> SnapshotNode:
    return SnapshotNode(
        id=node.id,
        kind=node.kind,
        label=_text(node.label),
        label_truncated=len(node.label) > MAX_TEXT,
        identity={_text(k): _value(v) for k, v in sorted(node.identity.items())},
        address=(
            None
            if node.address is None
            else SnapshotAddress(space=node.address.space, address=node.address.address)
        ),
        file_offset=node.file_offset,
        file_offset_basis=node.file_offset_basis,
        file_offset_state=node.file_offset_state,
        attributes={_text(k): _value(v) for k, v in sorted(node.attributes.items())},
        sources=[_locator(s) for s in node.sources[:MAX_SOURCES_PER_NODE]],
        sources_total=len(node.sources),
    )


def _edge(edge: EdgeOut) -> SnapshotEdge:
    return SnapshotEdge(
        id=edge.id,
        type=edge.type,
        strength=edge.strength,
        source=edge.source,
        target=edge.target,
        basis=[_text(b) for b in edge.basis[:8]],
        locators=[_locator(loc) for loc in edge.locators[:MAX_LOCATORS]],
        locator_count=edge.locator_count,
        locators_truncated=edge.locators_truncated or len(edge.locators) > MAX_LOCATORS,
        attributes={_text(k): _value(v) for k, v in sorted(edge.attributes.items())},
    )


def _sources(graph: Graph) -> list[SnapshotSource]:
    meta = graph.metadata
    out = [
        SnapshotSource(
            source="lief",
            state="available",
            status="succeeded",
            run_id=meta.run_id,
            invocation_id=meta.invocation_id,
            output_sha256=meta.output_sha256,
            tool_version=meta.tool_version,
        )
    ]
    if graph.ghidra is None:
        out.append(
            SnapshotSource(
                source="ghidra",
                state="unavailable",
                unavailable_reason="No completed Ghidra run was selected.",
            )
        )
    else:
        result = graph.ghidra.result
        out.append(
            SnapshotSource(
                source="ghidra",
                state="available",
                status="succeeded",
                run_id=graph.ghidra.run_id,
                invocation_id=graph.ghidra.invocation_id,
                output_sha256=graph.ghidra.output_sha256,
                tool_version=result.ghidra_version,
                protocol_version=result.schema_version,
                profile_sha256=result.profile_sha256,
                script_sha256=result.script_sha256,
                retention={
                    "function_count": result.function_count,
                    "functions_retained": len(result.functions),
                    "functions_truncated": result.functions_truncated,
                    "analysis_timed_out": result.analysis_timed_out,
                    "detailed_functions": sum(
                        f.pseudocode_status != "not_selected" for f in result.functions
                    ),
                    "memory_blocks_truncated": result.memory_blocks_truncated,
                },
            )
        )
    steps = {s.tool: s for s in graph.pattern.steps} if graph.pattern else {}
    pattern_tools: tuple[SourceName, ...] = ("strings", "yara-x", "capa")
    for tool in pattern_tools:
        step = steps.get(tool)
        if graph.pattern is None or step is None:
            out.append(
                SnapshotSource(
                    source=tool,
                    state="unavailable",
                    unavailable_reason="No completed pattern run was selected."
                    if graph.pattern is None
                    else f"The selected pattern source has no {tool} step.",
                )
            )
            continue
        available = step.status == "succeeded" and step.invocation_id is not None
        out.append(
            SnapshotSource(
                source=tool,
                state="available" if available else "unavailable",
                unavailable_reason=None
                if available
                else f"The {tool} step is {step.status.replace('_', ' ')}; no evidence is "
                "available and no absence is inferred.",
                status=step.status,
                run_id=step.run_id or (graph.pattern.run_id if available else None),
                invocation_id=step.invocation_id,
                output_sha256=step.output_sha256,
                tool_version=step.tool_version,
                adapter_version=step.adapter_version,
                rule_set_sha256=step.rule_set_sha256,
                retention=_pattern_retention(graph, tool) if available else {},
            )
        )
    return out


def _pattern_retention(graph: Graph, tool: str) -> dict[str, Scalar]:
    pattern = graph.pattern
    if pattern is None:
        return {}
    if tool == "strings":
        return {
            "strings_retained": len(pattern.strings or ()),
            "truncated": pattern.strings_truncated,
        }
    findings = [f for f in pattern.findings if f.tool == tool]
    return {
        "findings": len(findings),
        "findings_with_capped_evidence": sum(f.evidence_truncated for f in findings),
    }


def _mapping(graph: Graph) -> AddressMapping:
    gmap = graph.ghidra_map
    result = graph.ghidra.result if graph.ghidra else None
    return AddressMapping(
        declared_image_base=graph.metadata.layout.image_base,
        ghidra_protocol=result.schema_version if result else None,
        ghidra_memory_map="not_selected"
        if gmap is None
        else "available"
        if gmap.available
        else "unavailable",
        ghidra_memory_map_reason=gmap.reason if gmap else None,
        ghidra_image_base=(
            SnapshotAddress(space=gmap.image_base.space, address=gmap.image_base.address)
            if gmap is not None and gmap.image_base is not None
            else None
        ),
        ghidra_rejected_file_ranges=gmap.rejected_ranges if gmap else 0,
        ghidra_map_truncated=gmap.truncated if gmap else False,
    )


def _coverage(graph: Graph) -> list[SnapshotJoin]:
    return [
        SnapshotJoin(
            join=name,
            performed=join.performed,
            reason=join.reason[:512] if join.reason else None,
            candidates=join.candidates,
            joined=join.joined,
            not_joined=dict(sorted(join.unmapped.items())),
        )
        for name, join in sorted(graph.joins.items())
    ]


def _retained(graph: Graph, node_budget: int) -> tuple[list[NodeOut], list[EdgeOut]]:
    ranked = sorted(
        graph.nodes.values(),
        key=lambda n: (
            RETENTION_ORDER.index(n.kind) if n.kind in RETENTION_ORDER else len(RETENTION_ORDER),
            snapshot_order(n),
        ),
    )
    kept_nodes = ranked[:node_budget]
    kept_ids = {n.id for n in kept_nodes}
    candidates = sorted(
        (e for e in graph.edges.values() if e.source in kept_ids and e.target in kept_ids),
        key=lambda e: (
            STRENGTH_ORDER.index(e.strength)
            if e.strength in STRENGTH_ORDER
            else len(STRENGTH_ORDER),
            e.type,
            snapshot_order(graph.nodes[e.source]),
            snapshot_order(graph.nodes[e.target]),
        ),
    )
    return kept_nodes, candidates[:MAX_EDGES]


def snapshot_order(node: NodeOut) -> tuple[Any, ...]:
    """Canonical order without database identifiers (identity may hold row IDs)."""
    return (*sort_key(node)[:4], node.label, node.id)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _strip_database_ids(value: Any) -> Any:
    """Drop provenance that differs between databases or tool runs for equal evidence.

    Run, invocation and row identifiers are database-local. Raw-output digests
    are recorded but excluded too: some tools (capa) embed run metadata in
    their raw output, so equal evidence can come from unequal output bytes.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in DATABASE_IDENTITY_KEYS or k in ("run_id", "invocation_id", "output_sha256"):
                continue
            if k == "pointer" and isinstance(v, str) and v.startswith("row:"):
                v = v.rsplit("/", 1)[0]
            out[k] = _strip_database_ids(v)
        return out
    if isinstance(value, list):
        return [_strip_database_ids(v) for v in value]
    return value


def content_digest(body: dict[str, Any]) -> str:
    """Digest of the evidence content without database identifiers or timestamps."""
    content = {
        key: body[key]
        for key in (
            "schema_version",
            "algorithm",
            "sources",
            "address_mapping",
            "coverage",
            "nodes",
            "edges",
            "bounds",
            "limitations",
        )
    }
    content["sample_sha256"] = body["sample"]["sha256"]
    content["sample_size_bytes"] = body["sample"]["size_bytes"]
    content["sample_format"] = body["sample"]["format"]
    return hashlib.sha256(canonical(_strip_database_ids(content))).hexdigest()


def build_snapshot(graph: Graph, sample: SnapshotSample) -> EvidenceSnapshot:
    """Normalize a graph into a bounded snapshot; deterministic for equal inputs."""
    budget = min(MAX_NODES, len(graph.nodes))
    while True:
        snapshot = _assemble(graph, sample, budget)
        size = len(canonical(snapshot.model_dump(mode="json")))
        if size <= MAX_SNAPSHOT_BYTES or budget <= MIN_NODE_BUDGET:
            break
        # Shrink deterministically until the serialized snapshot fits.
        budget = max(MIN_NODE_BUDGET, int(budget * MAX_SNAPSHOT_BYTES / size * 0.95))
    if size > MAX_SNAPSHOT_BYTES:
        raise ValueError("Evidence snapshot exceeds its byte bound")
    return snapshot


def _assemble(graph: Graph, sample: SnapshotSample, node_budget: int) -> EvidenceSnapshot:
    kept_nodes, kept_edges = _retained(graph, node_budget)
    kept_node_ids = {n.id for n in kept_nodes}
    kept_edge_ids = {e.id for e in kept_edges}
    omitted_nodes: dict[str, int] = {}
    for node in graph.nodes.values():
        if node.id not in kept_node_ids:
            omitted_nodes[node.kind] = omitted_nodes.get(node.kind, 0) + 1
    omitted_edges: dict[str, int] = {}
    for edge in graph.edges.values():
        if edge.id not in kept_edge_ids:
            omitted_edges[edge.type] = omitted_edges.get(edge.type, 0) + 1
    nodes = [_node(n) for n in sorted(kept_nodes, key=snapshot_order)]
    edges = [
        _edge(e)
        for e in sorted(
            kept_edges,
            key=lambda e: (
                e.type,
                snapshot_order(graph.nodes[e.source]),
                snapshot_order(graph.nodes[e.target]),
            ),
        )
    ]
    truncated = bool(omitted_nodes or omitted_edges)
    limitations = list(graph.limitations)
    if truncated:
        limitations.append(
            "This snapshot retained a bounded subset of the evidence graph; omitted nodes "
            "and edges are counted in bounds and are not evidence of absence."
        )
    body: dict[str, Any] = {
        "schema_version": SNAPSHOT_SCHEMA,
        "algorithm": graph.schema,
        "sample": sample.model_dump(mode="json"),
        "scope_sha256": graph.scope_sha256,
        "sources": [s.model_dump(mode="json") for s in _sources(graph)],
        "address_mapping": _mapping(graph).model_dump(mode="json"),
        "coverage": [c.model_dump(mode="json") for c in _coverage(graph)],
        "nodes": [n.model_dump(mode="json") for n in nodes],
        "edges": [e.model_dump(mode="json") for e in edges],
        "bounds": SnapshotBounds(
            max_nodes=MAX_NODES,
            max_edges=MAX_EDGES,
            max_bytes=MAX_SNAPSHOT_BYTES,
            nodes_total=len(graph.nodes),
            edges_total=len(graph.edges),
            nodes_retained=len(nodes),
            edges_retained=len(edges),
            truncated=truncated,
            omitted_nodes_by_kind=dict(sorted(omitted_nodes.items())),
            omitted_edges_by_type=dict(sorted(omitted_edges.items())),
            retention_order=list(RETENTION_ORDER),
        ).model_dump(mode="json"),
        "limitations": [text[:1024] for text in limitations[:32]],
    }
    body["content_sha256"] = content_digest(body)
    return EvidenceSnapshot.model_validate(body)


def verify(snapshot: EvidenceSnapshot) -> bool:
    """Recompute the content digest of a stored snapshot."""
    body = snapshot.model_dump(mode="json")
    return content_digest(body) == snapshot.content_sha256
