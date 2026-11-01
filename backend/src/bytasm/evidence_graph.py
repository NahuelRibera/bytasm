"""Deterministic evidence correlation over one sample version (v0.10).

The graph relates observations that independent tools already produced. It
adds no observations of its own. An edge exists only when an exact,
documented relationship holds:

* `exact_reference`: the tool itself reported the relation (a Ghidra
  instruction reference or direct call).
* `exact_offset_equality`: two observations translate to the same file
  offset, each through a recorded translation basis (see bytasm.address_map).
* `address_containment`: a translated location lies inside a Ghidra function
  body range.
* `structural_containment`: a file offset lies inside one declared section.
* `name_equality`: two tools report the same symbol name. This is a coarse
  association and is labelled as one; it never becomes an address join.

Two observations are never related merely because they occur in the same
file. Nothing here describes runtime behavior: a reference is not a call that
executed, and a rule match is not a verdict.
"""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

from bytasm.address_map import (
    DECLARED_BASIS,
    GHIDRA_BASIS,
    DeclaredLayout,
    GhidraMemoryMap,
    parse_address,
)
from bytasm.ghidra_protocol import Address, GhidraResult

GRAPH_SCHEMA = "bytasm-evidence-graph-1"
MAX_LOCATORS_PER_EDGE = 8
MAX_PREVIEW = 256

NodeKind = Literal[
    "function",
    "program_data",
    "external_symbol",
    "string",
    "finding",
    "section",
    "import",
    "entry_point",
]
EdgeType = Literal[
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
]
Strength = Literal[
    "exact_reference",
    "exact_offset_equality",
    "address_containment",
    "structural_containment",
    "name_equality",
]
STRENGTH: dict[str, Strength] = {
    "calls": "exact_reference",
    "references_string": "exact_reference",
    "references_data": "exact_reference",
    "references_external_symbol": "exact_reference",
    "target_is_string_occurrence": "exact_offset_equality",
    "capa_match_at_function_entry": "exact_offset_equality",
    "yara_match_in_function_body": "address_containment",
    "entry_point_is_function": "exact_offset_equality",
    "located_in_section": "structural_containment",
    "external_symbol_named_as_import": "name_equality",
}
NODE_ORDER: tuple[str, ...] = (
    "entry_point",
    "section",
    "function",
    "finding",
    "external_symbol",
    "import",
    "program_data",
    "string",
)


# --------------------------------------------------------------------------- inputs


@dataclass(frozen=True)
class Locator:
    """Where an observation is stored.

    `pointer` is an RFC 6901 pointer into the invocation's raw output, or
    `row:<table>/<id>` for a database row persisted from that output.
    """

    tool: str
    tool_version: str
    run_id: str
    invocation_id: str
    output_sha256: str | None
    pointer: str


@dataclass(frozen=True)
class MetadataSource:
    run_id: str
    invocation_id: str
    output_sha256: str
    tool_version: str
    file_format: str
    file_size: int
    entry_point: int | None
    layout: DeclaredLayout
    imports: tuple[str, ...]
    imported_libraries: tuple[str, ...]


@dataclass(frozen=True)
class GhidraSource:
    run_id: str
    invocation_id: str
    output_sha256: str
    result: GhidraResult


@dataclass(frozen=True)
class EvidenceRecord:
    id: int
    kind: str  # byte_range | virtual_address
    file_offset: int | None
    length: int | None
    virtual_address: int | None
    pointer: str


@dataclass(frozen=True)
class FindingRecord:
    id: str
    tool: str  # yara-x | capa
    tool_version: str
    rule_id: str
    namespace: str
    rule_set_sha256: str
    invocation_id: str
    output_sha256: str | None
    match_count: int
    evidence_truncated: bool
    evidence: tuple[EvidenceRecord, ...]


@dataclass(frozen=True)
class StringRecord:
    id: int
    file_offset: int
    encoding: str
    value: str
    value_truncated: bool


@dataclass(frozen=True)
class StepRecord:
    tool: str
    status: str
    invocation_id: str | None
    tool_version: str | None


@dataclass(frozen=True)
class PatternSource:
    run_id: str
    status: str
    profile_id: str
    steps: tuple[StepRecord, ...]
    findings: tuple[FindingRecord, ...]
    strings: tuple[StringRecord, ...] | None  # None: no succeeded strings step
    strings_invocation_id: str | None
    strings_output_sha256: str | None
    strings_truncated: bool


# --------------------------------------------------------------------------- outputs


class LocatorOut(BaseModel):
    tool: str
    tool_version: str
    run_id: str
    invocation_id: str
    output_sha256: str | None
    pointer: str


class NodeOut(BaseModel):
    id: str
    kind: NodeKind
    # Untrusted text from the file or a tool (names, previews); render escaped.
    label: str
    identity: dict[str, str | int | None]
    address: Address | None = None
    file_offset: int | None = None
    file_offset_basis: str | None = None
    file_offset_state: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    sources: list[LocatorOut]


class EdgeOut(BaseModel):
    id: str
    type: EdgeType
    strength: Strength
    source: str
    target: str
    basis: list[str]
    locators: list[LocatorOut]
    locator_count: int
    locators_truncated: bool
    attributes: dict[str, Any] = Field(default_factory=dict)


@dataclass
class JoinCoverage:
    """Whether a join type was evaluated, and if not, the exact reason."""

    performed: bool
    reason: str | None = None
    candidates: int = 0
    joined: int = 0
    unmapped: dict[str, int] = field(default_factory=dict)


@dataclass
class Graph:
    schema: str
    scope_sha256: str
    nodes: dict[str, NodeOut]
    edges: dict[str, EdgeOut]
    joins: dict[str, JoinCoverage]
    limitations: list[str]
    metadata: MetadataSource
    ghidra: GhidraSource | None
    pattern: PatternSource | None
    ghidra_map: GhidraMemoryMap | None
    incident: dict[str, list[str]] = field(default_factory=dict)

    def edges_of(self, node_id: str) -> list[EdgeOut]:
        return [self.edges[e] for e in self.incident.get(node_id, [])]


# --------------------------------------------------------------------------- helpers


def _digest(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def node_id(kind: str, *identity: Any) -> str:
    return f"{kind}:{_digest(kind, *identity)[:20]}"


def _loc(locator: Locator) -> LocatorOut:
    return LocatorOut(**locator.__dict__)


def _bounded(text: str | None, limit: int = MAX_PREVIEW) -> str | None:
    return None if text is None else text[:limit]


def addr_key(address: Address) -> tuple[str, str]:
    return address.space, address.address


def scope_digest(
    version_id: str,
    sha256: str,
    metadata: MetadataSource,
    ghidra: GhidraSource | None,
    pattern: PatternSource | None,
) -> str:
    return _digest(
        GRAPH_SCHEMA,
        version_id,
        sha256,
        metadata.invocation_id,
        metadata.output_sha256,
        None if ghidra is None else [ghidra.run_id, ghidra.invocation_id, ghidra.output_sha256],
        None
        if pattern is None
        else [
            pattern.run_id,
            pattern.status,
            [[s.tool, s.status, s.invocation_id] for s in pattern.steps],
        ],
    )


class _Builder:
    def __init__(self) -> None:
        self.nodes: dict[str, NodeOut] = {}
        self.edges: dict[str, EdgeOut] = {}
        self._locators: dict[str, list[LocatorOut]] = defaultdict(list)
        self._seen: dict[str, set[str]] = defaultdict(set)

    def node(self, node: NodeOut) -> str:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
        else:
            for source in node.sources:
                if source not in existing.sources:
                    existing.sources.append(source)
        return node.id

    def edge(
        self,
        edge_type: EdgeType,
        source: str,
        target: str,
        basis: list[str],
        locators: list[Locator],
        attributes: dict[str, Any] | None = None,
    ) -> str:
        edge_id = f"edge:{_digest(edge_type, source, target)[:20]}"
        if edge_id not in self.edges:
            self.edges[edge_id] = EdgeOut(
                id=edge_id,
                type=edge_type,
                strength=STRENGTH[edge_type],
                source=source,
                target=target,
                basis=basis,
                locators=[],
                locator_count=0,
                locators_truncated=False,
                attributes=attributes or {},
            )
        edge = self.edges[edge_id]
        for locator in locators:
            key = f"{locator.invocation_id}{locator.pointer}"
            if key in self._seen[edge_id]:
                continue
            self._seen[edge_id].add(key)
            edge.locator_count += 1
            if len(edge.locators) < MAX_LOCATORS_PER_EDGE:
                edge.locators.append(_loc(locator))
            else:
                edge.locators_truncated = True
        return edge_id


# --------------------------------------------------------------------------- build


def build_graph(
    version_id: str,
    sha256: str,
    metadata: MetadataSource,
    ghidra: GhidraSource | None,
    pattern: PatternSource | None,
) -> Graph:
    b = _Builder()
    joins: dict[str, JoinCoverage] = {}
    limitations = [
        "Relationships are static correlations of stored tool outputs; none is a runtime "
        "observation, and none establishes intent, safety or maliciousness.",
        "A missing relationship does not establish absence: tools have bounded windows, "
        "and joins that cannot be evaluated exactly are skipped and reported.",
    ]
    layout = metadata.layout
    meta_locator = Locator(
        "lief",
        metadata.tool_version,
        metadata.run_id,
        metadata.invocation_id,
        metadata.output_sha256,
        "",
    )

    # Sections (declared structure) ------------------------------------------------
    section_ids: dict[int, str] = {}
    for s in layout.sections:
        section_ids[s.index] = b.node(
            NodeOut(
                id=node_id("section", s.index),
                kind="section",
                label=s.name[:MAX_PREVIEW],
                identity={"index": s.index},
                file_offset=s.file_offset if s.file_size else None,
                file_offset_basis=DECLARED_BASIS if s.file_size else None,
                attributes={
                    "file_size": s.file_size,
                    "declared_virtual_address": s.virtual_address,
                    "declared_virtual_size": s.virtual_size,
                    "flags": list(s.flags),
                },
                sources=[_loc(meta_locator)],
            )
        )

    section_join = JoinCoverage(performed=bool(layout.sections))
    if not layout.sections:
        section_join.reason = "No declared sections with file bytes were parsed."

    def in_section(source_id: str, file_offset: int | None, locator: Locator) -> None:
        if file_offset is None:
            return
        section_join.candidates += 1
        hit = layout.section_for_offset(file_offset)
        if hit is False:
            section_join.unmapped["ambiguous"] = section_join.unmapped.get("ambiguous", 0) + 1
            return
        if hit is None:
            section_join.unmapped["outside_sections"] = (
                section_join.unmapped.get("outside_sections", 0) + 1
            )
            return
        section_join.joined += 1
        b.edge(
            "located_in_section",
            source_id,
            section_ids[hit.index],
            [DECLARED_BASIS],
            [locator],
            {"file_offset": file_offset},
        )

    # Imports (declared) -- nodes are created on demand by the name join.
    import_names = set(metadata.imports)

    # Ghidra -------------------------------------------------------------------------
    ghidra_map: GhidraMemoryMap | None = None
    functions_by_entry: dict[tuple[str, str], str] = {}
    body_index: list[tuple[str, int, int, str]] = []  # space, start, end, function node
    if ghidra is None:
        reason = "No completed Ghidra run was selected."
        for name in ("calls", "references", "string_occurrence", "capa_function", "yara_body"):
            joins[name] = JoinCoverage(False, reason)
    else:
        result = ghidra.result
        ghidra_map = GhidraMemoryMap.from_result(result, metadata.file_size)
        if ghidra_map.available and ghidra_map.rejected_ranges:
            limitations.append(
                f"{ghidra_map.rejected_ranges} Ghidra file ranges fell outside the admitted "
                "bytes and were not used for translation."
            )
        if ghidra_map.truncated:
            limitations.append(
                "Ghidra's memory map was capped; some addresses may be untranslatable."
            )

        def gloc(pointer: str) -> Locator:
            return Locator(
                "ghidra",
                result.ghidra_version,
                ghidra.run_id,
                ghidra.invocation_id,
                ghidra.output_sha256,
                pointer,
            )

        incoming: dict[str, int] = defaultdict(int)
        for index, fn in enumerate(result.functions):
            translation = ghidra_map.to_file_offset(fn.entry)
            node = NodeOut(
                id=node_id("function", *addr_key(fn.entry)),
                kind="function",
                label=fn.name,
                identity={"space": fn.entry.space, "address": fn.entry.address, "index": index},
                address=fn.entry,
                file_offset=translation.file_offset,
                file_offset_basis=GHIDRA_BASIS if translation.mapped else None,
                file_offset_state=translation.state,
                attributes={
                    "namespace": fn.namespace,
                    "name_truncated": fn.name_truncated,
                    "external": fn.external,
                    "body_size": fn.body_size,
                    "body_range_count": len(fn.body_ranges),
                    "body_ranges_truncated": fn.body_ranges_truncated,
                    "detail_state": fn.pseudocode_status,
                    "retained_instructions": len(fn.instructions),
                    "instructions_truncated": fn.instructions_truncated,
                    "retained_calls": len(fn.calls),
                    "calls_truncated": fn.calls_truncated,
                    "retained_references": len(fn.references),
                    "references_truncated": fn.references_truncated,
                    "reference_kinds": {
                        kind: sum(r.kind == kind for r in fn.references)
                        for kind in ("string", "data", "external_symbol")
                    },
                },
                sources=[_loc(gloc(f"/functions/{index}"))],
            )
            fid = b.node(node)
            functions_by_entry[addr_key(fn.entry)] = fid
            for body in fn.body_ranges:
                low, high = parse_address(body.start.address), parse_address(body.end.address)
                if low is not None and high is not None:
                    body_index.append((body.start.space, low, high, fid))
            if translation.mapped:
                in_section(fid, translation.file_offset, gloc(f"/functions/{index}/entry"))

        calls = JoinCoverage(True)
        references = JoinCoverage(True)
        for index, fn in enumerate(result.functions):
            fid = functions_by_entry[addr_key(fn.entry)]
            for call_index, call in enumerate(fn.calls):
                calls.candidates += 1
                target = functions_by_entry.get(addr_key(call.target))
                if target is None:
                    calls.unmapped["target_not_in_inventory"] = (
                        calls.unmapped.get("target_not_in_inventory", 0) + 1
                    )
                    continue
                calls.joined += 1
                incoming[target] += 1
                b.edge(
                    "calls",
                    fid,
                    target,
                    ["ghidra_direct_static_call"],
                    [gloc(f"/functions/{index}/calls/{call_index}")],
                )
            for ref_index, ref in enumerate(fn.references):
                references.candidates += 1
                locator = gloc(f"/functions/{index}/references/{ref_index}")
                if ref.kind == "external_symbol":
                    identity = ref.resolved_external_target or ref.target
                    tid = b.node(
                        NodeOut(
                            id=node_id("external_symbol", *addr_key(identity)),
                            kind="external_symbol",
                            label=ref.target_name or f"{identity.space}:{identity.address}",
                            identity={"space": identity.space, "address": identity.address},
                            address=identity,
                            attributes={"name_truncated": ref.target_name_truncated},
                            sources=[_loc(locator)],
                        )
                    )
                    edge_type: EdgeType = "references_external_symbol"
                    basis = ["ghidra_instruction_reference"]
                    if ref.resolved_external_target is not None:
                        basis.append("ghidra_function_thunk")
                else:
                    translation = ghidra_map.to_file_offset(ref.target)
                    tid = b.node(
                        NodeOut(
                            id=node_id("program_data", *addr_key(ref.target)),
                            kind="program_data",
                            label=ref.target_name or f"{ref.target.space}:{ref.target.address}",
                            identity={"space": ref.target.space, "address": ref.target.address},
                            address=ref.target,
                            file_offset=translation.file_offset,
                            file_offset_basis=GHIDRA_BASIS if translation.mapped else None,
                            file_offset_state=translation.state,
                            attributes={
                                "data_kind": ref.kind,
                                "preview": _bounded(ref.preview),
                                "preview_truncated": ref.preview_truncated
                                or (ref.preview is not None and len(ref.preview) > MAX_PREVIEW),
                            },
                            sources=[_loc(locator)],
                        )
                    )
                    if translation.mapped:
                        in_section(tid, translation.file_offset, locator)
                    edge_type = "references_string" if ref.kind == "string" else "references_data"
                    basis = ["ghidra_instruction_reference"]
                references.joined += 1
                b.edge(
                    edge_type,
                    fid,
                    tid,
                    basis,
                    [locator],
                    {"reference_type": ref.reference_type}
                    | (
                        {"original_target": f"{ref.target.space}:{ref.target.address}"}
                        if ref.resolved_external_target is not None
                        else {}
                    ),
                )
        for fid, count in incoming.items():
            b.nodes[fid].attributes["retained_incoming_calls"] = count
        joins["calls"] = calls
        joins["references"] = references
        if not ghidra_map.available:
            reason = ghidra_map.reason or "Ghidra memory map unavailable."
            for name in ("string_occurrence", "capa_function", "yara_body", "entry_point"):
                joins[name] = JoinCoverage(False, reason)

    # External symbol -> declared import (coarse name equality) ----------------------
    name_join = JoinCoverage(bool(import_names))
    if not import_names:
        name_join.reason = "The import record declares no imported functions."
    libraries = {lib.casefold() for lib in metadata.imported_libraries}
    for nid, node in list(b.nodes.items()):
        if node.kind != "external_symbol" or not import_names:
            continue
        name_join.candidates += 1
        namespace, _, name = node.label.rpartition("::")
        library_ok = (
            namespace.casefold() in libraries
            if metadata.file_format == "PE"
            else namespace in ("", "<EXTERNAL>")
        )
        if not (name in import_names and library_ok) or node.attributes.get("name_truncated"):
            continue
        name_join.joined += 1
        iid = b.node(
            NodeOut(
                id=node_id("import", name),
                kind="import",
                label=name,
                identity={"name": name},
                sources=[_loc(meta_locator)],
            )
        )
        b.edge(
            "external_symbol_named_as_import",
            nid,
            iid,
            ["exact_symbol_name"]
            + (["exact_library_name_casefold"] if metadata.file_format == "PE" else []),
            [_locator_from(node.sources[0]), meta_locator],
        )
    joins["import_name"] = name_join

    def body_functions(file_offset: int) -> tuple[str, list[str]]:
        if ghidra_map is None:
            return "unavailable", []
        located = ghidra_map.to_addresses(file_offset)
        if located.state != "mapped":
            return located.state, []
        space, value = located.addresses[0]
        hits = sorted({fid for s, lo, hi, fid in body_index if s == space and lo <= value <= hi})
        return ("mapped" if hits else "outside_function_bodies"), hits

    # Entry point --------------------------------------------------------------------
    if metadata.entry_point is not None:
        translation = layout.va_to_file_offset(metadata.entry_point)
        ep = b.node(
            NodeOut(
                id=node_id("entry_point"),
                kind="entry_point",
                label="Declared entry point",
                identity={"declared_virtual_address": metadata.entry_point},
                file_offset=translation.file_offset,
                file_offset_basis=DECLARED_BASIS if translation.mapped else None,
                file_offset_state=translation.state,
                sources=[_loc(Locator(**{**meta_locator.__dict__, "pointer": "/entry_point"}))],
            )
        )
        if translation.mapped:
            in_section(ep, translation.file_offset, meta_locator)
        if ghidra is not None and ghidra_map is not None and ghidra_map.available:
            join = JoinCoverage(True, candidates=1)
            matches = [
                fid
                for fid in functions_by_entry.values()
                if translation.mapped and b.nodes[fid].file_offset == translation.file_offset
            ]
            if len(matches) == 1:
                join.joined = 1
                b.edge(
                    "entry_point_is_function",
                    ep,
                    matches[0],
                    [DECLARED_BASIS, GHIDRA_BASIS],
                    [meta_locator, _locator_from(b.nodes[matches[0]].sources[0])],
                )
            else:
                join.unmapped[translation.state if not translation.mapped else "no_function"] = 1
            joins["entry_point"] = join

    # Pattern run: findings and strings ----------------------------------------------
    if pattern is None:
        for name in ("string_occurrence", "capa_function", "yara_body"):
            joins.setdefault(name, JoinCoverage(False, "No completed pattern run was selected."))
    else:
        strings_by_offset: dict[int, list[StringRecord]] = defaultdict(list)
        for record in pattern.strings or ():
            strings_by_offset[record.file_offset].append(record)

        if pattern.strings is None:
            joins.setdefault(
                "string_occurrence",
                JoinCoverage(False, "The selected pattern run has no completed strings step."),
            )
        elif ghidra is not None and ghidra_map is not None and ghidra_map.available:
            join = JoinCoverage(True)
            for nid, node in list(b.nodes.items()):
                if node.kind != "program_data" or node.attributes.get("data_kind") != "string":
                    continue
                join.candidates += 1
                if node.file_offset is None:
                    state = node.file_offset_state or "unavailable"
                    join.unmapped[state] = join.unmapped.get(state, 0) + 1
                    continue
                hits = strings_by_offset.get(node.file_offset, [])
                if not hits:
                    join.unmapped["no_string_at_offset"] = (
                        join.unmapped.get("no_string_at_offset", 0) + 1
                    )
                    continue
                join.joined += 1
                for record in hits:
                    sid = _string_node(b, pattern, record)
                    b.edge(
                        "target_is_string_occurrence",
                        nid,
                        sid,
                        [GHIDRA_BASIS, "strings_step_file_offset"],
                        [_locator_from(node.sources[0]), _string_locator(pattern, record)],
                        {"file_offset": node.file_offset, "encoding": record.encoding},
                    )
            if pattern.strings_truncated:
                limitations.append(
                    "The strings step was capped; a string target without a matching "
                    "occurrence may lie beyond the cap."
                )
            joins["string_occurrence"] = join

        capa_join = JoinCoverage(
            ghidra is not None and ghidra_map is not None and ghidra_map.available
        )
        yara_join = JoinCoverage(capa_join.performed)
        if not capa_join.performed:
            reason = (
                "No completed Ghidra run was selected."
                if ghidra is None
                else (ghidra_map.reason if ghidra_map else None) or "Ghidra memory map unavailable."
            )
            capa_join.reason = yara_join.reason = reason
        elif metadata.file_format != "PE" or layout.image_base is None:
            capa_join.performed = False
            capa_join.reason = (
                "capa virtual addresses are translated only for PE files with a declared "
                "image base; other loaders' address bases are not verified."
            )
        for finding in pattern.findings:
            fnode = b.node(
                NodeOut(
                    id=node_id("finding", finding.tool, finding.namespace, finding.rule_id),
                    kind="finding",
                    label=finding.rule_id,
                    identity={"finding_id": finding.id, "tool": finding.tool},
                    attributes={
                        "tool": finding.tool,
                        "rule_id": finding.rule_id,
                        "namespace": finding.namespace,
                        "rule_set_sha256": finding.rule_set_sha256,
                        "match_count": finding.match_count,
                        "retained_evidence": len(finding.evidence),
                        "evidence_truncated": finding.evidence_truncated,
                    },
                    sources=[
                        _loc(
                            Locator(
                                finding.tool,
                                finding.tool_version,
                                pattern.run_id,
                                finding.invocation_id,
                                finding.output_sha256,
                                f"row:finding/{finding.id}",
                            )
                        )
                    ],
                )
            )
            for ev in finding.evidence:
                locator = Locator(
                    finding.tool,
                    finding.tool_version,
                    pattern.run_id,
                    finding.invocation_id,
                    finding.output_sha256,
                    ev.pointer,
                )
                if finding.tool == "capa" and ev.virtual_address is not None:
                    if not capa_join.performed:
                        continue
                    capa_join.candidates += 1
                    translation = layout.va_to_file_offset(ev.virtual_address)
                    if not translation.mapped:
                        capa_join.unmapped[translation.state] = (
                            capa_join.unmapped.get(translation.state, 0) + 1
                        )
                        continue
                    matches = [
                        fid
                        for fid in functions_by_entry.values()
                        if b.nodes[fid].file_offset == translation.file_offset
                    ]
                    in_section(fnode, translation.file_offset, locator)
                    if len(matches) != 1:
                        key = "no_function_entry" if not matches else "ambiguous"
                        capa_join.unmapped[key] = capa_join.unmapped.get(key, 0) + 1
                        continue
                    capa_join.joined += 1
                    b.edge(
                        "capa_match_at_function_entry",
                        fnode,
                        matches[0],
                        [DECLARED_BASIS, GHIDRA_BASIS],
                        [locator, _locator_from(b.nodes[matches[0]].sources[0])],
                        {
                            "virtual_address": ev.virtual_address,
                            "file_offset": translation.file_offset,
                        },
                    )
                elif ev.file_offset is not None:
                    in_section(fnode, ev.file_offset, locator)
                    if not yara_join.performed:
                        continue
                    yara_join.candidates += 1
                    state, body_hits = body_functions(ev.file_offset)
                    if not body_hits:
                        yara_join.unmapped[state] = yara_join.unmapped.get(state, 0) + 1
                        continue
                    yara_join.joined += 1
                    for fid in body_hits:
                        b.edge(
                            "yara_match_in_function_body",
                            fnode,
                            fid,
                            [GHIDRA_BASIS, "ghidra_function_body"],
                            [locator],
                            {"first_byte_file_offset": ev.file_offset},
                        )
        joins["capa_function"] = capa_join
        joins["yara_body"] = yara_join

    joins["section"] = section_join

    graph = Graph(
        schema=GRAPH_SCHEMA,
        scope_sha256=scope_digest(version_id, sha256, metadata, ghidra, pattern),
        nodes=b.nodes,
        edges=b.edges,
        joins=joins,
        limitations=limitations,
        metadata=metadata,
        ghidra=ghidra,
        pattern=pattern,
        ghidra_map=ghidra_map,
    )
    incident: dict[str, list[str]] = defaultdict(list)
    for edge in sorted(b.edges.values(), key=lambda e: (e.type, e.source, e.target)):
        incident[edge.source].append(edge.id)
        if edge.target != edge.source:
            incident[edge.target].append(edge.id)
    graph.incident = dict(incident)
    return graph


def _locator_from(out: LocatorOut) -> Locator:
    return Locator(**out.model_dump())


def _string_locator(pattern: PatternSource, record: StringRecord) -> Locator:
    return Locator(
        "strings",
        "bytasm",
        pattern.run_id,
        pattern.strings_invocation_id or "",
        pattern.strings_output_sha256,
        f"row:string_occurrence/{record.id}",
    )


def _string_node(b: _Builder, pattern: PatternSource, record: StringRecord) -> str:
    return b.node(
        NodeOut(
            id=node_id("string", record.file_offset, record.encoding),
            kind="string",
            label=record.value[:MAX_PREVIEW],
            identity={"file_offset": record.file_offset, "encoding": record.encoding},
            file_offset=record.file_offset,
            file_offset_basis="strings_step_file_offset",
            file_offset_state="mapped",
            attributes={
                "string_id": record.id,
                "value_truncated": record.value_truncated or len(record.value) > MAX_PREVIEW,
            },
            sources=[_loc(_string_locator(pattern, record))],
        )
    )


def sort_key(node: NodeOut) -> tuple[Any, ...]:
    """Deterministic order: kind, then exact location, then identity."""
    return (
        NODE_ORDER.index(node.kind),
        node.address.space if node.address else "",
        (parse_address(node.address.address) if node.address else None) or -1,
        node.file_offset if node.file_offset is not None else -1,
        json.dumps(node.identity, sort_keys=True),
    )
