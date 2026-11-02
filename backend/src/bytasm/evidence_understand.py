"""Understand layer: plain-language claims derived only from evidence-graph edges.

Every claim cites the exact edge IDs that support it, so the Understand and
Investigate views read one source. Wording comes from reviewed templates and
the existing interpretation catalog. Untrusted text (symbol names, string
values) never appears inside a sentence; it is returned as subject labels.
"""

from collections import defaultdict
from typing import Any, Literal

from pydantic import BaseModel

from bytasm.evidence_graph import EdgeOut, Graph, LocatorOut, NodeOut, sort_key
from bytasm.interpretation_catalog import DETAILS
from bytasm.review import explanation

MAX_CLAIMS = 64
CLAIM_TEMPLATE = "understand-claims-1"


class NavigateOut(BaseModel):
    node_id: str
    href: str


class CompletenessOut(BaseModel):
    state: Literal["complete_within_retained_windows", "bounded", "partial"]
    notes: list[str]


class ClaimOut(BaseModel):
    id: str
    kind: str
    title: str
    summary: str
    technical: str
    subjects: list[str]
    evidence: list[str]
    sources: list[LocatorOut]
    interpretation: str | None
    alternatives: str | None
    limitations: list[str]
    completeness: CompletenessOut
    navigate: NavigateOut
    reading_weight: int


def _addr(node: NodeOut) -> str:
    return f"{node.address.space}:{node.address.address}" if node.address else node.id


def _sources(edges: list[EdgeOut]) -> list[LocatorOut]:
    seen: dict[tuple[str, str, str], LocatorOut] = {}
    for edge in edges:
        for loc in edge.locators:
            seen.setdefault((loc.invocation_id, loc.pointer, loc.tool), loc)
    return sorted(seen.values(), key=lambda s: (s.tool, s.invocation_id, s.pointer))[:16]


def _completeness(fn: NodeOut, graph: Graph) -> CompletenessOut:
    notes = []
    attrs = fn.attributes
    if attrs.get("detail_state") == "not_selected":
        notes.append("Only inventory data was retained for this function.")
    for key, text in (
        ("instructions_truncated", "Instruction window capped at 64."),
        ("references_truncated", "Reference window capped; more references may exist."),
        ("calls_truncated", "Call window capped; more calls may exist."),
        ("body_ranges_truncated", "Body ranges capped at 64."),
    ):
        if attrs.get(key):
            notes.append(text)
    partial = graph.ghidra is not None and (
        graph.ghidra.result.functions_truncated or graph.ghidra.result.analysis_timed_out
    )
    if partial:
        notes.append("The Ghidra inventory was capped or timed out.")
    state: Literal["complete_within_retained_windows", "bounded", "partial"] = (
        "partial" if partial else "bounded" if notes else "complete_within_retained_windows"
    )
    return CompletenessOut(state=state, notes=notes)


def _href(version_id: str, node_id: str) -> str:
    return f"/api/v1/sample-versions/{version_id}/evidence/nodes/{node_id}"


def build_claims(graph: Graph, version_id: str) -> tuple[list[ClaimOut], int]:
    claims: list[ClaimOut] = []
    nodes = graph.nodes
    by_type: dict[str, list[EdgeOut]] = defaultdict(list)
    for edge in graph.edges.values():
        by_type[edge.type].append(edge)

    def claim(**fields: Any) -> None:
        from bytasm.evidence_graph import _digest

        cid = "claim:" + _digest(CLAIM_TEMPLATE, fields["kind"], fields["subjects"])[:20]
        claims.append(ClaimOut(id=cid, **fields))

    # 1. capa rule at a function entry -------------------------------------------
    for edge in by_type["capa_match_at_function_entry"]:
        finding, fn = nodes[edge.source], nodes[edge.target]
        rule = str(finding.attributes["rule_id"])
        version = finding.sources[0].tool_version
        statement, hypothesis = explanation(
            "capa", version, rule, str(finding.attributes["rule_set_sha256"])
        )
        reviewed = not hypothesis.startswith("There is no reviewed")
        details = DETAILS.get(rule) if reviewed else None
        claim(
            kind="capa_rule_at_function",
            title=details[0] if details else "Static rule match needs review",
            summary=(
                f"capa reported a rule match located at the function that starts at "
                f"{_addr(fn)}. The analyzed code contains the features the rule describes; "
                "this does not show that the code ran."
            ),
            technical=(
                f"capa {version} rule match at VA 0x{edge.attributes['virtual_address']:x}; "
                f"declared PE section mapping gives file offset "
                f"0x{edge.attributes['file_offset']:x}, equal to the Ghidra memory-map offset "
                f"of function entry {_addr(fn)}."
            ),
            subjects=[finding.id, fn.id],
            evidence=[edge.id],
            sources=_sources([edge]),
            interpretation=details[2] if details else None,
            alternatives=details[3] if details else None,
            limitations=[
                "A rule match is a static observation, not a verdict or runtime event.",
                "Function-scope capa matches are reported at the function start address.",
            ],
            completeness=_completeness(fn, graph),
            navigate=NavigateOut(node_id=fn.id, href=_href(version_id, fn.id)),
            reading_weight=details[4] if details else 0,
        )

    # 2. Entry point ----------------------------------------------------------------
    for edge in by_type["entry_point_is_function"]:
        fn = nodes[edge.target]
        claim(
            kind="entry_point_function",
            title="The declared entry point starts a function",
            summary=(
                f"The header's declared entry point corresponds to the function at {_addr(fn)}. "
                "Startup code generated by compilers usually lives here, so it is a natural "
                "place to begin reading."
            ),
            technical=(
                "Declared entry VA translated through LIEF section declarations and the "
                "function entry through Ghidra's memory map give the same file offset "
                f"0x{fn.file_offset or 0:x}."
            ),
            subjects=[edge.source, fn.id],
            evidence=[edge.id],
            sources=_sources([edge]),
            interpretation=None,
            alternatives=None,
            limitations=["The entry point is a header declaration; it was not executed."],
            completeness=_completeness(fn, graph),
            navigate=NavigateOut(node_id=fn.id, href=_href(version_id, fn.id)),
            reading_weight=12,
        )

    # 3. YARA match inside a function body ------------------------------------------
    for edge in by_type["yara_match_in_function_body"]:
        finding, fn = nodes[edge.source], nodes[edge.target]
        rule = str(finding.attributes["rule_id"])
        version = finding.sources[0].tool_version
        statement, hypothesis = explanation(
            "yara-x", version, rule, str(finding.attributes["rule_set_sha256"])
        )
        reviewed = not hypothesis.startswith("There is no reviewed")
        details = DETAILS.get(rule) if reviewed else None
        claim(
            kind="yara_match_in_function",
            title=(details[0] if details else "Static rule match needs review")
            + " inside a function",
            summary=(
                f"A YARA-X rule matched bytes that Ghidra places inside the function at "
                f"{_addr(fn)}. The matched bytes are part of that function's code range."
            ),
            technical=(
                f"YARA-X match first byte at file offset "
                f"0x{edge.attributes['first_byte_file_offset']:x}; Ghidra memory map gives a "
                f"program address inside a retained body range of {_addr(fn)}."
            ),
            subjects=[finding.id, fn.id],
            evidence=[edge.id],
            sources=_sources([edge]),
            interpretation=details[2] if details else None,
            alternatives=details[3] if details else None,
            limitations=[
                "Only the first matched byte is located; a match may extend past the body.",
                "Body ranges are Ghidra's reconstruction and are capped at 64 ranges.",
            ],
            completeness=_completeness(fn, graph),
            navigate=NavigateOut(node_id=fn.id, href=_href(version_id, fn.id)),
            reading_weight=(details[4] if details else 0) // 2,
        )

    # 4. External symbol references, one claim per function -------------------------
    ext: dict[str, list[EdgeOut]] = defaultdict(list)
    for edge in by_type["references_external_symbol"]:
        ext[edge.source].append(edge)
    import_edges = {e.source: e for e in by_type["external_symbol_named_as_import"]}
    for fid, edges in ext.items():
        fn = nodes[fid]
        targets = sorted({e.target for e in edges})
        matched = [import_edges[t] for t in targets if t in import_edges]
        claim(
            kind="function_references_external_symbols",
            title=f"Function refers to {len(targets)} external symbol"
            + ("s" if len(targets) != 1 else ""),
            summary=(
                f"The function at {_addr(fn)} contains instruction references to "
                f"{len(targets)} symbols provided by other libraries"
                + (
                    f"; {len(matched)} share a name with the declared import table"
                    if matched
                    else ""
                )
                + ". A reference means the code can reach the symbol; it does not show "
                "the call happened."
            ),
            technical=(
                f"{sum(e.locator_count for e in edges)} retained Ghidra instruction "
                "references (kind external_symbol, thunk resolution recorded separately). "
                "Import association is exact name equality, not an address join."
            ),
            subjects=[fid, *targets],
            evidence=[e.id for e in edges] + [e.id for e in matched],
            sources=_sources(edges),
            interpretation=None,
            alternatives=None,
            limitations=[
                "References come from at most 64 retained instructions.",
                "Indirect calls are listed as call sites only from protocol ghidra-5; "
                "a call without a Ghidra call reference stays unresolved.",
            ],
            completeness=_completeness(fn, graph),
            navigate=NavigateOut(node_id=fid, href=_href(version_id, fid)),
            reading_weight=8,
        )

    # 5. String references, one claim per function ----------------------------------
    occurrences = {e.source: e for e in by_type["target_is_string_occurrence"]}
    strs: dict[str, list[EdgeOut]] = defaultdict(list)
    for edge in by_type["references_string"]:
        strs[edge.source].append(edge)
    for fid, edges in strs.items():
        fn = nodes[fid]
        targets = sorted({e.target for e in edges})
        linked = [occurrences[t] for t in targets if t in occurrences]
        claim(
            kind="function_references_strings",
            title=f"Function refers to {len(targets)} text value"
            + ("s" if len(targets) != 1 else ""),
            summary=(
                f"The function at {_addr(fn)} refers to {len(targets)} text values defined "
                "in the file"
                + (
                    f"; {len(linked)} are the same bytes the strings step recorded"
                    if linked
                    else ""
                )
                + ". The text itself is untrusted data from the file."
            ),
            technical=(
                "Ghidra instruction references to defined string data; string-step links "
                "require equal file offsets through Ghidra's memory map."
            ),
            subjects=[fid, *targets],
            evidence=[e.id for e in edges] + [e.id for e in linked],
            sources=_sources(edges + linked),
            interpretation=None,
            alternatives=None,
            limitations=["Text values are shown as escaped data and may be truncated."],
            completeness=_completeness(fn, graph),
            navigate=NavigateOut(node_id=fid, href=_href(version_id, fid)),
            reading_weight=6,
        )

    # 6. Import slots: exact file-offset join of Ghidra and LIEF slots -------------
    slot_edges = sorted(
        by_type["external_symbol_import_slot"],
        key=lambda e: (e.attributes.get("slot_file_offset") or 0, e.id),
    )
    if slot_edges:
        anchor = slot_edges[0].source
        named = sum(bool(e.attributes.get("names_equal")) for e in slot_edges)
        claim(
            kind="import_slots_match_ghidra_pointers",
            title=f"{len(slot_edges)} import slot"
            + ("s" if len(slot_edges) != 1 else "")
            + " confirmed by two tools",
            summary=(
                f"For {len(slot_edges)} imported names, the slot that the file's import "
                "table or relocations designate is the same file location that Ghidra "
                f"reports as a pointer to an external function. {named} of these also "
                "carry the same name in both tools. This links declared imports to "
                "Ghidra's external symbols exactly; it does not show that any import is "
                "called."
            ),
            technical=(
                "LIEF import-address-table (PE) or JUMP_SLOT/GLOB_DAT relocation (ELF) slot "
                "offsets, translated through declared sections or PT_LOAD headers, equal "
                "Ghidra pointer-slot offsets translated through Ghidra's memory map."
            ),
            subjects=sorted({e.source for e in slot_edges} | {e.target for e in slot_edges}),
            evidence=[e.id for e in slot_edges],
            sources=_sources(slot_edges),
            interpretation=None,
            alternatives=None,
            limitations=[
                "Ghidra retains at most 4 pointer slots per function.",
                "A slot is a data location; references to it are reported separately.",
            ],
            completeness=CompletenessOut(state="complete_within_retained_windows", notes=[]),
            navigate=NavigateOut(node_id=anchor, href=_href(version_id, anchor)),
            reading_weight=7,
        )

    claims.sort(
        key=lambda c: (
            -c.reading_weight,
            c.kind,
            sort_key(nodes[c.navigate.node_id]),
            c.id,
        )
    )
    return claims[:MAX_CLAIMS], len(claims)


# --------------------------------------------------------------------------- coverage


class StepCoverageOut(BaseModel):
    tool: str
    status: str
    run_id: str
    invocation_id: str | None
    tool_version: str | None


class JoinOut(BaseModel):
    join: str
    performed: bool
    reason: str | None
    candidates: int
    joined: int
    not_joined: dict[str, int]


class CoverageOut(BaseModel):
    steps: list[StepCoverageOut]
    ghidra_protocol: str | None
    ghidra_memory_map: Literal["available", "unavailable", "not_selected"]
    ghidra_memory_map_reason: str | None
    functions_identified: int | None
    functions_retained: int | None
    functions_inventory_complete: bool | None
    functions_with_detail_windows: int | None
    functions_with_capped_windows: int | None
    strings_retained: int | None
    strings_truncated: bool | None
    findings: int | None
    findings_with_capped_evidence: int | None
    joins: list[JoinOut]
    statements: list[str]


JOIN_LABELS = {
    "calls": "Ghidra direct calls to inventory functions",
    "references": "Ghidra instruction references",
    "string_occurrence": "Ghidra string targets to strings-step occurrences",
    "capa_function": "capa matches to Ghidra function entries",
    "yara_body": "YARA-X matches to Ghidra function bodies",
    "entry_point": "Declared entry point to a Ghidra function",
    "import_name": "External symbols to declared imports (name equality)",
    "section": "Locations to declared sections",
}


def build_coverage(graph: Graph) -> CoverageOut:
    steps = [
        StepCoverageOut(
            tool="lief",
            status="succeeded",
            run_id=graph.metadata.run_id,
            invocation_id=graph.metadata.invocation_id,
            tool_version=graph.metadata.tool_version,
        )
    ]
    statements: list[str] = []
    result = graph.ghidra.result if graph.ghidra else None
    if graph.ghidra is not None and result is not None:
        steps.append(
            StepCoverageOut(
                tool="ghidra",
                status="succeeded",
                run_id=graph.ghidra.run_id,
                invocation_id=graph.ghidra.invocation_id,
                tool_version=result.ghidra_version,
            )
        )
    if graph.pattern is not None:
        steps.extend(
            StepCoverageOut(
                tool=s.tool,
                status=s.status,
                run_id=graph.pattern.run_id,
                invocation_id=s.invocation_id,
                tool_version=s.tool_version,
            )
            for s in graph.pattern.steps
        )
    detailed = capped = None
    if result is not None:
        selected = [f for f in result.functions if f.pseudocode_status != "not_selected"]
        detailed = len(selected)
        capped = sum(
            f.instructions_truncated or f.references_truncated or f.calls_truncated
            for f in selected
        )
        statements.append(
            f"Ghidra identified {result.function_count} functions and retained "
            f"{len(result.functions)}; {detailed} have detailed instruction windows "
            f"and {capped} of those {detailed} windows were capped."
        )
    else:
        statements.append("No completed Ghidra run was selected; function evidence is absent.")
    for step in steps:
        if step.status != "succeeded":
            statements.append(
                f"{step.tool} step is {step.status.replace('_', ' ')}; its evidence is not "
                "available and no absence is inferred."
            )
    findings = graph.pattern.findings if graph.pattern else None
    gmap = graph.ghidra_map
    return CoverageOut(
        steps=steps,
        ghidra_protocol=result.schema_version if result else None,
        ghidra_memory_map=(
            "not_selected" if gmap is None else "available" if gmap.available else "unavailable"
        ),
        ghidra_memory_map_reason=gmap.reason if gmap else None,
        functions_identified=result.function_count if result else None,
        functions_retained=len(result.functions) if result else None,
        functions_inventory_complete=(
            not result.functions_truncated and not result.analysis_timed_out if result else None
        ),
        functions_with_detail_windows=detailed,
        functions_with_capped_windows=capped,
        strings_retained=(
            len(graph.pattern.strings)
            if graph.pattern and graph.pattern.strings is not None
            else None
        ),
        strings_truncated=(
            graph.pattern.strings_truncated
            if graph.pattern and graph.pattern.strings is not None
            else None
        ),
        findings=len(findings) if findings is not None else None,
        findings_with_capped_evidence=(
            sum(f.evidence_truncated for f in findings) if findings is not None else None
        ),
        joins=[
            JoinOut(
                join=name,
                performed=join.performed,
                reason=join.reason,
                candidates=join.candidates,
                joined=join.joined,
                not_joined=dict(sorted(join.unmapped.items())),
            )
            for name, join in sorted(graph.joins.items())
        ],
        statements=statements,
    )


# --------------------------------------------------------------------------- layout


class LayoutSectionOut(BaseModel):
    node_id: str
    index: int
    name: str
    file_offset: int
    file_size: int
    declared_virtual_address: int | None
    declared_virtual_size: int
    flags: list[str]
    contains: dict[str, int]


class LayoutBlockOut(BaseModel):
    name: str
    start: str
    end: str
    permissions: str
    initialized: bool
    file_backed: bool


class LayoutOut(BaseModel):
    file_size: int
    sections: list[LayoutSectionOut]
    ghidra_blocks: list[LayoutBlockOut] | None
    basis: str


def build_layout(graph: Graph) -> LayoutOut:
    contains: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for edge in graph.edges.values():
        if edge.type == "located_in_section":
            contains[edge.target][graph.nodes[edge.source].kind] += 1
    sections = []
    for node in sorted(
        (n for n in graph.nodes.values() if n.kind == "section"),
        key=lambda n: int(n.identity["index"] or 0),
    ):
        a = node.attributes
        sections.append(
            LayoutSectionOut(
                node_id=node.id,
                index=int(node.identity["index"] or 0),
                name=node.label,
                file_offset=node.file_offset or 0,
                file_size=a["file_size"],
                declared_virtual_address=a["declared_virtual_address"],
                declared_virtual_size=a["declared_virtual_size"],
                flags=a["flags"],
                contains=dict(sorted(contains[node.id].items())),
            )
        )
    blocks = None
    if graph.ghidra is not None and graph.ghidra.result.schema_version in ("ghidra-4", "ghidra-5"):
        blocks = [
            LayoutBlockOut(
                name=b.name,
                start=f"{b.start.space}:{b.start.address}",
                end=f"{b.end.space}:{b.end.address}",
                permissions=("r" if b.read else "-")
                + ("w" if b.write else "-")
                + ("x" if b.execute else "-"),
                initialized=b.initialized,
                file_backed=bool(b.file_ranges),
            )
            for b in graph.ghidra.result.memory_blocks
        ]
    return LayoutOut(
        file_size=graph.metadata.file_size,
        sections=sections,
        ghidra_blocks=blocks,
        basis=(
            "Section rows are LIEF declarations; block rows are Ghidra's loaded memory map. "
            "Counts are evidence-graph nodes located in each section by file offset."
        ),
    )
