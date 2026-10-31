"""One-hop direct static call evidence over retained instruction windows only."""

from pydantic import BaseModel

from bytasm.ghidra_protocol import Address, GhidraResult


class RelationshipEdge(BaseModel):
    source_index: int
    target_index: int | None
    call_site: Address
    target: Address
    reference_type: str = "direct_static_call"
    citation: str


class Relationships(BaseModel):
    run_id: str
    center_index: int
    node_limit: int
    edge_limit: int
    retained_matches: int
    truncated: bool
    inventory_complete: bool
    reference_windows_complete: bool
    edges: list[RelationshipEdge]
    limitations: list[str]


def relationships(
    result: GhidraResult,
    run_id: str,
    invocation_id: str,
    index: int,
    node_limit: int = 33,
    edge_limit: int = 32,
) -> Relationships:
    if (
        not 0 <= index < len(result.functions)
        or not 2 <= node_limit <= 33
        or not 1 <= edge_limit <= 64
    ):
        raise ValueError("Invalid relationship bounds")

    def identity(entry: Address) -> tuple[str, str]:
        return entry.space, entry.address

    by_entry = {identity(fn.entry): i for i, fn in enumerate(result.functions)}
    center = identity(result.functions[index].entry)
    nodes = {center}
    edges: list[RelationshipEdge] = []
    matches = 0
    for source, fn in enumerate(result.functions):
        for call_index, call in enumerate(fn.calls):
            if source != index and identity(call.target) != center:
                continue
            matches += 1
            additions = {identity(fn.entry), identity(call.target)}
            if len(edges) >= edge_limit or len(nodes | additions) > node_limit:
                continue
            nodes |= additions
            edges.append(
                RelationshipEdge(
                    source_index=source,
                    target_index=by_entry.get(identity(call.target)),
                    call_site=call.source,
                    target=call.target,
                    citation=f"/api/v1/invocations/{invocation_id}/raw#/functions/{source}/calls/{call_index}",
                )
            )
    return Relationships(
        run_id=run_id,
        center_index=index,
        node_limit=node_limit,
        edge_limit=edge_limit,
        retained_matches=matches,
        truncated=len(edges) < matches,
        inventory_complete=not result.functions_truncated and not result.analysis_timed_out,
        reference_windows_complete=not result.functions_truncated
        and not result.analysis_timed_out
        and all(
            f.pseudocode_status != "not_selected"
            and not f.instructions_truncated
            and not f.calls_truncated
            for f in result.functions
        ),
        edges=edges,
        limitations=[
            "One hop over retained direct static call references, not a runtime trace.",
            "References cover at most 64 instructions in each detailed function. "
            "Inventory-only functions have no retained call records.",
            "Incoming references match the exact function entry and address space only; "
            "calls into body interiors are not assigned to functions.",
            "A target without a matching inventory entry remains unresolved in this view; "
            "indirect and non-call references are unavailable.",
        ],
    )
