"""Compare two evidence snapshots without confusing tool drift with file change (v0.11).

Both sides are `EvidenceSnapshot`s: a pinned review's stored snapshot, or a
snapshot built in memory from a version's current graph. Comparison never
recomputes a pinned side.

Canonical identity is not correspondence. A node ID identifies an observation
inside one graph (a function at `ram:00101139`). Whether the function at that
address in one file "is" a function in another file is a separate question,
answered only by the documented matching methods below. Addresses are compared
across sides only when both sides analyzed identical bytes in an identical
Ghidra environment; otherwise a rebase, a section shift or a code change
would make address equality meaningless.

Matching methods, strongest first:

* `identical_input_address`: same sample SHA-256 and the same Ghidra version,
  protocol and image base. The same deterministic tool on the same bytes
  reports the same entry address.
* `rule_identity`: findings, by tool, namespace and rule name.
* `declared_section_name`: sections, by declared name and ordinal among
  sections with that name.
* `string_value_digest`: strings, by encoding and SHA-256 of the complete
  retained value, ordinal by file offset. Values the strings step truncated
  are never matched: a shared prefix is not content equality.
* `joined_string_value_digest`: program data whose exact file-offset join
  reached a string with a string_value_digest key.
* `unique_symbol_name`: functions and external symbols whose tool-reported
  name is unique on both sides and is not a tool-generated default name.
  Names are declarations: a renamed function is unmatched, not removed.
* `import_name`, `singleton`: imports by exact name; the declared entry point.

A node without a key is `not_comparable` (never added or removed). A change
is attributed to the file only when every source that could produce it was
available on both sides with an identical tool identity and configuration.
"""

import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Literal

from pydantic import BaseModel

from bytasm.evidence_snapshot import (
    EvidenceSnapshot,
    SnapshotEdge,
    SnapshotNode,
    SnapshotSource,
)

COMPARISON_SCHEMA = "bytasm-evidence-comparison-1"
MATCHING_POLICY = "evidence-correspondence-1"
MAX_CITATIONS = 16
SOURCES = ("lief", "ghidra", "strings", "yara-x", "capa")
ENVIRONMENT_FIELDS = (
    "tool_version",
    "adapter_version",
    "protocol_version",
    "rule_set_sha256",
    "profile_sha256",
    "script_sha256",
)
# Ghidra's generated names carry the address; they are not identities.
DEFAULT_NAME = re.compile(
    r"^(?:thunk_)?(?:FUN|SUB|LAB|DAT|PTR|UNK|OFF|Ordinal|switchD|caseD)_[0-9A-Fa-f_]+$"
)
EXACT_STRENGTHS = frozenset({"exact_reference", "exact_offset_equality"})

Change = Literal["added", "removed", "modified", "unchanged", "not_comparable"]
Attribution = Literal[
    "identical_input",
    "comparable_coverage",
    "binary_difference_under_comparable_coverage",
    "analysis_environment_difference",
    "coverage_difference",
    "source_output_difference",
    "retention_bound",
    "no_stable_correspondence",
]
CHANGE_ORDER: tuple[Change, ...] = ("added", "removed", "modified", "not_comparable", "unchanged")

NODE_SOURCES: dict[str, tuple[str, ...]] = {
    "entry_point": ("lief",),
    "section": ("lief",),
    # Import nodes exist only when the name join reached an external symbol.
    "import": ("lief", "ghidra"),
    "function": ("ghidra",),
    "program_data": ("ghidra",),
    "external_symbol": ("ghidra",),
    "string": ("strings",),
}
EDGE_SOURCES: dict[str, tuple[str, ...]] = {
    "calls": ("ghidra",),
    "references_string": ("ghidra",),
    "references_data": ("ghidra",),
    "references_external_symbol": ("ghidra",),
    "target_is_string_occurrence": ("ghidra", "strings"),
    "target_within_string_occurrence": ("ghidra", "strings"),
    "capa_match_at_function_entry": ("lief", "ghidra", "capa"),
    "yara_match_in_function_body": ("ghidra", "yara-x"),
    "entry_point_is_function": ("lief", "ghidra"),
    "located_in_section": ("lief",),
    "external_symbol_named_as_import": ("lief", "ghidra"),
    "external_symbol_import_slot": ("lief", "ghidra"),
}
# Joins whose evaluation an edge type depends on (coverage comparison).
EDGE_JOINS: dict[str, str] = {
    "calls": "calls",
    "references_string": "references",
    "references_data": "references",
    "references_external_symbol": "references",
    "target_is_string_occurrence": "string_occurrence",
    "target_within_string_occurrence": "string_occurrence",
    "capa_match_at_function_entry": "capa_function",
    "yara_match_in_function_body": "yara_body",
    "entry_point_is_function": "entry_point",
    "located_in_section": "section",
    "external_symbol_named_as_import": "import_name",
    "external_symbol_import_slot": "import_slot",
}
MODIFIED_FIELDS: dict[str, tuple[str, ...]] = {
    "section": (
        "file_offset",
        "attributes.file_size",
        "attributes.declared_virtual_address",
        "attributes.declared_virtual_size",
        "attributes.flags",
    ),
    "entry_point": ("identity.declared_virtual_address", "file_offset"),
    "function": (
        "address",
        "attributes.body_size",
        "attributes.external",
        "attributes.basic_block_count",
        "attributes.instruction_count",
        "attributes.conditional_branch_count",
        "attributes.indirect_call_count",
    ),
    "finding": ("attributes.match_count", "attributes.rule_set_sha256"),
    "string": ("file_offset",),
    "program_data": ("address", "file_offset"),
    "external_symbol": (),
    "import": (),
}


class SideOut(BaseModel):
    side: Literal["a", "b"]
    kind: Literal["version_current", "pinned_review"]
    version_id: str
    review_id: str | None
    sample_id: str
    sample_sha256: str
    file_format: str
    algorithm: str
    snapshot_schema: str
    scope_sha256: str
    content_sha256: str


class BinaryOut(BaseModel):
    identical: bool
    sha256_a: str
    sha256_b: str
    size_a: int
    size_b: int
    format_a: str
    format_b: str
    same_sample: bool


class SourceDiffOut(BaseModel):
    source: str
    state_a: str
    state_b: str
    differing_fields: list[str]
    retention_a: dict[str, Any]
    retention_b: dict[str, Any]
    comparability: Literal[
        "comparable", "environment_differs", "coverage_differs", "unavailable_on_both"
    ]
    explanation: str


class JoinDiffOut(BaseModel):
    join: str
    performed_a: bool | None
    performed_b: bool | None
    candidates_a: int
    candidates_b: int
    joined_a: int
    joined_b: int
    comparable: bool
    reason: str | None


class MappingOut(BaseModel):
    declared_image_base_a: int | None
    declared_image_base_b: int | None
    ghidra_image_base_a: str | None
    ghidra_image_base_b: str | None
    ghidra_memory_map_a: str
    ghidra_memory_map_b: str
    addresses_comparable: bool
    explanation: str


class CorrespondenceOut(BaseModel):
    kind: str
    method: str
    matched: int
    unmatched_a: int
    unmatched_b: int
    limitation: str


class ChangeOut(BaseModel):
    id: str
    category: Literal["node", "edge"]
    kind: str
    change: Change
    attribution: Attribution
    match_method: str | None
    correspondence_key: str | None
    required_sources: list[str]
    changed_fields: list[str]
    reason: str
    exact_join: bool
    before: dict[str, Any] | None
    after: dict[str, Any] | None


class StatementOut(BaseModel):
    id: str
    kind: str
    text: str
    cites: list[str]
    cites_total: int


class CountsOut(BaseModel):
    nodes: dict[str, int]
    edges: dict[str, int]
    attribution: dict[str, int]
    exact_joins_established: int
    exact_joins_lost: int


class ComparisonOut(BaseModel):
    schema_version: str
    matching_policy: str
    a: SideOut
    b: SideOut
    binary: BinaryOut
    environment: list[SourceDiffOut]
    coverage: list[JoinDiffOut]
    mapping: MappingOut
    correspondence: list[CorrespondenceOut]
    counts: CountsOut
    statements: list[StatementOut]
    review_candidates: list[str]
    incomparable: list[str]
    limitations: list[str]
    comparison_sha256: str


class Comparison:
    """A full comparison: the summary plus every change, for pagination."""

    def __init__(self, summary: ComparisonOut, changes: list[ChangeOut]) -> None:
        self.summary = summary
        self.changes = changes


def _digest(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def _field(node: SnapshotNode, path: str) -> Any:
    if path == "address":
        return None if node.address is None else [node.address.space, node.address.address]
    if path == "file_offset":
        return node.file_offset
    group, _, key = path.partition(".")
    container = node.attributes if group == "attributes" else node.identity
    return container.get(key)


def _sources(snapshot: EvidenceSnapshot) -> dict[str, SnapshotSource]:
    return {s.source: s for s in snapshot.sources}


def _node_sources(node: SnapshotNode) -> tuple[str, ...]:
    if node.kind == "finding":
        tool = node.attributes.get("tool")
        return (str(tool),) if tool in ("yara-x", "capa") else ()
    return NODE_SOURCES.get(node.kind, ())


def _edge_sources(edge: SnapshotEdge, nodes: dict[str, SnapshotNode]) -> tuple[str, ...]:
    """Every source an edge depends on: its join plus both endpoints' producers."""
    found = set(EDGE_SOURCES.get(edge.type, ()))
    for node_id in (edge.source, edge.target):
        if node_id in nodes:
            found.update(_node_sources(nodes[node_id]))
    return tuple(name for name in SOURCES if name in found)


def _brief(node: SnapshotNode) -> dict[str, Any]:
    return node.model_dump(mode="json", exclude={"sources"}) | {
        "sources": [s.model_dump(mode="json") for s in node.sources[:2]]
    }


def _brief_edge(edge: SnapshotEdge) -> dict[str, Any]:
    return edge.model_dump(mode="json", exclude={"locators"}) | {
        "locators": [s.model_dump(mode="json") for s in edge.locators[:2]]
    }


class _Keys:
    """Correspondence keys of one side: node ID -> (method, key)."""

    def __init__(self, snapshot: EvidenceSnapshot, addresses_comparable: bool) -> None:
        self.snapshot = snapshot
        self.keys: dict[str, tuple[str, str]] = {}
        self.unkeyed: dict[str, str] = {}  # node ID -> reason
        nodes = snapshot.nodes
        by_kind: dict[str, list[SnapshotNode]] = defaultdict(list)
        for node in nodes:
            by_kind[node.kind].append(node)

        for node in by_kind["entry_point"]:
            self.keys[node.id] = ("singleton", "entry_point")
        for node in by_kind["finding"]:
            a = node.attributes
            self.keys[node.id] = (
                "rule_identity",
                f"{a.get('tool')}\x00{a.get('namespace')}\x00{a.get('rule_id')}",
            )
        ordinal: dict[str, int] = defaultdict(int)
        for node in sorted(by_kind["section"], key=lambda n: int(n.identity.get("index") or 0)):
            if node.label_truncated:
                self.unkeyed[node.id] = "The declared section name was truncated."
                continue
            self.keys[node.id] = ("declared_section_name", f"{node.label}#{ordinal[node.label]}")
            ordinal[node.label] += 1
        for node in by_kind["import"]:
            self.keys[node.id] = ("import_name", node.label)

        string_ordinal: dict[str, int] = defaultdict(int)
        for node in sorted(by_kind["string"], key=lambda n: n.file_offset or 0):
            if node.label_truncated or node.attributes.get("value_truncated"):
                self.unkeyed[node.id] = (
                    "The string value was truncated; a shared prefix is not content equality."
                )
                continue
            value = (
                f"{node.identity.get('encoding')}\x00"
                + hashlib.sha256(node.label.encode("utf-8", "surrogatepass")).hexdigest()
            )
            self.keys[node.id] = ("string_value_digest", f"{value}#{string_ordinal[value]}")
            string_ordinal[value] += 1

        def by_unique_name(kind: str, name_of: Any) -> None:
            names: dict[str, list[SnapshotNode]] = defaultdict(list)
            for node in by_kind[kind]:
                if node.id in self.keys:
                    continue
                name = name_of(node)
                if name is None:
                    continue
                names[name].append(node)
            for name, group in names.items():
                if len(group) == 1:
                    self.keys[group[0].id] = ("unique_symbol_name", name)
                else:
                    for node in group:
                        self.unkeyed[node.id] = "The tool-reported name is not unique."

        for kind in ("function", "program_data"):
            if addresses_comparable:
                for node in by_kind[kind]:
                    if node.address is not None:
                        self.keys[node.id] = (
                            "identical_input_address",
                            f"{node.address.space}:{node.address.address}",
                        )

        def function_name(node: SnapshotNode) -> str | None:
            if node.label_truncated or DEFAULT_NAME.match(node.label):
                return None
            namespace = str(node.attributes.get("namespace") or "")
            return f"{namespace}::{node.label}|external={bool(node.attributes.get('external'))}"

        by_unique_name("function", function_name)

        def external_name(node: SnapshotNode) -> str | None:
            if node.label_truncated or (
                node.address is not None
                and node.label == f"{node.address.space}:{node.address.address}"
            ):
                return None
            return node.label

        by_unique_name("external_symbol", external_name)

        # Program data reached by an exact offset join inherits the string key.
        string_targets: dict[str, list[str]] = defaultdict(list)
        for edge in snapshot.edges:
            if edge.type == "target_is_string_occurrence" and edge.target in self.keys:
                string_targets[edge.source].append(self.keys[edge.target][1])
        for node in by_kind["program_data"]:
            if node.id in self.keys:
                continue
            targets = sorted(set(string_targets.get(node.id, [])))
            if len(targets) == 1:
                self.keys[node.id] = ("joined_string_value_digest", targets[0])

        for node in nodes:
            if node.id not in self.keys and node.id not in self.unkeyed:
                self.unkeyed[node.id] = (
                    "No stable identity: the name is tool-generated or absent, and addresses "
                    "are not compared across different inputs or tool environments."
                    if node.kind in ("function", "program_data", "external_symbol")
                    else "No correspondence method is defined for this observation."
                )

    def key(self, node_id: str) -> str | None:
        found = self.keys.get(node_id)
        return None if found is None else f"{found[0]}:{found[1]}"


def compare_snapshots(
    a: EvidenceSnapshot,
    b: EvidenceSnapshot,
    side_a: dict[str, Any],
    side_b: dict[str, Any],
) -> Comparison:
    """Deterministic comparison of snapshot `a` (before) with `b` (after)."""
    src_a, src_b = _sources(a), _sources(b)
    same_bytes = a.sample.sha256 == b.sample.sha256
    incomparable: list[str] = []
    limitations = [
        "Comparisons relate static observations of stored tool outputs. A difference is "
        "not a behavior change, and no difference establishes safety or intent.",
        "Correspondence between sides uses the documented matching policy; canonical node "
        "identity inside one graph is not correspondence across files.",
        "Observations absent from a side are limited to that side's retained windows and "
        "available sources; absence is never inferred where a source did not run.",
    ]
    if a.sample.format != b.sample.format:
        incomparable.append(
            "File formats differ; structural coordinates are not comparable and only "
            "rule and string content can correspond."
        )
    if a.sample.sample_id != b.sample.sample_id:
        limitations.append(
            "The sides belong to different samples of the same project; correspondence "
            "is by content and declared names only."
        )
    if a.algorithm != b.algorithm:
        incomparable.append(
            f"Evidence algorithms differ ({a.algorithm} vs {b.algorithm}); edge types "
            "introduced by the newer algorithm are not compared as changes."
        )

    # Environment and coverage ----------------------------------------------------
    environment: list[SourceDiffOut] = []
    source_state: dict[str, str] = {}
    for name in SOURCES:
        sa, sb = src_a.get(name), src_b.get(name)
        state_a = sa.state if sa else "unavailable"
        state_b = sb.state if sb else "unavailable"
        differing = (
            [f for f in ENVIRONMENT_FIELDS if getattr(sa, f) != getattr(sb, f)]
            if sa is not None and sb is not None and state_a == state_b == "available"
            else []
        )
        if state_a == state_b == "unavailable":
            comparability: Any = "unavailable_on_both"
            text = f"{name} evidence is unavailable on both sides; nothing is compared for it."
        elif state_a != state_b:
            comparability = "coverage_differs"
            present = "B" if state_b == "available" else "A"
            text = (
                f"{name} evidence is available only on side {present}. Its observations are "
                "not reported as added or removed; the other side has no comparable source."
            )
        elif differing:
            comparability = "environment_differs"
            text = (
                f"{name} ran on both sides with a different tool identity or configuration "
                f"({', '.join(differing)}). Differences in its evidence cannot be attributed "
                "solely to the file."
            )
        else:
            comparability = "comparable"
            text = f"{name} ran on both sides with the same tool identity and configuration."
        source_state[name] = comparability
        environment.append(
            SourceDiffOut(
                source=name,
                state_a=state_a,
                state_b=state_b,
                differing_fields=differing,
                retention_a=dict(sa.retention) if sa else {},
                retention_b=dict(sb.retention) if sb else {},
                comparability=comparability,
                explanation=text,
            )
        )

    joins_a = {j.join: j for j in a.coverage}
    joins_b = {j.join: j for j in b.coverage}
    coverage: list[JoinDiffOut] = []
    join_comparable: dict[str, bool] = {}
    for name in sorted(joins_a.keys() | joins_b.keys()):
        ja, jb = joins_a.get(name), joins_b.get(name)
        comparable = bool(ja and jb and ja.performed and jb.performed)
        join_comparable[name] = comparable
        coverage.append(
            JoinDiffOut(
                join=name,
                performed_a=ja.performed if ja else None,
                performed_b=jb.performed if jb else None,
                candidates_a=ja.candidates if ja else 0,
                candidates_b=jb.candidates if jb else 0,
                joined_a=ja.joined if ja else 0,
                joined_b=jb.joined if jb else 0,
                comparable=comparable,
                reason=None
                if comparable
                else "The join was not evaluated on "
                + (
                    "either side"
                    if not (ja and ja.performed) and not (jb and jb.performed)
                    else "side A"
                    if not (ja and ja.performed)
                    else "side B"
                )
                + (
                    "; this algorithm version does not define it on one side."
                    if ja is None or jb is None
                    else "."
                ),
            )
        )

    ma, mb = a.address_mapping, b.address_mapping
    ghidra_env_same = source_state["ghidra"] == "comparable"
    addresses_comparable = (
        same_bytes
        and ghidra_env_same
        and ma.ghidra_image_base == mb.ghidra_image_base
        and ma.declared_image_base == mb.declared_image_base
    )
    if addresses_comparable:
        mapping_text = (
            "Both sides analyzed identical bytes with the same Ghidra environment and image "
            "base, so function and data addresses correspond exactly."
        )
    else:
        reasons = []
        if not same_bytes:
            reasons.append("the files differ")
        if not ghidra_env_same:
            reasons.append("the Ghidra source is missing or configured differently")
        if ma.declared_image_base != mb.declared_image_base:
            reasons.append("the declared image bases differ (the file was rebased)")
        if ma.ghidra_image_base != mb.ghidra_image_base:
            reasons.append("Ghidra reported different image bases")
        mapping_text = (
            "Addresses are not compared directly because "
            + "; ".join(reasons or ["no Ghidra source is available"])
            + ". Functions and data correspond only through declared names or exact "
            "content joins."
        )
    mapping = MappingOut(
        declared_image_base_a=ma.declared_image_base,
        declared_image_base_b=mb.declared_image_base,
        ghidra_image_base_a=(
            f"{ma.ghidra_image_base.space}:{ma.ghidra_image_base.address}"
            if ma.ghidra_image_base
            else None
        ),
        ghidra_image_base_b=(
            f"{mb.ghidra_image_base.space}:{mb.ghidra_image_base.address}"
            if mb.ghidra_image_base
            else None
        ),
        ghidra_memory_map_a=ma.ghidra_memory_map,
        ghidra_memory_map_b=mb.ghidra_memory_map,
        addresses_comparable=addresses_comparable,
        explanation=mapping_text,
    )

    keys_a = _Keys(a, addresses_comparable)
    keys_b = _Keys(b, addresses_comparable)

    def capped(source: str, retention: dict[str, Any]) -> bool:
        return bool(
            retention.get("functions_truncated")
            or retention.get("analysis_timed_out")
            or retention.get("truncated")
            or retention.get("findings_with_capped_evidence")
        )

    def attribute(
        required: tuple[str, ...], lacking_side: str | None, kind: str, edge: bool = False
    ) -> tuple[Change | None, Attribution, str]:
        """Attribution for an observation that differs; `lacking_side` misses it."""
        for name in required:
            if source_state[name] in ("coverage_differs", "unavailable_on_both"):
                return (
                    "not_comparable",
                    "coverage_difference",
                    f"The {name} source is not available on both sides; this is not an "
                    "observed addition or removal.",
                )
        if lacking_side is not None:
            bounds = (a if lacking_side == "a" else b).bounds
            omitted = (bounds.omitted_edges_by_type if edge else bounds.omitted_nodes_by_kind).get(
                kind, 0
            )
            if omitted:
                return (
                    "not_comparable",
                    "retention_bound",
                    f"Side {lacking_side.upper()}'s snapshot omitted {kind} records at its bound; "
                    "the observation may exist there.",
                )
        environment_changed = [n for n in required if source_state[n] == "environment_differs"]
        if environment_changed:
            return (
                None,
                "analysis_environment_difference",
                "The producing source ran with a different tool identity or configuration ("
                + ", ".join(environment_changed)
                + "); the difference cannot be attributed solely to the file.",
            )
        if lacking_side is not None:
            sources = src_a if lacking_side == "a" else src_b
            capped_sources = [
                n for n in required if n in sources and capped(n, dict(sources[n].retention))
            ]
            if capped_sources:
                return (
                    None,
                    "retention_bound",
                    "The side without this observation had a capped retained window ("
                    + ", ".join(capped_sources)
                    + "); it may lie beyond that window.",
                )
        if same_bytes:
            differing_outputs = [
                n
                for n in required
                if n in src_a and n in src_b and src_a[n].output_sha256 != src_b[n].output_sha256
            ]
            if differing_outputs:
                return (
                    None,
                    "source_output_difference",
                    "Identical bytes and tool identity, but different stored outputs ("
                    + ", ".join(differing_outputs)
                    + "); the file is not the cause.",
                )
            return (
                None,
                "identical_input",
                "Both sides analyzed identical bytes with identical tool environments.",
            )
        return (
            None,
            "binary_difference_under_comparable_coverage",
            "Observed under comparable coverage: the producing sources ran on both sides with "
            "the same tool identity and configuration, and the files differ.",
        )

    changes: list[ChangeOut] = []
    correspondence_stats: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])

    def change_id(category: str, *parts: Any) -> str:
        return "change:" + _digest(COMPARISON_SCHEMA, category, *parts)[:24]

    # Nodes -------------------------------------------------------------------------
    nodes_a = {n.id: n for n in a.nodes}
    nodes_b = {n.id: n for n in b.nodes}
    index_a: dict[str, str] = {}
    index_b: dict[str, str] = {}
    for nid in nodes_a:
        key = keys_a.key(nid)
        if key is not None:
            index_a[key] = nid
    for nid in nodes_b:
        key = keys_b.key(nid)
        if key is not None:
            index_b[key] = nid
    for key in sorted(index_a.keys() | index_b.keys()):
        na = nodes_a.get(index_a.get(key, ""))
        nb = nodes_b.get(index_b.get(key, ""))
        node = na if na is not None else nb
        if node is None:
            continue
        method = key.split(":", 1)[0]
        stats = correspondence_stats[(node.kind, method)]
        required = _node_sources(node)
        if na is not None and nb is not None:
            stats[0] += 1
            fields = [
                f
                for f in MODIFIED_FIELDS.get(node.kind, ())
                if _field(na, f) != _field(nb, f)
                and not (f == "address" and method == "identical_input_address")
            ]
            change: Change = "modified" if fields else "unchanged"
            verdict, attribution, reason = attribute(required, None, node.kind)
            if change == "unchanged":
                attribution, reason = (
                    _unchanged(attribution, same_bytes),
                    "The corresponding observation is present on both sides with equal "
                    "compared fields.",
                )
            elif verdict is not None:
                change = verdict
        else:
            stats[1 if na is not None else 2] += 1
            change = "removed" if na is not None else "added"
            verdict, attribution, reason = attribute(
                required, "b" if na is not None else "a", node.kind
            )
            if verdict is not None:
                change = verdict
            fields = []
        changes.append(
            ChangeOut(
                id=change_id("node", key),
                category="node",
                kind=node.kind,
                change=change,
                attribution=attribution,
                match_method=method if na is not None and nb is not None else None,
                correspondence_key=key,
                required_sources=list(required),
                changed_fields=fields,
                reason=reason,
                exact_join=False,
                before=_brief(na) if na else None,
                after=_brief(nb) if nb else None,
            )
        )
    for side, keys, nodes in (("a", keys_a, nodes_a), ("b", keys_b, nodes_b)):
        for nid, reason in sorted(keys.unkeyed.items()):
            node = nodes[nid]
            correspondence_stats[(node.kind, "none")][1 if side == "a" else 2] += 1
            changes.append(
                ChangeOut(
                    id=change_id("node", side, nid),
                    category="node",
                    kind=node.kind,
                    change="not_comparable",
                    attribution="no_stable_correspondence",
                    match_method=None,
                    correspondence_key=None,
                    required_sources=list(_node_sources(node)),
                    changed_fields=[],
                    reason=f"Present on side {side.upper()}: {reason}",
                    exact_join=False,
                    before=_brief(node) if side == "a" else None,
                    after=_brief(node) if side == "b" else None,
                )
            )

    # Edges -------------------------------------------------------------------------
    def edge_index(
        snapshot: EvidenceSnapshot, keys: _Keys
    ) -> tuple[dict[str, SnapshotEdge], list[SnapshotEdge]]:
        keyed: dict[str, SnapshotEdge] = {}
        unkeyed: list[SnapshotEdge] = []
        for edge in snapshot.edges:
            ks, kt = keys.key(edge.source), keys.key(edge.target)
            if ks is None or kt is None:
                unkeyed.append(edge)
                continue
            keyed[f"{edge.type}\x00{ks}\x00{kt}"] = edge
        return keyed, unkeyed

    edges_a, loose_a = edge_index(a, keys_a)
    edges_b, loose_b = edge_index(b, keys_b)
    for key in sorted(edges_a.keys() | edges_b.keys()):
        ea, eb = edges_a.get(key), edges_b.get(key)
        edge = ea if ea is not None else eb
        if edge is None:
            continue
        endpoints = nodes_a if ea is not None else nodes_b
        required = _edge_sources(edge, endpoints)
        join = EDGE_JOINS.get(edge.type)
        exact = edge.strength in EXACT_STRENGTHS
        if ea is not None and eb is not None:
            fields = sorted(
                {f"attributes.{k}" for k in ea.attributes.keys() | eb.attributes.keys()}
                - {
                    f"attributes.{k}"
                    for k in ea.attributes
                    if ea.attributes.get(k) == eb.attributes.get(k)
                }
            )
            if ea.strength != eb.strength:
                fields.append("strength")
            change = "modified" if fields else "unchanged"
            verdict, attribution, reason = attribute(required, None, edge.type)
            if change == "unchanged":
                attribution = _unchanged(attribution, same_bytes)
                reason = "The relationship holds on both sides between corresponding observations."
            else:
                reason = (
                    "The relationship holds on both sides; its location attributes differ."
                    if verdict is None
                    else reason
                )
                if verdict is not None:
                    change = verdict
        else:
            change = "removed" if ea is not None else "added"
            fields = []
            if join is not None and not join_comparable.get(join, False):
                change, attribution = "not_comparable", "coverage_difference"
                reason = (
                    f"The {join} join was not evaluated on both sides; the relationship's "
                    "absence on one side is not an observation."
                )
            else:
                verdict, attribution, reason = attribute(
                    required, "b" if ea is not None else "a", edge.type, edge=True
                )
                if verdict is not None:
                    change = verdict
        changes.append(
            ChangeOut(
                id=change_id("edge", key),
                category="edge",
                kind=edge.type,
                change=change,
                attribution=attribution,
                match_method="endpoint_correspondence" if ea and eb else None,
                correspondence_key=key.replace("\x00", " | "),
                required_sources=list(required),
                changed_fields=fields,
                reason=reason,
                exact_join=exact,
                before=_brief_edge(ea) if ea else None,
                after=_brief_edge(eb) if eb else None,
            )
        )
    for side, loose in (("a", loose_a), ("b", loose_b)):
        for edge in loose:
            changes.append(
                ChangeOut(
                    id=change_id("edge", side, edge.id),
                    category="edge",
                    kind=edge.type,
                    change="not_comparable",
                    attribution="no_stable_correspondence",
                    match_method=None,
                    correspondence_key=None,
                    required_sources=list(_edge_sources(edge, nodes_a if side == "a" else nodes_b)),
                    changed_fields=[],
                    reason=f"Present on side {side.upper()}: an endpoint has no stable "
                    "correspondence, so the relationship cannot be matched.",
                    exact_join=edge.strength in EXACT_STRENGTHS,
                    before=_brief_edge(edge) if side == "a" else None,
                    after=_brief_edge(edge) if side == "b" else None,
                )
            )

    changes.sort(
        key=lambda c: (
            0 if c.category == "node" else 1,
            CHANGE_ORDER.index(c.change),
            c.kind,
            c.correspondence_key or "",
            c.id,
        )
    )

    # Summary -------------------------------------------------------------------------
    node_counts: dict[str, int] = defaultdict(int)
    edge_counts: dict[str, int] = defaultdict(int)
    attribution_counts: dict[str, int] = defaultdict(int)
    established = lost = 0
    for c in changes:
        (node_counts if c.category == "node" else edge_counts)[c.change] += 1
        if c.change != "unchanged":
            attribution_counts[c.attribution] += 1
        if c.exact_join and c.change == "added":
            established += 1
        if c.exact_join and c.change == "removed":
            lost += 1
    correspondence = [
        CorrespondenceOut(
            kind=kind,
            method=method,
            matched=stats[0],
            unmatched_a=stats[1],
            unmatched_b=stats[2],
            limitation=METHOD_LIMITATIONS.get(method, ""),
        )
        for (kind, method), stats in sorted(correspondence_stats.items())
    ]
    statements = _statements(changes, environment, same_bytes, mapping, established, lost)
    review_candidates = [
        c.id
        for c in changes
        if c.change in ("added", "removed", "modified")
        and c.attribution == "binary_difference_under_comparable_coverage"
        and (c.kind in ("finding", "function", "import", "external_symbol") or c.exact_join)
    ][:64]
    summary_body: dict[str, Any] = {
        "schema_version": COMPARISON_SCHEMA,
        "matching_policy": MATCHING_POLICY,
        "a": SideOut(**side_a, side="a", **_side_identity(a)),
        "b": SideOut(**side_b, side="b", **_side_identity(b)),
        "binary": BinaryOut(
            identical=same_bytes,
            sha256_a=a.sample.sha256,
            sha256_b=b.sample.sha256,
            size_a=a.sample.size_bytes,
            size_b=b.sample.size_bytes,
            format_a=a.sample.format,
            format_b=b.sample.format,
            same_sample=a.sample.sample_id == b.sample.sample_id,
        ),
        "environment": environment,
        "coverage": coverage,
        "mapping": mapping,
        "correspondence": correspondence,
        "counts": CountsOut(
            nodes=dict(sorted(node_counts.items())),
            edges=dict(sorted(edge_counts.items())),
            attribution=dict(sorted(attribution_counts.items())),
            exact_joins_established=established,
            exact_joins_lost=lost,
        ),
        "statements": statements,
        "review_candidates": review_candidates,
        "incomparable": incomparable,
        "limitations": limitations,
    }
    digest = _digest(
        COMPARISON_SCHEMA,
        a.content_sha256,
        b.content_sha256,
        [c.model_dump(mode="json") for c in changes],
    )
    summary = ComparisonOut(**summary_body, comparison_sha256=digest)
    return Comparison(summary, changes)


def _unchanged(attribution: Attribution, same_bytes: bool) -> Attribution:
    if same_bytes:
        return "identical_input"
    if attribution == "binary_difference_under_comparable_coverage":
        return "comparable_coverage"
    return attribution


METHOD_LIMITATIONS = {
    "identical_input_address": "Exact: identical bytes and Ghidra environment on both sides.",
    "rule_identity": "Same rule name; the rule's text may differ if rule-set digests differ.",
    "declared_section_name": "Declared names can be changed or reused; ordinal disambiguates.",
    "string_value_digest": "Complete-value equality; says nothing about location or use.",
    "joined_string_value_digest": "Inherited through an exact file-offset join to a string.",
    "unique_symbol_name": "Declared names can change; a renamed symbol is unmatched.",
    "import_name": "Import nodes exist only where an external symbol joined them by name.",
    "singleton": "One declared entry point per file.",
    "none": "No correspondence method applied; these observations are not compared.",
}


def _side_identity(snapshot: EvidenceSnapshot) -> dict[str, Any]:
    return {
        "version_id": snapshot.sample.version_id,
        "sample_id": snapshot.sample.sample_id,
        "sample_sha256": snapshot.sample.sha256,
        "file_format": snapshot.sample.format,
        "algorithm": snapshot.algorithm,
        "snapshot_schema": snapshot.schema_version,
        "scope_sha256": snapshot.scope_sha256,
        "content_sha256": snapshot.content_sha256,
    }


KIND_NOUNS = {
    "entry_point": "entry-point declaration",
    "section": "declared section",
    "import": "import joined to an external symbol",
    "function": "Ghidra function",
    "program_data": "Ghidra data item",
    "external_symbol": "Ghidra external symbol",
    "string": "extracted string",
    "finding": "rule match",
}


def _statements(
    changes: list[ChangeOut],
    environment: list[SourceDiffOut],
    same_bytes: bool,
    mapping: MappingOut,
    established: int,
    lost: int,
) -> list[StatementOut]:
    """Reviewed sentence templates. No untrusted text is interpolated."""
    out: list[StatementOut] = []

    def say(kind: str, text: str, cited: list[str]) -> None:
        out.append(
            StatementOut(
                id="statement:" + _digest(kind, text)[:20],
                kind=kind,
                text=text,
                cites=cited[:MAX_CITATIONS],
                cites_total=len(cited),
            )
        )

    say(
        "binary_identity",
        "Both sides analyzed identical bytes (same SHA-256); any difference comes from "
        "sources, configuration or retention, not from the file."
        if same_bytes
        else "The sides analyzed different files. Differences observed under comparable "
        "coverage are consistent with the file change; others are attributed below.",
        [],
    )
    for diff in environment:
        if diff.comparability in ("environment_differs", "coverage_differs"):
            say(f"source_{diff.comparability}", diff.explanation, [])
    if not mapping.addresses_comparable:
        say("address_correspondence", mapping.explanation, [])

    grouped: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for c in changes:
        if c.change == "unchanged":
            continue
        grouped[(c.category, c.change, c.attribution)].append(c.id)
        if c.category == "node":
            grouped[("kind", c.kind, f"{c.change}|{c.attribution}")].append(c.id)
    for (category, kind, key), cited in sorted(grouped.items()):
        if category != "kind":
            continue
        change, attribution = key.split("|")
        noun = KIND_NOUNS.get(kind, kind)
        count = len(cited)
        plural = "s" if count != 1 else ""
        one = count == 1
        appear, differ, have = (
            ("appears", "differs", "has") if one else ("appear", "differ", "have")
        )
        if change == "added" and attribution == "binary_difference_under_comparable_coverage":
            text = (
                f"{count} {noun} observation{plural} {appear} only in B under comparable coverage."
            )
        elif change == "removed" and attribution == "binary_difference_under_comparable_coverage":
            text = (
                f"{count} {noun} observation{plural} from A {have} no counterpart in B under "
                "comparable coverage, within B's retained windows."
            )
        elif change == "modified":
            text = (
                f"{count} corresponding {noun} observation{plural} {differ} in compared fields "
                "(location, size or declared values)."
            )
        elif change in ("added", "removed") and attribution == "analysis_environment_difference":
            side = "B" if change == "added" else "A"
            text = (
                f"{count} {noun} observation{plural} {appear} only in {side}, but the producing "
                "tool or configuration differs; the file is not established as the cause."
            )
        elif change in ("added", "removed") and attribution == "retention_bound":
            side = "B" if change == "added" else "A"
            text = (
                f"{count} {noun} observation{plural} {appear} only in {side}; the other side's "
                "window was capped, so absence there is not established."
            )
        elif change == "not_comparable" and attribution == "coverage_difference":
            text = (
                f"{count} {noun} observation{plural} cannot be compared because a required "
                "source is available on one side only."
            )
        elif change == "not_comparable" and attribution == "no_stable_correspondence":
            text = (
                f"{count} {noun} observation{plural} {have} no stable correspondence key and "
                "are not compared."
            )
        elif change == "not_comparable":
            text = f"{count} {noun} observation{plural} cannot be compared ({attribution})."
        else:
            text = f"{count} {noun} observation{plural}: {change} ({attribution})."
        say(f"{kind}_{change}_{attribution}", text, cited)
    if established or lost:
        exact_added = [c.id for c in changes if c.exact_join and c.change == "added"]
        exact_removed = [c.id for c in changes if c.exact_join and c.change == "removed"]
        say(
            "exact_joins",
            f"{established} exact relationship(s) are established only in B and {lost} only "
            "in A, among relationships whose joins were evaluated on both sides.",
            exact_added + exact_removed,
        )
    unchanged = sum(c.change == "unchanged" for c in changes)
    say("unchanged", f"{unchanged} corresponding observations and relationships are unchanged.", [])
    return out
