"""Evidence snapshot and comparison rules over a real recorded Ghidra document.

The inputs are the recorded real ghidra-4 output for hello_v1 (x86-64 ELF) and
LIEF's real parse of the same fixture. Rebasing, section shifts, tool drift and
protocol changes are applied as exact transformations of those documents, so
the expected answers are known independently of Bytasm's matching.
"""

import copy
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from conftest import ELF_X86_64

import bytasm.evidence_snapshot as evidence_snapshot
from bytasm.adapters.metadata_lief import extract_metadata
from bytasm.address_map import DeclaredLayout
from bytasm.evidence_compare import Comparison, compare_snapshots
from bytasm.evidence_graph import (
    GhidraSource,
    MetadataSource,
    PatternSource,
    StepRecord,
    StringRecord,
    build_graph,
)
from bytasm.evidence_snapshot import EvidenceSnapshot, SnapshotSample, build_snapshot, verify
from bytasm.ghidra_protocol import GhidraResult

RECORDED = Path(__file__).resolve().parents[1] / "recorded"
SIDE = {"kind": "version_current", "review_id": None}


def elf_metadata(
    sha: str = "a" * 64, va_delta: int = 0, offset_delta: int = 0
) -> tuple[MetadataSource, int]:
    data = ELF_X86_64.read_bytes()
    meta = extract_metadata(data, "ELF")
    rows = [
        SimpleNamespace(
            index=i,
            name=s["name"],
            file_offset=s["file_offset"] + (offset_delta if s["file_offset"] else 0),
            raw_size=s["file_size"],
            virtual_address=s["virtual_address"] + (va_delta if s["virtual_address"] else 0),
            virtual_size=s["declared_size"],
            flags=s["flags"],
        )
        for i, s in enumerate(meta["sections"])
    ]
    header = {"format": "ELF", "declared_header": meta["declared_header"]}
    entry = meta["entry_point"] + va_delta
    return (
        MetadataSource(
            run_id=sha[:32],
            invocation_id=sha[32:],
            output_sha256=sha,
            tool_version="0.17.6",
            file_format="ELF",
            file_size=len(data) + offset_delta,
            entry_point=entry,
            layout=DeclaredLayout.from_import(header, rows),
            imports=tuple(sorted(meta["imports"]["functions"])),
            imported_libraries=tuple(meta["imports"]["libraries"]),
        ),
        len(data),
    )


def recorded_doc() -> dict[str, Any]:
    value: dict[str, Any] = json.loads((RECORDED / "hello_v1-x86_64.elf.ghidra.json").read_text())
    return value


def shift_ram(value: Any, delta: int, offset_delta: int = 0) -> Any:
    """Rebase every `ram` address by `delta` and every file offset by `offset_delta`."""
    if isinstance(value, dict):
        if set(value) == {"space", "address"} and value["space"] == "ram":
            return {"space": "ram", "address": f"{int(value['address'], 16) + delta:08x}"}
        out = {k: shift_ram(v, delta, offset_delta) for k, v in value.items()}
        if "file_offset" in out and "provenance" in out and offset_delta:
            out["file_offset"] = value["file_offset"] + offset_delta
        if "name" in value and isinstance(value["name"], str) and value["name"].startswith("FUN_"):
            out["name"] = f"FUN_{int(value['name'][4:], 16) + delta:08x}"
        return out
    if isinstance(value, list):
        return [shift_ram(v, delta, offset_delta) for v in value]
    return value


def snapshot(
    doc: dict[str, Any] | None,
    meta: MetadataSource,
    sha: str = "a" * 64,
    pattern: PatternSource | None = None,
    version: str = "v" * 32,
) -> EvidenceSnapshot:
    ghidra = (
        None
        if doc is None
        else GhidraSource("g" * 32, "h" * 32, "1" * 64, GhidraResult.model_validate(doc))
    )
    graph = build_graph(version, sha, meta, ghidra, pattern)
    return build_snapshot(
        graph,
        SnapshotSample(
            version_id=version, sample_id="s" * 32, sha256=sha, size_bytes=1, format="ELF"
        ),
    )


def by_kind(result: Comparison, kind: str) -> list[Any]:
    return [c for c in result.changes if c.kind == kind]


def test_identical_snapshots_compare_as_unchanged_and_deterministic() -> None:
    meta, _ = elf_metadata()
    a = snapshot(recorded_doc(), meta)
    b = snapshot(recorded_doc(), meta)
    assert a.content_sha256 == b.content_sha256 and verify(a)
    first = compare_snapshots(a, b, SIDE, SIDE)
    second = compare_snapshots(a, b, SIDE, SIDE)
    assert first.summary == second.summary
    assert first.summary.comparison_sha256 == second.summary.comparison_sha256
    assert first.summary.mapping.addresses_comparable
    assert {c.change for c in first.changes} == {"unchanged"}
    assert {c.attribution for c in first.changes} == {"identical_input"}
    methods = {c.match_method for c in by_kind(first, "function")}
    assert methods == {"identical_input_address"}


def test_rebased_binary_never_matches_functions_by_address() -> None:
    delta = 0x200000
    meta_a, _ = elf_metadata("a" * 64)
    meta_b, _ = elf_metadata("b" * 64, va_delta=delta)
    doc_b = shift_ram(recorded_doc(), delta)
    result = compare_snapshots(
        snapshot(recorded_doc(), meta_a, "a" * 64), snapshot(doc_b, meta_b, "b" * 64), SIDE, SIDE
    )
    summary = result.summary
    assert not summary.mapping.addresses_comparable
    assert summary.mapping.ghidra_image_base_b == "ram:00300000"
    assert "Ghidra reported different image bases" in summary.mapping.explanation
    functions = by_kind(result, "function")
    # No function is reported added or removed merely because its address moved.
    assert not [c for c in functions if c.change in ("added", "removed")]
    main = next(c for c in functions if c.before is not None and c.before["label"] == "main")
    assert main.match_method == "unique_symbol_name"
    assert main.change == "modified" and main.changed_fields == ["address"]
    assert main.after["address"]["address"] == f"{0x101139 + delta:08x}"
    generated = [
        c for c in functions if (c.before or c.after or {}).get("label", "").startswith("FUN_")
    ]
    assert generated and {c.change for c in generated} == {"not_comparable"}
    assert {c.attribution for c in generated} == {"no_stable_correspondence"}
    # Declared sections moved in the address space: modified, not added/removed.
    sections = by_kind(result, "section")
    assert not [c for c in sections if c.change in ("added", "removed")]
    assert any("attributes.declared_virtual_address" in c.changed_fields for c in sections)
    # Exact offset joins survive the rebase: offsets did not move.
    entry = [c for c in result.changes if c.kind == "entry_point_is_function"]
    assert entry and entry[0].change in ("unchanged", "modified")


def test_shifted_sections_report_offset_changes_under_comparable_coverage() -> None:
    meta_a, _ = elf_metadata("a" * 64)
    meta_b, _ = elf_metadata("b" * 64, offset_delta=0x1000)
    doc_b = shift_ram(recorded_doc(), 0, offset_delta=0x1000)
    result = compare_snapshots(
        snapshot(recorded_doc(), meta_a, "a" * 64), snapshot(doc_b, meta_b, "b" * 64), SIDE, SIDE
    )
    text = next(c for c in by_kind(result, "section") if c.before and c.before["label"] == ".text")
    assert text.change == "modified" and text.changed_fields == ["file_offset"]
    assert text.attribution == "binary_difference_under_comparable_coverage"
    assert result.summary.binary.identical is False


def test_tool_identity_changes_are_not_attributed_to_the_file() -> None:
    meta_a, _ = elf_metadata("a" * 64)
    meta_b, _ = elf_metadata("b" * 64)
    doc_b = recorded_doc()
    doc_b["script_sha256"] = "f" * 64
    doc_b["functions"] = doc_b["functions"][:12]
    doc_b["function_count"] = 12
    result = compare_snapshots(
        snapshot(recorded_doc(), meta_a, "a" * 64), snapshot(doc_b, meta_b, "b" * 64), SIDE, SIDE
    )
    ghidra = next(e for e in result.summary.environment if e.source == "ghidra")
    assert ghidra.comparability == "environment_differs"
    assert ghidra.differing_fields == ["script_sha256"]
    changed = [c for c in by_kind(result, "function") if c.change in ("added", "removed")]
    assert changed
    assert {c.attribution for c in changed} == {"analysis_environment_difference"}
    assert not result.summary.review_candidates


def test_protocol_versions_and_missing_maps_make_joins_incomparable() -> None:
    meta, _ = elf_metadata()
    legacy = recorded_doc()
    legacy["schema_version"] = "ghidra-3"
    for key in ("image_base", "memory_blocks", "memory_blocks_truncated"):
        legacy.pop(key)
    result = compare_snapshots(snapshot(legacy, meta), snapshot(recorded_doc(), meta), SIDE, SIDE)
    ghidra = next(e for e in result.summary.environment if e.source == "ghidra")
    assert "protocol_version" in ghidra.differing_fields
    joins = {j.join: j for j in result.summary.coverage}
    assert joins["entry_point"].comparable is False
    entry_edges = [c for c in result.changes if c.kind == "entry_point_is_function"]
    assert entry_edges and {c.change for c in entry_edges} == {"not_comparable"}
    assert {c.attribution for c in entry_edges} == {"coverage_difference"}
    assert result.summary.mapping.ghidra_memory_map_a == "unavailable"


def test_missing_tool_output_is_not_comparable_rather_than_removed() -> None:
    meta, _ = elf_metadata()
    result = compare_snapshots(snapshot(recorded_doc(), meta), snapshot(None, meta), SIDE, SIDE)
    functions = by_kind(result, "function")
    assert functions and {c.change for c in functions} <= {"not_comparable"}
    assert "coverage_difference" in {c.attribution for c in functions}
    assert not [c for c in result.changes if c.change == "removed"]
    statements = " ".join(s.text for s in result.summary.statements)
    assert "available only on side A" in statements


def pattern(strings: list[tuple[int, str]], truncated: bool = False) -> PatternSource:
    return PatternSource(
        run_id="p" * 32,
        status="succeeded",
        profile_id="default-static",
        steps=(StepRecord("strings", "succeeded", "q" * 32, "bytasm", "p" * 32, "2" * 64, "1"),),
        findings=(),
        strings=tuple(
            StringRecord(i, off, "ascii", text, False) for i, (off, text) in enumerate(strings)
        ),
        strings_invocation_id="q" * 32,
        strings_output_sha256="2" * 64,
        strings_truncated=truncated,
    )


def string_offsets(doc: dict[str, Any], meta: MetadataSource) -> list[tuple[int, str]]:
    """Strings at the exact offsets of Ghidra's string references (joined nodes)."""
    graph = build_graph(
        "v",
        "a" * 64,
        meta,
        GhidraSource("g", "h", "1" * 64, GhidraResult.model_validate(doc)),
        None,
    )
    return sorted(
        {
            (n.file_offset, str(n.attributes["preview"]))
            for n in graph.nodes.values()
            if n.kind == "program_data"
            and n.attributes.get("data_kind") == "string"
            and n.file_offset is not None
        }
    )


def test_strings_correspond_by_complete_value_not_display_text() -> None:
    meta_a, _ = elf_metadata("a" * 64)
    meta_b, _ = elf_metadata("b" * 64)
    found = string_offsets(recorded_doc(), meta_a)
    assert found
    a = snapshot(recorded_doc(), meta_a, "a" * 64, pattern(found))
    b = snapshot(recorded_doc(), meta_b, "b" * 64, pattern([(o, t + "!") for o, t in found]))
    result = compare_snapshots(a, b, SIDE, SIDE)
    strings = by_kind(result, "string")
    assert {c.change for c in strings} == {"added", "removed"}
    assert {c.match_method for c in strings} == {None}
    # Program data reached through a string join inherits that content key.
    data = [c for c in by_kind(result, "program_data") if c.correspondence_key]
    assert data and all(
        (c.correspondence_key or "").startswith("joined_string_value_digest") for c in data
    )
    same = compare_snapshots(
        a, snapshot(recorded_doc(), meta_b, "b" * 64, pattern(found)), SIDE, SIDE
    )
    assert {c.change for c in by_kind(same, "string")} == {"unchanged"}
    assert {c.match_method for c in by_kind(same, "string")} == {"string_value_digest"}


def test_capped_strings_window_is_reported_as_retention_bound() -> None:
    meta_a, _ = elf_metadata("a" * 64)
    meta_b, _ = elf_metadata("b" * 64)
    found = string_offsets(recorded_doc(), meta_a)
    a = snapshot(recorded_doc(), meta_a, "a" * 64, pattern(found))
    b = snapshot(recorded_doc(), meta_b, "b" * 64, pattern(found[1:], truncated=True))
    result = compare_snapshots(a, b, SIDE, SIDE)
    removed = [c for c in by_kind(result, "string") if c.before and not c.after]
    assert removed and {c.attribution for c in removed} == {"retention_bound"}


def test_snapshot_bounds_retain_by_priority_and_count_omissions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    meta, _ = elf_metadata()
    monkeypatch.setattr(evidence_snapshot, "MAX_NODES", 40)
    bounded = snapshot(recorded_doc(), meta)
    assert bounded.bounds.truncated
    assert bounded.bounds.nodes_retained == 40
    assert sum(bounded.bounds.omitted_nodes_by_kind.values()) == (
        bounded.bounds.nodes_total - bounded.bounds.nodes_retained
    )
    kinds = [n.kind for n in bounded.nodes]
    assert "section" in kinds and "entry_point" in kinds
    ids = {n.id for n in bounded.nodes}
    assert all(e.source in ids and e.target in ids for e in bounded.edges)
    assert any("bounded subset" in text for text in bounded.limitations)
    full = snapshot(recorded_doc(), meta)
    monkeypatch.setattr(evidence_snapshot, "MAX_NODES", 4096)
    result = compare_snapshots(bounded, snapshot(recorded_doc(), meta), SIDE, SIDE)
    added = [c for c in result.changes if c.change == "added"]
    assert not added  # omitted at a bound is never "added" on the other side
    assert full.bounds.truncated  # MAX_NODES was still 40 when built


def test_snapshot_byte_bound_shrinks_deterministically(monkeypatch: pytest.MonkeyPatch) -> None:
    meta, _ = elf_metadata()
    full = snapshot(recorded_doc(), meta)
    size = len(evidence_snapshot.canonical(full.model_dump(mode="json")))
    monkeypatch.setattr(evidence_snapshot, "MAX_SNAPSHOT_BYTES", size // 2)
    first = snapshot(recorded_doc(), meta)
    second = snapshot(recorded_doc(), meta)
    assert first == second and first.bounds.truncated
    assert len(evidence_snapshot.canonical(first.model_dump(mode="json"))) <= size // 2
    monkeypatch.setattr(evidence_snapshot, "MAX_SNAPSHOT_BYTES", 2048)
    with pytest.raises(ValueError):
        snapshot(recorded_doc(), meta)


def test_tampered_snapshot_fails_verification() -> None:
    meta, _ = elf_metadata()
    good = snapshot(recorded_doc(), meta)
    body = good.model_dump(mode="json")
    body["nodes"][0]["label"] = "tampered"
    assert not verify(EvidenceSnapshot.model_validate(body))


def large_doc(count: int, offset: int = 0) -> dict[str, Any]:
    doc = recorded_doc()
    template = copy.deepcopy(doc["functions"][-1])  # an inventory-only external entry
    functions = []
    for i in range(count):
        fn = copy.deepcopy(template)
        fn["entry"] = {"space": "ram", "address": f"{0x400000 + 16 * (i + offset):08x}"}
        fn["name"] = f"routine_{i}"
        fn["external"] = False
        fn["namespace"] = "Global"
        functions.append(fn)
    doc["functions"] = functions
    doc["function_count"] = count
    doc["functions_truncated"] = False
    return doc


def test_large_bounded_graph_comparison_is_fast_and_bounded() -> None:
    meta_a, _ = elf_metadata("a" * 64)
    meta_b, _ = elf_metadata("b" * 64)
    started = time.monotonic()
    a = snapshot(large_doc(1024), meta_a, "a" * 64)
    b = snapshot(large_doc(1024, offset=3), meta_b, "b" * 64)
    built = time.monotonic() - started
    started = time.monotonic()
    result = compare_snapshots(a, b, SIDE, SIDE)
    compared = time.monotonic() - started
    functions = by_kind(result, "function")
    assert len([c for c in functions if c.match_method == "unique_symbol_name"]) == 1024
    assert {c.changed_fields[0] for c in functions if c.change == "modified"} == {"address"}
    assert built < 10 and compared < 5, (built, compared)
