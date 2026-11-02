"""Graph construction rules that need no tool: deduplication, caps and coarse joins."""

from types import SimpleNamespace
from typing import Any

from test_ghidra_provider import document

from bytasm.address_map import DeclaredLayout
from bytasm.evidence_graph import (
    MAX_LOCATORS_PER_EDGE,
    GhidraSource,
    MetadataSource,
    build_graph,
)
from bytasm.evidence_understand import build_claims
from bytasm.ghidra_protocol import GhidraResult


def metadata(imports: tuple[str, ...], libraries: tuple[str, ...], fmt: str = "PE") -> Any:
    header = {"format": fmt, "declared_header": {"pe_image_base": 0x100000}}
    sections = [
        SimpleNamespace(
            index=0,
            name=".text",
            file_offset=0,
            raw_size=0x1000,
            virtual_address=0,
            virtual_size=0x1000,
            flags=[],
        )
    ]
    return MetadataSource(
        run_id="r" * 32,
        invocation_id="i" * 32,
        output_sha256="0" * 64,
        tool_version="1.0.0",
        file_format=fmt,
        file_size=0x1000,
        entry_point=None,
        layout=DeclaredLayout.from_import(header, sections),
        imports=imports,
        imported_libraries=libraries,
    )


def ghidra_with_references(count: int, name: str) -> GhidraSource:
    value = document()
    fn = value["functions"][0]
    instructions = [
        {
            "address": {"space": "ram", "address": f"{0x100000 + i:08x}"},
            "bytes_hex": "90",
            "text": "NOP",
        }
        for i in range(count)
    ]
    fn["instructions"] = instructions
    fn["references"] = [
        {
            "source": ins["address"],
            "target": {"space": "ram", "address": "00100800"},
            "kind": "external_symbol",
            "reference_type": "DATA",
            "provenance": "ghidra_instruction_reference",
            "resolved_external_target": {"space": "EXTERNAL", "address": "00000001"},
            "resolved_external_provenance": "ghidra_function_thunk",
            "target_name": name,
        }
        for ins in instructions
    ]
    return GhidraSource("g" * 32, "h" * 32, "1" * 64, GhidraResult.model_validate(value))


def test_repeated_references_are_one_edge_with_capped_locators() -> None:
    graph = build_graph(
        "v",
        "s",
        metadata(("ReadFile",), ("KERNEL32.dll",)),
        ghidra_with_references(12, "KERNEL32.DLL::ReadFile"),
        None,
    )
    refs = [e for e in graph.edges.values() if e.type == "references_external_symbol"]
    assert len(refs) == 1
    assert refs[0].locator_count == 12
    assert len(refs[0].locators) == MAX_LOCATORS_PER_EDGE and refs[0].locators_truncated
    assert refs[0].basis == ["ghidra_instruction_reference", "ghidra_function_thunk"]
    assert refs[0].attributes["original_target"] == "ram:00100800"
    named = [e for e in graph.edges.values() if e.type == "external_symbol_named_as_import"]
    assert len(named) == 1 and named[0].strength == "name_equality"
    claims, total = build_claims(graph, "v")
    assert total == 1 and "ReadFile" not in claims[0].summary
    assert claims[0].completeness.state == "complete_within_retained_windows"


def test_name_join_requires_exact_name_and_declared_library() -> None:
    for name, libraries in (
        ("OTHER.DLL::ReadFile", ("KERNEL32.dll",)),
        ("KERNEL32.DLL::ReadFileEx", ("KERNEL32.dll",)),
        ("KERNEL32.DLL::readfile", ("KERNEL32.dll",)),
    ):
        graph = build_graph(
            "v", "s", metadata(("ReadFile",), libraries), ghidra_with_references(1, name), None
        )
        assert not [e for e in graph.edges.values() if e.type == "external_symbol_named_as_import"]
        assert graph.joins["import_name"].candidates == 1
        assert graph.joins["import_name"].joined == 0


def test_without_memory_map_no_offset_is_invented() -> None:
    source = ghidra_with_references(1, "KERNEL32.DLL::ReadFile")
    value = source.result.model_dump()
    value["schema_version"] = "ghidra-3"
    for key in ("image_base", "memory_blocks", "memory_blocks_truncated"):
        value.pop(key)
    legacy = GhidraSource("g" * 32, "h" * 32, "1" * 64, GhidraResult.model_validate(value))
    graph = build_graph("v", "s", metadata((), ()), legacy, None)
    functions = [n for n in graph.nodes.values() if n.kind == "function"]
    assert functions and all(n.file_offset is None for n in functions)
    assert not [e for e in graph.edges.values() if e.type == "located_in_section"]
    assert graph.joins["import_name"].reason


def test_recorded_real_outputs_match_the_published_v4_schema() -> None:
    import json
    from pathlib import Path

    import jsonschema

    root = Path(__file__).resolve().parents[3]
    # The v4 schema is historical (frozen); the current model publishes v5.
    v4 = json.loads((root / "schemas/ghidra-analysis-v4.schema.json").read_text())
    v5 = json.loads((root / "schemas/ghidra-analysis-v5.schema.json").read_text())
    assert v5 == GhidraResult.model_json_schema()
    for path in sorted((root / "backend/tests/recorded").glob("*.ghidra.json")):
        value = json.loads(path.read_text())
        version = GhidraResult.model_validate(value).schema_version
        assert version in ("ghidra-4", "ghidra-5")
        jsonschema.validate(value, v5)
        if version == "ghidra-4":
            jsonschema.validate(value, v4)
