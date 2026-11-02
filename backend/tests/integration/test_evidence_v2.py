"""Evidence graph v2 (v0.11) over real outputs: import slots, structure, comparison.

LIEF, strings, YARA-X and capa run live. Ghidra documents are real ghidra-5
recordings (tests/recorded/README.md). Expected slot offsets are computed with
LIEF's own translation helpers, independently of Bytasm's derived values.
"""

import json
from pathlib import Path
from typing import Any

import lief
from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64, ELF_X86_64_V2
from test_analysis import process
from test_evidence_graph import (
    CAPA_READ_FILE,
    all_edges,
    import_and_scan,
    recorded,
    seed_ghidra,
    summary,
)
from test_evidence_snapshots import all_changes, compare, pin

RECORDED_V5 = Path(__file__).resolve().parents[1] / "recorded" / "ghidra-5"


def recorded_v5(fixture: Path) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((RECORDED_V5 / f"{fixture.name}.ghidra.json").read_text())
    return value


def test_pe_import_slots_join_ghidra_pointer_slots_exactly(tmp_path: Path) -> None:
    binary = lief.parse(CAPA_READ_FILE.read_bytes())
    assert isinstance(binary, lief.PE.Binary)
    expected = {
        binary.rva_to_offset(e.iat_address): e.name for i in binary.imports for e in i.entries
    }
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        ghidra = seed_ghidra(client, version, recorded_v5(CAPA_READ_FILE))
        result = summary(client, version)
        assert result["scope"]["schema_version"] == "bytasm-evidence-graph-2"
        joins = {j["join"]: j for j in result["coverage"]["joins"]}
        slot_join = joins["import_slot"]
        assert slot_join["performed"] is True and slot_join["joined"] >= 30
        assert joins["capa_function"]["joined"] == 1  # v0.10 join unchanged
        edges = all_edges(client, version, "external_symbol_import_slot")
        assert len(edges) >= 30
        for edge in edges:
            assert edge["strength"] == "exact_offset_equality"
            assert edge["basis"] == ["lief_import_address_table", "ghidra_memory_block_file_bytes"]
            offset = edge["attributes"]["slot_file_offset"]
            assert offset in expected
            assert edge["attributes"]["names_equal"] is True
            tools = {loc["tool"] for loc in edge["locators"]}
            assert tools == {"ghidra", "lief"}
        claim = next(
            c for c in result["claims"] if c["kind"] == "import_slots_match_ghidra_pointers"
        )
        assert set(claim["evidence"]) == {e["id"] for e in edges}
        assert "does not show that any import is called" in claim["summary"]
        for name in ("ReadFile", "CreateFileA"):
            assert name not in claim["summary"]  # untrusted names stay labels

        # Function structure: real basic blocks, flows and call sites.
        functions = client.get(f"/api/v1/runs/{ghidra}/ghidra/functions?q=FUN_140001180").json()
        indices = [f["index"] for f in functions["items"] if f["name"] == "FUN_140001180"]
        assert indices, functions["items"][:3]
        structure = client.get(f"/api/v1/runs/{ghidra}/ghidra/functions/{indices[0]}/structure")
        assert structure.status_code == 200, structure.text
        body = structure.json()
        assert body["state"] == "available" and body["protocol_version"] == "ghidra-5"
        assert body["basic_block_count"] == len(body["basic_blocks"]) >= 2
        assert any(k.startswith("conditional_jump") for k in body["flow_counts"])
        kinds = {s["kind"] for s in body["call_sites"]}
        assert kinds == {"direct", "indirect"}
        for site in body["call_sites"]:
            if site["target"] is None:
                assert site["resolution"] == "unresolved" and site["target_basis"] is None
            elif site["resolution"] == "inventory_function":
                assert site["target_function_name"]
        for block in body["basic_blocks"]:
            for flow in block["flows"]:
                assert flow["provenance"] == "ghidra_basic_block_model"
        node = next(
            n
            for n in client.get(
                f"/api/v1/sample-versions/{version}/evidence/nodes",
                params={"kind": "function", "q": "FUN_140001180"},
            ).json()["items"]
        )
        assert node["attributes"]["basic_block_count"] == body["basic_block_count"]
        assert node["attributes"]["indirect_call_count"] >= 1


def test_historical_protocols_report_structure_and_slots_as_not_captured(
    tmp_path: Path,
) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        ghidra = seed_ghidra(client, version, recorded(CAPA_READ_FILE))  # ghidra-4
        joins = {j["join"]: j for j in summary(client, version)["coverage"]["joins"]}
        assert joins["import_slot"]["performed"] is False
        assert "ghidra-5" in joins["import_slot"]["reason"]
        assert all_edges(client, version, "external_symbol_import_slot") == []
        body = client.get(f"/api/v1/runs/{ghidra}/ghidra/functions/0/structure").json()
        assert body["state"] == "not_captured" and body["basic_blocks"] == []
        assert "ghidra-4" in body["reason"]
        assert (
            client.get(f"/api/v1/runs/{ghidra}/ghidra/functions/9999/structure").status_code == 404
        )


def test_elf_versions_compare_with_real_ghidra_on_both_sides(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        first = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        second = do_import(
            client, project, ELF_X86_64_V2.read_bytes(), sample_id=first["sample_id"]
        ).json()["sample_version"]
        v1, v2 = first["id"], second["id"]
        for version, fixture in ((v1, ELF_X86_64), (v2, ELF_X86_64_V2)):
            run = client.post(
                f"/api/v1/sample-versions/{version}/runs", json={"profile_id": "default-static"}
            )
            assert run.status_code == 202
            assert process(ctx_of(client)) == "succeeded"
            seed_ghidra(client, version, recorded_v5(fixture))
        joins = {j["join"]: j for j in summary(client, v2)["coverage"]["joins"]}
        assert joins["import_slot"]["joined"] >= 6
        review = pin(client, v1)
        assert any(e["type"] == "external_symbol_import_slot" for e in review["evidence"]["edges"])
        result = compare(client, f"review:{review['id']}", f"version:{v2}")["comparison"]
        envs = {e["source"]: e for e in result["environment"]}
        assert envs["ghidra"]["comparability"] == "comparable"
        assert envs["strings"]["comparability"] == "comparable"
        assert result["mapping"]["addresses_comparable"] is False

        changes = all_changes(client, f"review:{review['id']}", f"version:{v2}")
        added_strings = [c for c in changes if c["kind"] == "string" and c["change"] == "added"]
        assert any("environment lookup" in c["after"]["label"] for c in added_strings)
        assert all(
            c["attribution"] == "binary_difference_under_comparable_coverage" for c in added_strings
        )
        added_imports = [c for c in changes if c["kind"] == "import" and c["change"] == "added"]
        assert [c["after"]["label"] for c in added_imports] == ["getenv"]
        slot_edges = [
            c
            for c in changes
            if c["kind"] == "external_symbol_import_slot" and c["change"] == "added"
        ]
        assert slot_edges and all(c["exact_join"] for c in slot_edges)
        main = next(
            c
            for c in changes
            if c["kind"] == "function" and (c["before"] or {}).get("label") == "main"
        )
        assert main["match_method"] == "unique_symbol_name"
        assert main["change"] == "modified"
        assert "attributes.basic_block_count" in main["changed_fields"]
        assert main["id"] in result["review_candidates"]
        assert not [
            c
            for c in changes
            if c["kind"] == "function"
            and c["change"] in ("added", "removed")
            and (c["before"] or c["after"])["label"].startswith("FUN_")
        ]
        statements = " ".join(s["text"] for s in result["statements"])
        assert "appear only in B under comparable coverage" in statements or (
            "appears only in B under comparable coverage" in statements
        )
        assert result["counts"]["exact_joins_established"] >= 1
