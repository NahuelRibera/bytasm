"""Evidence correlation over real tool outputs.

LIEF, strings, YARA-X and capa run for real in these tests. The Ghidra side is a
recorded real ghidra-4 document (tests/recorded/README.md), persisted exactly
as the worker would persist it. Expected offsets are computed independently
with LIEF, never copied from Bytasm's own translation.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import lief
from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64, FIXTURES_DIR, PE_X86_64_EXE
from fastapi.testclient import TestClient
from test_analysis import process

from bytasm.db.models import AnalysisRun, ToolInvocation
from bytasm.ghidra_protocol import GhidraResult
from bytasm.ghidra_provider import profile_snapshot
from bytasm.jobs import runs

RECORDED = Path(__file__).resolve().parents[1] / "recorded"
CAPA_READ_FILE = FIXTURES_DIR / "bin" / "capa_read_file-x86_64.exe"


def seed_ghidra(
    client: TestClient, version: str, document: dict[str, Any], state: str = "succeeded"
) -> str:
    """Persist a Ghidra document as a completed ghidra-static run (no tool executed)."""
    ctx = ctx_of(client)
    raw = GhidraResult.model_validate(document).model_dump_json().encode()
    digest = hashlib.sha256(raw).hexdigest()
    ctx.outputs.put_bytes(raw, digest, ctx.tmp_dir)
    snapshot = profile_snapshot()
    step = {
        **snapshot["steps"][0],
        "profile_sha256": document["profile_sha256"],
        "script_sha256": document["script_sha256"],
    }
    snapshot["steps"] = [step]
    with ctx.sessions() as session:
        run = runs.new_queued_run(version, snapshot, datetime.now(UTC))
        run.status = state
        run.started_at = run.finished_at = datetime.now(UTC)
        session.add(run)
        session.flush()
        session.add(
            ToolInvocation(
                run_id=run.id,
                step_index=0,
                tool_name="ghidra",
                tool_version="12.2",
                adapter_name="ghidra_headless",
                adapter_version="1",
                args=step,
                status=state,
                failure_reason=None,
                exit_code=0,
                duration_ms=1,
                warnings=[],
                raw_output_sha256=digest if state == "succeeded" else None,
                raw_output_path=ctx.outputs.relative_path(digest) if state == "succeeded" else None,
            )
        )
        session.commit()
        return run.id


def recorded(fixture: Path) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((RECORDED / f"{fixture.name}.ghidra.json").read_text())
    return value


def import_and_scan(client: TestClient, fixture: Path, profile: str) -> tuple[str, str]:
    imported = do_import(client, create_project(client), fixture.read_bytes())
    assert imported.status_code == 201, imported.text
    version = imported.json()["sample_version"]["id"]
    run = client.post(f"/api/v1/sample-versions/{version}/runs", json={"profile_id": profile})
    assert run.status_code == 202, run.text
    assert process(ctx_of(client)) == "succeeded"
    return version, run.json()["id"]


def summary(client: TestClient, version: str, **params: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/sample-versions/{version}/evidence", params=params)
    assert response.status_code == 200, response.text
    value: dict[str, Any] = response.json()
    return value


def all_edges(client: TestClient, version: str, edge_type: str) -> list[dict[str, Any]]:
    response = client.get(
        f"/api/v1/sample-versions/{version}/evidence/edges", params={"type": edge_type}
    )
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


def node(client: TestClient, version: str, node_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/sample-versions/{version}/evidence/nodes/{node_id}")
    assert response.status_code == 200, response.text
    value: dict[str, Any] = response.json()
    return value


def test_real_capa_match_joins_ghidra_function_by_exact_file_offset(tmp_path: Path) -> None:
    data = CAPA_READ_FILE.read_bytes()
    binary = lief.parse(data)
    assert isinstance(binary, lief.PE.Binary)
    with api_client(make_settings(tmp_path)) as client:
        version, analysis = import_and_scan(client, CAPA_READ_FILE, "full-static")
        ghidra = seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        result = summary(client, version)
        sources = {s["source"]: s for s in result["scope"]["sources"]}
        assert sources["ghidra"]["run_id"] == ghidra
        assert sources["pattern"]["run_id"] == analysis
        assert sources["ghidra"]["selected_by"] == "latest_completed"
        coverage = result["coverage"]
        assert coverage["ghidra_memory_map"] == "available"
        assert coverage["ghidra_protocol"] == "ghidra-4"
        joins = {j["join"]: j for j in coverage["joins"]}
        assert joins["capa_function"] == {
            "join": "capa_function",
            "performed": True,
            "reason": None,
            "candidates": 1,
            "joined": 1,
            "not_joined": {},
        }

        [capa] = all_edges(client, version, "capa_match_at_function_entry")
        assert capa["strength"] == "exact_offset_equality"
        assert capa["basis"] == ["lief_section_declaration", "ghidra_memory_block_file_bytes"]
        assert capa["attributes"]["virtual_address"] == 0x140001450
        # Independent LIEF translation of capa's VA (RVA = VA - ImageBase).
        expected = binary.rva_to_offset(0x140001450 - binary.optional_header.imagebase)
        assert capa["attributes"]["file_offset"] == expected
        target = node(client, version, capa["target"])
        assert target["node"]["kind"] == "function"
        assert target["node"]["address"] == {"space": "ram", "address": "140001450"}
        assert target["node"]["file_offset"] == expected
        finding = node(client, version, capa["source"])["node"]
        assert finding["attributes"]["rule_id"] == "read file via Windows API"
        assert {loc["tool"] for loc in capa["locators"]} == {"capa", "ghidra"}

        # The same function references ReadFile; the import association is
        # reported as name equality, never as an address join.
        refs = [e for e in target["edges"] if e["type"] == "references_external_symbol"]
        labels = {n["id"]: n["label"] for n in target["neighbors"]}
        assert "KERNEL32.DLL::ReadFile" in {labels[e["target"]] for e in refs}
        names = all_edges(client, version, "external_symbol_named_as_import")
        read_file = [
            e for e in names if node(client, version, e["target"])["node"]["label"] == "ReadFile"
        ]
        assert len(read_file) == 1 and read_file[0]["strength"] == "name_equality"

        # Declared entry point and Ghidra function agree through two sources.
        [entry] = all_edges(client, version, "entry_point_is_function")
        entry_fn = node(client, version, entry["target"])["node"]
        entry_rva = binary.optional_header.addressof_entrypoint
        assert entry_fn["file_offset"] == binary.rva_to_offset(entry_rva)
        assert int(entry_fn["address"]["address"], 16) == binary.imagebase + entry_rva

        # Section placement uses LIEF's declared file ranges.
        text = [
            e
            for e in target["edges"]
            if e["type"] == "located_in_section" and e["source"] == target["node"]["id"]
        ]
        assert len(text) == 1 and labels[text[0]["target"]] == ".text"

        # Understand claims cite the exact edges the Investigate view returns.
        [claim] = [c for c in result["claims"] if c["kind"] == "capa_rule_at_function"]
        assert claim["title"] == "Code refers to reading a file"
        assert claim["evidence"] == [capa["id"]]
        assert "140001450" in claim["summary"] and "does not show" in claim["summary"]
        assert claim["navigate"]["node_id"] == target["node"]["id"]
        assert client.get(claim["navigate"]["href"]).status_code == 200
        assert claim["id"] in target["claims"]
        layout = {s["name"]: s for s in result["layout"]["sections"]}
        assert layout[".text"]["contains"]["function"] >= 1
        blocks = {b["name"]: b for b in result["layout"]["ghidra_blocks"]}
        assert blocks[".text"]["permissions"] == "r-x" and not blocks[".bss"]["file_backed"]


def test_real_elf_string_reference_joins_strings_step_occurrence(tmp_path: Path) -> None:
    data = ELF_X86_64.read_bytes()
    literal = data.find(b"bytasm fixture v1")
    assert literal > 0
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, ELF_X86_64, "default-static")
        seed_ghidra(client, version, recorded(ELF_X86_64))
        result = summary(client, version)
        joins = {j["join"]: j for j in result["coverage"]["joins"]}
        assert joins["string_occurrence"]["performed"] and joins["string_occurrence"]["joined"] >= 1
        # capa is not part of this profile, and ELF capa addresses are never translated.
        assert joins["capa_function"]["candidates"] == 0
        assert "PE" in (joins["capa_function"]["reason"] or "")
        links = all_edges(client, version, "target_is_string_occurrence")
        literal_links = [e for e in links if e["attributes"]["file_offset"] == literal]
        assert literal_links, links
        string = node(client, version, literal_links[0]["target"])["node"]
        assert string["kind"] == "string" and "bytasm fixture v1" in string["label"]
        program_data = node(client, version, literal_links[0]["source"])
        # Ghidra loads this PIE at 0x100000; the address is never treated as an offset.
        assert int(program_data["node"]["address"]["address"], 16) != literal
        assert program_data["node"]["file_offset"] == literal
        claims = [c for c in result["claims"] if c["kind"] == "function_references_strings"]
        assert any(literal_links[0]["id"] in c["evidence"] for c in claims)
        # Untrusted text stays in subject labels, out of the generated sentence.
        assert all("bytasm fixture" not in c["summary"] for c in result["claims"])


def test_historical_ghidra3_output_is_not_translated(tmp_path: Path) -> None:
    document = recorded(CAPA_READ_FILE)
    document["schema_version"] = "ghidra-3"
    for key in ("image_base", "memory_blocks", "memory_blocks_truncated"):
        document.pop(key)
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        seed_ghidra(client, version, document)
        result = summary(client, version)
        coverage = result["coverage"]
        assert coverage["ghidra_memory_map"] == "unavailable"
        assert "ghidra-4" in coverage["ghidra_memory_map_reason"]
        joins = {j["join"]: j for j in coverage["joins"]}
        for name in ("capa_function", "yara_body", "string_occurrence", "entry_point"):
            assert joins[name]["performed"] is False and joins[name]["joined"] == 0
        # Exact tool-reported relations do not depend on translation.
        assert joins["calls"]["performed"] and joins["references"]["joined"] > 0
        assert "capa_match_at_function_entry" not in result["counts"]["edges"]
        functions = client.get(
            f"/api/v1/sample-versions/{version}/evidence/nodes",
            params={"kind": "function", "limit": 200},
        ).json()["items"]
        assert functions and all(f["file_offset"] is None for f in functions)
        assert {f["file_offset_state"] for f in functions} == {"unavailable"}


def test_metadata_only_scope_reports_absent_sources(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        imported = do_import(client, create_project(client), PE_X86_64_EXE.read_bytes())
        version = imported.json()["sample_version"]["id"]
        result = summary(client, version)
        sources = {s["source"]: s for s in result["scope"]["sources"]}
        assert sources["ghidra"]["selected_by"] == "none"
        assert sources["pattern"]["unavailable_reason"]
        assert result["coverage"]["ghidra_memory_map"] == "not_selected"
        assert result["coverage"]["findings"] is None
        assert result["claims"] == []
        assert result["counts"]["nodes"]["section"] >= 1
        joins = {j["join"]: j for j in result["coverage"]["joins"]}
        assert joins["capa_function"]["performed"] is False


def test_run_scoping_refuses_foreign_and_unfinished_runs(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, analysis = import_and_scan(client, CAPA_READ_FILE, "full-static")
        ghidra = seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        other = do_import(client, create_project(client, "Other"), ELF_X86_64.read_bytes())
        other_version = other.json()["sample_version"]["id"]
        base = f"/api/v1/sample-versions/{other_version}/evidence"
        # Runs of another version are refused, never substituted.
        assert client.get(base, params={"ghidra_run_id": ghidra}).status_code == 404
        assert client.get(base, params={"analysis_run_id": analysis}).status_code == 404
        own = f"/api/v1/sample-versions/{version}/evidence"
        # A run of the wrong profile cannot fill the other source.
        assert client.get(own, params={"ghidra_run_id": analysis}).status_code == 404
        assert client.get(own, params={"analysis_run_id": ghidra}).status_code == 404
        assert client.get(own, params={"ghidra_run_id": "x" * 32}).status_code == 422
        failed = seed_ghidra(client, version, recorded(CAPA_READ_FILE), state="failed")
        assert client.get(own, params={"ghidra_run_id": failed}).status_code == 404
        result = summary(client, version)
        sources = {s["source"]: s for s in result["scope"]["sources"]}
        # The newer failed run is disclosed, and the completed one stays selected.
        assert sources["ghidra"]["run_id"] == ghidra
        assert sources["ghidra"]["newer_unselected_run_ids"] == [failed]
        explicit = summary(client, version, ghidra_run_id=ghidra, analysis_run_id=analysis)
        assert explicit["scope"]["scope_sha256"] == result["scope"]["scope_sha256"]
        assert {s["selected_by"] for s in explicit["scope"]["sources"]} >= {"explicit"}
        assert client.get(own + "/nodes/function:unknown").status_code == 404
        assert client.get(own + "/nodes/" + "a" * 65).status_code == 404


def test_pagination_is_deterministic_and_cursor_bound(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        base = f"/api/v1/sample-versions/{version}/evidence/nodes"
        full = client.get(base, params={"limit": 200}).json()
        seen: list[str] = []
        cursor = None
        while True:
            params: dict[str, Any] = {"limit": 7}
            if cursor:
                params["cursor"] = cursor
            page = client.get(base, params=params).json()
            seen.extend(item["id"] for item in page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert seen == [n["id"] for n in full["items"]][: len(seen)]
        assert len(seen) == full["matched"] == len(set(seen))
        first = client.get(base, params={"limit": 7}).json()
        assert client.get(base, params={"limit": 7}).json() == first
        # A cursor is bound to its filter and page size.
        mismatched = client.get(
            base, params={"limit": 7, "kind": "function", "cursor": first["next_cursor"]}
        )
        assert mismatched.status_code == 422
        bad = client.get(base, params={"limit": 8, "cursor": first["next_cursor"]})
        assert bad.status_code == 422
        both = client.get(base, params={"limit": 7, "offset": 7, "cursor": first["next_cursor"]})
        assert both.status_code == 422
        assert client.get(base, params={"cursor": "!!"}).status_code == 422
        edges = client.get(
            f"/api/v1/sample-versions/{version}/evidence/edges", params={"limit": 200}
        ).json()
        assert edges["items"] == sorted(edges["items"], key=lambda e: e["type"]), (
            "edges are grouped by type"
        )
        # Every edge endpoint exists and repeated references form one edge.
        ids = {n["id"] for n in full["items"]}
        assert all(e["source"] in ids and e["target"] in ids for e in edges["items"])
        keys = [(e["type"], e["source"], e["target"]) for e in edges["items"]]
        assert len(keys) == len(set(keys))


def test_identifiers_are_stable_across_databases(tmp_path: Path) -> None:
    def capture(root: Path) -> tuple[list[str], list[str], list[str]]:
        with api_client(make_settings(root)) as client:
            version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
            seed_ghidra(client, version, recorded(CAPA_READ_FILE))
            nodes = client.get(
                f"/api/v1/sample-versions/{version}/evidence/nodes",
                params={"kind": "function", "limit": 200},
            ).json()["items"]
            edges = all_edges(client, version, "calls")
            claims = summary(client, version)["claims"]
            return [n["id"] for n in nodes], [e["id"] for e in edges], [c["id"] for c in claims]

    # Function, call-edge and claim identities depend on exact tool identity,
    # not on database row IDs, so two independent imports agree.
    assert capture(tmp_path / "a") == capture(tmp_path / "b")


def test_tampered_ghidra_output_is_an_integrity_error(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        ghidra = seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        ctx = ctx_of(client)
        with ctx.sessions() as session:
            run = session.get(AnalysisRun, ghidra)
            assert run is not None
            path = ctx.outputs.path(run.invocations[0].raw_output_sha256 or "")
        path.chmod(0o644)
        path.write_bytes(path.read_bytes().replace(b"FUN_", b"FUX_", 1))
        response = client.get(f"/api/v1/sample-versions/{version}/evidence")
        assert response.status_code == 409, response.text
