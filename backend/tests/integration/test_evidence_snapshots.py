"""Pinned evidence snapshots and evidence comparison (v0.11) over real tool outputs.

LIEF, strings, YARA-X and capa run for real. The Ghidra side is a recorded real
document (tests/recorded/README.md) persisted exactly as the worker would.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64, ELF_X86_64_V2
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_analysis import process
from test_evidence_graph import CAPA_READ_FILE, import_and_scan, recorded, seed_ghidra

from bytasm.db.models import ReviewSnapshot, ToolInvocation
from bytasm.reports.generate import canonical_json


def pin(client: TestClient, version: str, **body: Any) -> dict[str, Any]:
    response = client.post(f"/api/v1/sample-versions/{version}/reviews", json=body)
    assert response.status_code == 201, response.text
    value: dict[str, Any] = response.json()
    return value


def compare(client: TestClient, a: str, b: str, **params: Any) -> dict[str, Any]:
    response = client.get("/api/v1/evidence/compare", params={"a": a, "b": b, **params})
    assert response.status_code == 200, response.text
    value: dict[str, Any] = response.json()
    return value


def all_changes(client: TestClient, a: str, b: str, **params: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = None
    while True:
        extra = {"limit": 200, **params, **({"cursor": cursor} if cursor else {})}
        page = compare(client, a, b, **extra)["changes"]
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            return items


def stored(client: TestClient, review_id: str) -> tuple[str, str]:
    with ctx_of(client).sessions() as session:
        row = session.get(ReviewSnapshot, review_id)
        assert row is not None
        return row.canonical, row.sha256


def test_review_pins_a_verified_evidence_snapshot_from_its_sources(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, analysis = import_and_scan(client, CAPA_READ_FILE, "full-static")
        ghidra = seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        review = pin(client, version)
        assert review["schema_version"] == "bytasm-review-3"
        assert review["evidence_status"] == {"state": "captured", "reason": None}
        snapshot = review["evidence"]
        assert snapshot["schema_version"] == "bytasm-evidence-snapshot-1"
        assert snapshot["algorithm"].startswith("bytasm-evidence-graph-")
        sources = {s["source"]: s for s in snapshot["sources"]}
        assert sources["ghidra"]["run_id"] == ghidra
        assert sources["ghidra"]["protocol_version"] == "ghidra-4"
        assert sources["ghidra"]["retention"]["function_count"] >= 1
        assert sources["capa"]["run_id"] == analysis
        assert sources["capa"]["rule_set_sha256"]
        assert sources["lief"]["state"] == "available"
        assert snapshot["address_mapping"]["ghidra_memory_map"] == "available"
        assert snapshot["address_mapping"]["declared_image_base"] == 0x140000000
        [capa] = [e for e in snapshot["edges"] if e["type"] == "capa_match_at_function_entry"]
        assert capa["strength"] == "exact_offset_equality"
        assert capa["locators"][0]["tool"] == "capa"
        assert not snapshot["bounds"]["truncated"]

        summary = client.get(f"/api/v1/reviews/{review['id']}/evidence").json()
        assert summary["evidence"]["state"] == "captured"
        assert summary["content_verified"] is True
        assert summary["content_sha256"] == snapshot["content_sha256"]
        assert summary["counts"]["edges"]["capa_match_at_function_entry"] == 1

        # Pinned graph equals the live graph built from the same runs.
        live = client.get(
            f"/api/v1/sample-versions/{version}/evidence/edges",
            params={"type": "capa_match_at_function_entry"},
        ).json()["items"]
        assert [e["id"] for e in live] == [capa["id"]]

        # Pagination of pinned nodes is cursor-bound and complete.
        seen: list[str] = []
        cursor = None
        while True:
            params: dict[str, Any] = {"limit": 7}
            if cursor:
                params["cursor"] = cursor
            page = client.get(f"/api/v1/reviews/{review['id']}/evidence/nodes", params=params)
            assert page.status_code == 200, page.text
            seen.extend(n["id"] for n in page.json()["items"])
            cursor = page.json()["next_cursor"]
            if cursor is None:
                break
        assert seen == [n["id"] for n in snapshot["nodes"]]
        bad = client.get(
            f"/api/v1/reviews/{review['id']}/evidence/edges", params={"cursor": cursor or "x"}
        )
        assert bad.status_code == 422

        fn = capa["target"]
        detail = client.get(f"/api/v1/reviews/{review['id']}/evidence/nodes/{fn}").json()
        assert detail["node"]["kind"] == "function"
        assert any(e["id"] == capa["id"] for e in detail["edges"])
        assert client.get(f"/api/v1/reviews/{review['id']}/evidence/nodes/nope").status_code == 404
        assert client.get(f"/api/v1/reviews/{'0' * 32}/evidence").status_code == 404
        assert client.get("/api/v1/reviews/not-hex/evidence").status_code == 404


def test_pinned_snapshot_is_immutable_after_new_runs_and_tool_changes(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        review = pin(client, version)
        before = stored(client, review["id"])
        # A new run with a different Ghidra output, and a changed tool identity.
        changed = recorded(CAPA_READ_FILE)
        changed["functions"] = changed["functions"][:3]
        changed["function_count"] = 3
        changed["functions_truncated"] = False
        seed_ghidra(client, version, changed)
        rerun = client.post(
            f"/api/v1/sample-versions/{version}/runs", json={"profile_id": "full-static"}
        )
        assert rerun.status_code == 202
        assert process(ctx_of(client)) == "succeeded"
        with ctx_of(client).sessions() as session, session.begin():
            for inv in session.scalars(
                select(ToolInvocation).where(ToolInvocation.tool_name == "capa")
            ):
                inv.tool_version = "99.0.0"
        assert stored(client, review["id"]) == before
        assert client.get(f"/api/v1/reviews/{review['id']}").json() == review
        assert client.get(f"/api/v1/reviews/{review['id']}/evidence").json()["content_verified"]
        # Creating a review re-verifies sources: the mutated identity is refused.
        refused = client.post(f"/api/v1/sample-versions/{version}/reviews", json={})
        assert refused.status_code == 409
        with ctx_of(client).sessions() as session, session.begin():
            for inv in session.scalars(
                select(ToolInvocation).where(ToolInvocation.tool_name == "capa")
            ):
                inv.tool_version = "10.0.0"
        # A new pin reflects the new Ghidra output; the old one does not.
        newer = pin(client, version)
        assert newer["evidence"]["content_sha256"] != review["evidence"]["content_sha256"]
        assert stored(client, review["id"]) == before
        result = compare(client, f"review:{review['id']}", f"review:{newer['id']}")
        summary = result["comparison"]
        assert summary["binary"]["identical"] is True
        envs = {e["source"]: e for e in summary["environment"]}
        assert envs["ghidra"]["comparability"] == "comparable"
        changes = all_changes(client, f"review:{review['id']}", f"review:{newer['id']}")
        assert not any(
            c["attribution"] == "binary_difference_under_comparable_coverage" for c in changes
        )
        # Same bytes and Ghidra identity, different stored output: never the file.
        removed = [c for c in changes if c["kind"] == "function" and c["change"] == "removed"]
        assert removed
        assert {c["attribution"] for c in removed} == {"source_output_difference"}


def test_historical_reviews_stay_readable_and_report_missing_evidence(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]["id"]
        review = pin(client, version)
        historical = {k: v for k, v in review.items() if k not in {"evidence", "evidence_status"}}
        historical["schema_version"] = "bytasm-review-2"
        raw = canonical_json(historical)
        with ctx_of(client).sessions() as session, session.begin():
            row = session.get(ReviewSnapshot, review["id"])
            assert row is not None
            row.canonical = raw.decode()
            row.sha256 = hashlib.sha256(raw).hexdigest()
        read = client.get(f"/api/v1/reviews/{review['id']}")
        assert read.status_code == 200
        assert read.json()["evidence"] is None
        summary = client.get(f"/api/v1/reviews/{review['id']}/evidence").json()
        assert summary["evidence"]["state"] == "not_captured_historical"
        assert "bytasm-review-2" in summary["evidence"]["reason"]
        assert summary["sources"] == [] and summary["content_sha256"] is None
        nodes = client.get(f"/api/v1/reviews/{review['id']}/evidence/nodes")
        assert nodes.status_code == 409
        assert nodes.json()["code"] == "evidence_not_captured"
        assert nodes.json()["evidence"]["state"] == "not_captured_historical"
        refused = client.get(
            "/api/v1/evidence/compare",
            params={"a": f"review:{review['id']}", "b": f"version:{version}"},
        )
        assert refused.status_code == 409
        exported = client.post(f"/api/v1/reviews/{review['id']}/export/json", json={}).json()
        assert exported["schema_version"] == "bytasm-review-export-2"
        assert "evidence" not in exported
        # The stored bytes were not rewritten by any read.
        assert stored(client, review["id"])[0].encode() == raw


def test_missing_sources_are_reported_not_fabricated(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]["id"]
        snapshot = pin(client, version)["evidence"]
        sources = {s["source"]: s for s in snapshot["sources"]}
        assert sources["lief"]["state"] == "available"
        for tool in ("ghidra", "strings", "yara-x", "capa"):
            assert sources[tool]["state"] == "unavailable"
            assert sources[tool]["unavailable_reason"]
            assert sources[tool]["run_id"] is None
        joins = {j["join"]: j for j in snapshot["coverage"]}
        assert joins["calls"]["performed"] is False
        assert joins["calls"]["reason"] == "No completed Ghidra run was selected."
        assert snapshot["address_mapping"]["ghidra_memory_map"] == "not_selected"
        assert {n["kind"] for n in snapshot["nodes"]} <= {"section", "entry_point"}


def test_identical_inputs_give_identical_snapshot_content_across_databases(
    tmp_path: Path,
) -> None:
    digests = []
    node_ids = []
    for name in ("one", "two"):
        with api_client(make_settings(tmp_path / name)) as client:
            version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
            seed_ghidra(client, version, recorded(CAPA_READ_FILE))
            snapshot = pin(client, version)["evidence"]
            digests.append(snapshot["content_sha256"])
            node_ids.append([n["id"] for n in snapshot["nodes"]])
            run_ids = {s["run_id"] for s in snapshot["sources"] if s["run_id"]}
            assert run_ids  # database identifiers are present, but not in the digest
    assert node_ids[0] == node_ids[1]
    assert digests[0] == digests[1]


def test_same_version_comparison_is_identical_and_deterministic(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        review = pin(client, version)
        first = compare(client, f"review:{review['id']}", f"version:{version}", limit=200)
        second = compare(client, f"review:{review['id']}", f"version:{version}", limit=200)
        assert first["comparison"] == second["comparison"]
        assert first["changes"]["items"] == second["changes"]["items"]
        summary = first["comparison"]
        assert summary["binary"]["identical"] is True
        assert summary["mapping"]["addresses_comparable"] is True
        assert set(summary["counts"]["nodes"]) == {"unchanged"}
        assert set(summary["counts"]["edges"]) == {"unchanged"}
        assert summary["counts"]["exact_joins_established"] == 0
        assert summary["review_candidates"] == []
        assert summary["a"]["kind"] == "pinned_review"
        assert summary["b"]["kind"] == "version_current"


def test_versions_compare_with_coverage_and_correspondence(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        first = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        second = do_import(
            client, project, ELF_X86_64_V2.read_bytes(), sample_id=first["sample_id"]
        ).json()["sample_version"]
        v1, v2 = first["id"], second["id"]
        # Only v2 has a pattern run: its rule matches are not comparable, never "added".
        run = client.post(
            f"/api/v1/sample-versions/{v2}/runs", json={"profile_id": "default-static"}
        )
        assert run.status_code == 202
        assert process(ctx_of(client)) == "succeeded"
        partial = compare(client, f"version:{v1}", f"version:{v2}")["comparison"]
        envs = {e["source"]: e for e in partial["environment"]}
        assert envs["yara-x"]["comparability"] == "coverage_differs"
        findings = all_changes(client, f"version:{v1}", f"version:{v2}", kind="finding")
        assert findings and all(c["change"] == "not_comparable" for c in findings)
        assert all(c["attribution"] == "coverage_difference" for c in findings)
        assert not any(c["change"] in ("added", "removed") for c in findings)

        run = client.post(
            f"/api/v1/sample-versions/{v1}/runs", json={"profile_id": "default-static"}
        )
        assert run.status_code == 202
        assert process(ctx_of(client)) == "succeeded"
        result = compare(client, f"version:{v1}", f"version:{v2}")["comparison"]
        assert result["binary"]["identical"] is False
        envs = {e["source"]: e for e in result["environment"]}
        assert envs["yara-x"]["comparability"] == "comparable"
        assert envs["ghidra"]["comparability"] == "unavailable_on_both"
        assert result["mapping"]["addresses_comparable"] is False
        findings = all_changes(client, f"version:{v1}", f"version:{v2}", kind="finding")
        assert findings and {c["change"] for c in findings} == {"unchanged"}
        assert {c["match_method"] for c in findings} == {"rule_identity"}
        # Shifted sections correspond by declared name and report exact field changes.
        sections = all_changes(client, f"version:{v1}", f"version:{v2}", kind="section")
        assert {c["match_method"] for c in sections} == {"declared_section_name"}
        text = next(c for c in sections if c["before"]["label"] == ".text")
        assert text["change"] == "modified"
        assert "attributes.file_size" in text["changed_fields"]
        assert text["attribution"] == "binary_difference_under_comparable_coverage"
        statements = [s["text"] for s in result["statements"]]
        assert any("declared section observations differ" in t for t in statements)
        assert any("entry-point declaration observation differs" in t for t in statements)
        assert not any("malicious" in t.lower() or " safe" in t.lower() for t in statements)
        # Ghidra-dependent joins were evaluated on neither side.
        joins = {j["join"]: j for j in result["coverage"]}
        assert joins["calls"]["comparable"] is False


def test_comparison_scoping_and_invalid_references(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        a = do_import(client, create_project(client, "A"), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]["id"]
        b = do_import(client, create_project(client, "B"), ELF_X86_64_V2.read_bytes()).json()[
            "sample_version"
        ]["id"]
        cross = client.get(
            "/api/v1/evidence/compare", params={"a": f"version:{a}", "b": f"version:{b}"}
        )
        assert cross.status_code == 422  # evidence never crosses projects
        for bad in ("version:xyz", f"run:{a}", f"version:{a}x", ""):
            response = client.get(
                "/api/v1/evidence/compare", params={"a": bad, "b": f"version:{a}"}
            )
            assert response.status_code == 422, bad
        missing = client.get(
            "/api/v1/evidence/compare", params={"a": f"version:{'0' * 32}", "b": f"version:{a}"}
        )
        assert missing.status_code == 404
        review = pin(client, a)
        pinned_with_run = client.get(
            "/api/v1/evidence/compare",
            params={
                "a": f"review:{review['id']}",
                "b": f"version:{a}",
                "a_ghidra_run_id": "0" * 32,
            },
        )
        assert pinned_with_run.status_code == 422
        too_big = client.get(
            "/api/v1/evidence/compare",
            params={"a": f"version:{a}", "b": f"version:{a}", "limit": 201},
        )
        assert too_big.status_code == 422


def test_review_export_carries_evidence_provenance_with_privacy(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version, _ = import_and_scan(client, CAPA_READ_FILE, "full-static")
        seed_ghidra(client, version, recorded(CAPA_READ_FILE))
        review = pin(client, version)
        url = f"/api/v1/reviews/{review['id']}/export/json"
        minimized = client.post(url, json={}).json()
        assert minimized["schema_version"] == "bytasm-review-export-3"
        evidence = minimized["evidence"]
        assert evidence["state"] == "captured"
        assert evidence["content_sha256"] == review["evidence"]["content_sha256"]
        assert "nodes" not in evidence and "edges" not in evidence
        assert any("Evidence graph nodes" in item for item in minimized["excluded_content"])
        full = client.post(
            url, json={"technical_details": True, "original_names": True, "string_values": True}
        ).json()
        assert len(full["evidence"]["nodes"]) == len(review["evidence"]["nodes"])
        html = client.post(f"/api/v1/reviews/{review['id']}/export/html", json={}).text
        assert "Pinned evidence graph" in html
        assert json.loads(json.dumps(minimized)) == minimized
