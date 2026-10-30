"""Human text remains separate, append-only and scoped to retained observations."""

from pathlib import Path
from typing import Any

import pytest
from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64
from fastapi.testclient import TestClient
from sqlalchemy import select

from bytasm.annotations import current_annotations
from bytasm.db.models import (
    ActivityEvent,
    AnalysisRun,
    Annotation,
    Evidence,
    Finding,
    RuleSet,
    ToolInvocation,
)


def _version(client: TestClient, name: str = "sample") -> str:
    response = do_import(client, create_project(client), ELF_X86_64.read_bytes(), sample_name=name)
    assert response.status_code == 201
    version_id: str = response.json()["sample_version"]["id"]
    return version_id


def _finding(client: TestClient, version: str) -> tuple[str, str]:
    with ctx_of(client).sessions() as session, session.begin():
        run = session.scalar(select(AnalysisRun).where(AnalysisRun.sample_version_id == version))
        assert run is not None
        invocation = session.scalar(select(ToolInvocation).where(ToolInvocation.run_id == run.id))
        assert invocation is not None
        # Retained successful steps remain citable even when the run was cancelled.
        run.status = "cancelled"
        rule = RuleSet(
            tool="yara-x",
            name="test",
            version="1",
            sha256=version * 2,
            source="bytasm-repo",
            snapshot_path="test",
            rule_count=1,
        )
        session.add(rule)
        session.flush()
        finding = Finding(
            run_id=run.id,
            invocation_id=invocation.id,
            kind="yara_match",
            title="Observation",
            rule_id="test",
            rule_namespace="test",
            rule_set_id=rule.id,
            tool_reported_attributes={},
            fingerprint="a" * 64,
            match_count=1,
            evidence_truncated=False,
        )
        session.add(finding)
        session.flush()
        evidence = Evidence(
            finding_id=finding.id,
            kind="byte_range",
            pattern_id="$test",
            file_offset=0,
            length=1,
            excerpt_hex="7f",
            raw_json_pointer="/test",
        )
        session.add(evidence)
        session.flush()
        return finding.id, str(evidence.id)


def _note(version: str, **changes: Any) -> dict[str, Any]:
    return {
        "target_type": "sample_version",
        "target_id": version,
        "kind": "note",
        "body": "  Private analyst note  ",
        "cites": [],
        **changes,
    }


def test_revisions_pagination_and_minimal_audit(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = _version(client)
        first = client.post("/api/v1/annotations", json=_note(version))
        assert first.status_code == 201, first.text
        item = first.json()
        assert item["body"] == "Private analyst note"
        assert item["author"] == {"id": "local", "display_name": "Local analyst"}
        url = f"/api/v1/annotations/{item['id']}/revisions"
        revised = client.post(
            url,
            json={"expected_revision": 1, "kind": "interpretation", "body": "Updated", "cites": []},
        )
        assert revised.status_code == 201, revised.text
        assert revised.json()["revision"] == 2
        assert revised.json()["id"] == item["id"]
        assert revised.json()["revision_id"] != item["revision_id"]
        stale = client.post(url, json={"expected_revision": 1, "kind": "note", "body": "stale"})
        assert stale.status_code == 409
        assert stale.json()["code"] == "annotation_stale"
        page = client.get(url, params={"limit": 1}).json()
        assert [r["body"] for r in page["items"]] == [item["body"]]
        assert page["next_offset"] == 1
        assert client.get(url, params={"offset": 1}).json()["items"][0]["body"] == "Updated"
        current = client.get(
            "/api/v1/annotations", params={"target_type": "sample_version", "target_id": version}
        ).json()
        assert [r["revision"] for r in current["items"]] == [2]
        assert client.get(url, params={"limit": 101}).status_code == 422
        with ctx_of(client).sessions() as session:
            assert [a.revision for a in current_annotations(session, version)] == [2]
            events = session.scalars(
                select(ActivityEvent).where(ActivityEvent.type.like("annotation.%"))
            ).all()
            assert [e.type for e in events] == ["annotation.created", "annotation.revised"]
            assert all(
                set(e.payload) == {"annotation_id", "revision_id", "sample_version_id", "revision"}
                for e in events
            )


def test_conclusion_citations_scope_and_targets(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = _version(client)
        other = _version(client, "other")
        finding, evidence = _finding(client, version)
        _, foreign_evidence = _finding(client, other)
        body = _note(version, kind="conclusion", confidence="likely")
        assert client.post("/api/v1/annotations", json=body).status_code == 422
        body["cites"] = [{"target_type": "evidence", "target_id": evidence}]
        saved = client.post("/api/v1/annotations", json=body)
        assert saved.status_code == 201, saved.text
        assert saved.json()["cites"][0]["version_id"] == version
        targets = client.get(f"/api/v1/sample-versions/{version}/citation-targets").json()
        assert {(t["target_type"], t["target_id"]) for t in targets["items"]} == {
            ("finding", finding),
            ("evidence", evidence),
        }
        for target_type, target_id in (("finding", finding), ("evidence", evidence)):
            assert (
                client.post(
                    "/api/v1/annotations",
                    json=_note(version, target_type=target_type, target_id=target_id),
                ).status_code
                == 201
            )
        body["cites"] = [{"target_type": "evidence", "target_id": foreign_evidence}]
        assert client.post("/api/v1/annotations", json=body).status_code == 422
        body["cites"] *= 2
        assert client.post("/api/v1/annotations", json=body).status_code == 422
        with ctx_of(client).sessions() as session:
            assert len(current_annotations(session, version)) == 3


@pytest.mark.parametrize(
    "changes",
    [
        {"body": " "},
        {"body": "x" * 4001},
        {"kind": "verdict"},
        {"confidence": "likely"},
        {"cites": [{"target_type": "finding", "target_id": "missing"}]},
        {"cites": [{"target_type": "finding", "target_id": "x"}] * 21},
    ],
)
def test_invalid_inputs(tmp_path: Path, changes: dict[str, Any]) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = _version(client)
        assert client.post("/api/v1/annotations", json=_note(version, **changes)).status_code in (
            422,
            404,
        )


def test_event_failure_rolls_back_revision(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path), raise_server_exceptions=False) as client:
        version = _version(client)
        with ctx_of(client).engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TRIGGER reject_annotation_event BEFORE INSERT ON activity_event "
                "WHEN NEW.type LIKE 'annotation.%' "
                "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
            )
        assert client.post("/api/v1/annotations", json=_note(version)).status_code == 500
        with ctx_of(client).sessions() as session:
            assert session.scalars(select(Annotation)).all() == []


def test_simultaneous_edits_have_one_winner(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    with api_client(make_settings(tmp_path)) as client:
        version = _version(client)
        root = client.post("/api/v1/annotations", json=_note(version)).json()["id"]

        def edit(index: int) -> int:
            response = client.post(
                f"/api/v1/annotations/{root}/revisions",
                json={"expected_revision": 1, "kind": "note", "body": f"Edit {index}"},
            )
            status: int = response.status_code
            return status

        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(edit, range(4)))
        assert sorted(statuses) == [201, 409, 409, 409]
        history = client.get(f"/api/v1/annotations/{root}/revisions").json()["items"]
        assert [row["revision"] for row in history] == [1, 2]


def test_export_rejects_corrupt_cross_scope_citation(tmp_path: Path) -> None:
    from bytasm.annotations import AnnotationError
    from bytasm.db.models import AnnotationCitation

    with api_client(make_settings(tmp_path)) as client:
        version = _version(client)
        other = _version(client, "other")
        foreign_finding, _ = _finding(client, other)
        row = client.post("/api/v1/annotations", json=_note(version)).json()
        with ctx_of(client).sessions() as session, session.begin():
            session.add(
                AnnotationCitation(
                    annotation_id=row["revision_id"],
                    position=0,
                    target_type="finding",
                    target_id=foreign_finding,
                    finding_id=foreign_finding,
                )
            )
        with ctx_of(client).sessions() as session, pytest.raises(AnnotationError) as caught:
            current_annotations(session, version)
        assert caught.value.code == "integrity_error"


def test_create_request_id_replays_original_without_duplicate_event(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = _version(client)
        body = _note(version, request_id="a" * 32)
        first = client.post("/api/v1/annotations", json=body)
        assert first.status_code == 201
        assert first.json()["id"] == "a" * 32
        root = first.json()["id"]
        assert (
            client.post(
                f"/api/v1/annotations/{root}/revisions",
                json={"expected_revision": 1, "kind": "note", "body": "Later revision"},
            ).status_code
            == 201
        )
        replay = client.post("/api/v1/annotations", json=body)
        assert replay.status_code == 201
        assert replay.json() == first.json()
        conflict = client.post("/api/v1/annotations", json={**body, "body": "Different"})
        assert conflict.status_code == 409
        assert conflict.json()["code"] == "annotation_stale"
        with ctx_of(client).sessions() as session:
            events = session.scalars(
                select(ActivityEvent).where(ActivityEvent.type == "annotation.created")
            ).all()
            assert len(events) == 1
            assert len(session.scalars(select(Annotation)).all()) == 2
