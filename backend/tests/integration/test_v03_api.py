"""v0.3 endpoints retain the local request boundary and validate IDs and links."""

import json
from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64


def test_v03_guards_identifiers_and_annotation_activity(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project_id = create_project(client)
        version = do_import(client, project_id, ELF_X86_64.read_bytes()).json()["sample_version"]
        url = f"/api/v1/compare?a={version['id']}&b={version['id']}"
        assert client.get(url).status_code == 200
        assert client.get(url, headers={"Host": "evil.invalid"}).status_code == 400
        assert client.get(url, headers={"Origin": "https://evil.invalid"}).status_code == 403
        for query in (
            "a=bad&b=bad",
            f"a={version['id']}&b={version['id']}&limit=201",
            f"a={version['id']}&b={version['id']}&offset=1000001",
        ):
            assert client.get(f"/api/v1/compare?{query}").status_code == 422
        draft = {
            "target_type": "sample_version",
            "target_id": version["id"],
            "kind": "note",
            "body": "My private observation",
            "cites": [],
        }
        assert (
            client.post(
                "/api/v1/annotations", json=draft, headers={"X-Bytasm-Request": ""}
            ).status_code
            == 403
        )
        created = client.post("/api/v1/annotations", json=draft)
        assert created.status_code == 201
        item = created.json()
        activity = client.get(f"/api/v1/projects/{project_id}/activity").json()
        event = next(e for e in activity["items"] if e["type"] == "annotation.created")
        assert event["annotation_id"] == item["id"]
        assert event["revision_id"] == item["revision_id"]
        assert event["sample_version_id"] == version["id"]
        assert "private observation" not in str(activity)
        from sqlalchemy import text

        with ctx_of(client).engine.begin() as connection:
            # The projection must not link a forged revision from another version.
            connection.execute(
                text("UPDATE activity_event SET payload = :payload WHERE id = :id"),
                {
                    "payload": json.dumps(
                        {
                            "annotation_id": "missing",
                            "revision_id": "missing",
                            "sample_version_id": version["id"],
                            "revision": 1,
                        }
                    ),
                    "id": event["id"],
                },
            )
        changed = client.get(f"/api/v1/projects/{project_id}/activity").json()["items"]
        assert next(e for e in changed if e["id"] == event["id"])["annotation_id"] is None


def test_annotation_activity_resolves_the_exact_finding_or_evidence_target(tmp_path: Path) -> None:
    from test_analysis import process, start_run

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        run = start_run(client, version["id"])
        assert process(ctx_of(client)) == "succeeded"
        finding = client.get(f"/api/v1/runs/{run['id']}/findings").json()["findings"][0]
        for kind, identity in (
            ("finding", finding["id"]),
            ("evidence", str(finding["evidence"][0]["id"])),
        ):
            annotation = client.post(
                "/api/v1/annotations",
                json={
                    "target_type": kind,
                    "target_id": identity,
                    "kind": "note",
                    "body": "private text",
                },
            )
            assert annotation.status_code == 201
            entries = client.get(f"/api/v1/projects/{project}/activity").json()["items"]
            entry = next(
                item for item in entries if item["annotation_id"] == annotation.json()["id"]
            )
            assert entry["annotation_target_type"] == kind
            assert entry["annotation_target_id"] == identity
            assert entry["run_id"] == run["id"]
            assert "private text" not in str(entry)
