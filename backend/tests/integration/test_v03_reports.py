"""Schema 3 snapshots analyst statements and optional same-sample comparisons."""

from pathlib import Path
from typing import Any

import pytest
from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64, PE_X86_64_EXE
from jsonschema import Draft202012Validator
from test_analysis import process, start_run

from bytasm.reports.model import json_schema


def test_report_includes_annotations_and_comparison_deterministically(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        a = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        b = do_import(client, project, PE_X86_64_EXE.read_bytes(), sample_id=a["sample_id"]).json()[
            "sample_version"
        ]
        annotation = client.post(
            "/api/v1/annotations",
            json={
                "target_type": "sample_version",
                "target_id": b["id"],
                "kind": "note",
                "body": "My own observation",
                "confidence": None,
                "cites": [],
            },
        )
        assert annotation.status_code == 201
        reports = []
        for _ in range(2):
            created = client.post(
                f"/api/v1/sample-versions/{b['id']}/reports", params={"compare_with": a["id"]}
            )
            assert created.status_code == 201, created.text
            report = client.get(created.json()["download_url"]).json()
            Draft202012Validator(json_schema()).validate(report)
            assert report["schema_version"] == 4
            assert report["scope"]["kind"] == "comparison"
            assert report["comparison"]["a"]["version_id"] == a["id"]
            assert report["comparison"]["b"]["version_id"] == b["id"]
            assert report["annotations"][0]["body"] == "My own observation"
            assert report["annotations"][0]["author"]["id"] == "local"
            assert report["pattern_analysis"] is None
            assert not any("counts only in this report" in text for text in report["limitations"])
            assert any("changed string values" in text for text in report["limitations"])
            report.pop("generated_at")
            reports.append(report)
        assert reports[0] == reports[1]
        other = do_import(client, project, ELF_X86_64.read_bytes(), sample_name="other").json()[
            "sample_version"
        ]
        assert (
            client.post(
                f"/api/v1/sample-versions/{b['id']}/reports", params={"compare_with": other["id"]}
            ).status_code
            == 422
        )
        ctx = ctx_of(client)
        ctx.blobs.path(a["sha256"]).chmod(0o600)
        ctx.blobs.path(a["sha256"]).write_bytes(b"tampered")
        assert (
            client.post(
                f"/api/v1/sample-versions/{b['id']}/reports", params={"compare_with": a["id"]}
            ).status_code
            == 409
        )


def test_report_reverifies_cited_run_outputs(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        run = start_run(client, version["id"])
        assert process(ctx_of(client)) == "succeeded"
        finding = client.get(f"/api/v1/runs/{run['id']}/findings").json()["findings"][0]
        response = client.post(
            "/api/v1/annotations",
            json={
                "target_type": "sample_version",
                "target_id": version["id"],
                "kind": "conclusion",
                "body": "I can cite this observation.",
                "confidence": "tentative",
                "cites": [{"target_type": "finding", "target_id": finding["id"]}],
            },
        )
        assert response.status_code == 201
        report = client.post(f"/api/v1/sample-versions/{version['id']}/reports")
        assert report.status_code == 201
        result = client.get(report.json()["download_url"]).json()
        assert result["annotations"][0]["cites"][0]["target_id"] == finding["id"]
        invocation = client.get(f"/api/v1/runs/{run['id']}").json()["steps"][1]
        raw = ctx_of(client).outputs.path(invocation["raw_output_sha256"])
        raw.chmod(0o600)
        raw.write_bytes(b"tampered")
        assert client.post(f"/api/v1/sample-versions/{version['id']}/reports").status_code == 409


def test_export_snapshot_excludes_concurrent_annotation_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sqlite3

    import bytasm.reports.generate as generate

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        original = generate.build_report
        attempted = []

        def during_export(*args: Any, **kwargs: Any) -> dict[str, Any]:
            # A second writer must not change the verified snapshot before rendering.
            with sqlite3.connect(ctx_of(client).settings.database_path, timeout=0.01) as other:
                try:
                    other.execute(
                        "INSERT INTO project (id,name,description,created_at,updated_at) "
                        "VALUES ('concurrent','test','','2026-10-29T00:00:00Z',"
                        "'2026-10-29T00:00:00Z')"
                    )
                    other.commit()
                    attempted.append("committed")
                except sqlite3.OperationalError as error:
                    assert "locked" in str(error)
                    attempted.append("waited")
            return original(*args, **kwargs)

        monkeypatch.setattr(generate, "build_report", during_export)
        response = client.post(f"/api/v1/sample-versions/{version['id']}/reports")
        assert response.status_code == 201
        assert attempted == ["waited"]
        with sqlite3.connect(ctx_of(client).settings.database_path, timeout=0.1) as other:
            other.execute(
                "UPDATE project SET description = 'after export' WHERE id = ?", (project,)
            )
            other.commit()
