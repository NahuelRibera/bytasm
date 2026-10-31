"""Immutable comparison, explicit source windows and historical readers."""

import hashlib
import json
from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64
from sqlalchemy import select

from bytasm.db.models import ReviewSnapshot
from bytasm.reports.generate import canonical_json


def test_comparison_is_pinned_and_explains_new_result(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        root = f"/api/v1/sample-versions/{version['id']}/reviews"
        left = client.post(root, json={}).json()
        right = client.post(f"/api/v1/reviews/{left['id']}/refresh", json={}).json()
        response = client.get(f"/api/v1/reviews/{left['id']}/compare/{right['id']}")
        assert response.status_code == 200, response.text
        compared = response.json()
        assert compared["compatible"]
        assert all(s["change"] == "unchanged" for s in compared["source_changes"])
        assert compared["observation_changes"]["added"] == []
        assert any("not executed" in c for c in compared["cautions"])
        assert client.get(f"/api/v1/reviews/{left['id']}").json() == left
        from bytasm.review_comparison import compare_reviews
        from bytasm.review_snapshot import Snapshot

        original = Snapshot.model_validate(left)
        altered = original.model_copy(update={"import_inventory": ["authored_new_import"]})
        delta = compare_reviews(original, altered)
        assert delta["import_changes"]["added"] == ["authored_new_import"]
        incompatible = altered.model_copy(
            update={
                "sample": original.sample.model_copy(
                    update={"sample_id": "other", "sha256": "f" * 64}
                )
            }
        )
        refused = compare_reviews(original, incompatible)
        assert not refused["compatible"]
        assert refused["import_changes"] == {"added": [], "removed": []}

        assert (
            client.post(
                root, json={"scope": "exact_run", "run_id": "a" * 32, "run_offset": 1}
            ).status_code
            == 422
        )
        assert client.post(root, json={"run_offset": 200}).status_code == 422


def test_historical_snapshot_bytes_are_not_rewritten(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        review = client.post(f"/api/v1/sample-versions/{version['id']}/reviews", json={}).json()
        historical = {
            k: v
            for k, v in review.items()
            if k
            not in {
                "structure",
                "function_evidence",
                "source_run_offset",
                "source_runs_more",
                "answers",
                "interpretation_version",
                "import_inventory",
            }
        }
        historical["schema_version"] = "bytasm-review-1"
        historical["catalog_version"] = "review-2"
        historical["source_selection_policy"] = "latest-completed-step-per-tool-v1"
        raw = canonical_json(historical)
        with ctx_of(client).sessions() as session, session.begin():
            row = session.scalars(select(ReviewSnapshot)).one()
            row.canonical = raw.decode()
            row.sha256 = hashlib.sha256(raw).hexdigest()
        assert client.get(f"/api/v1/reviews/{review['id']}").status_code == 200
        exported = client.post(f"/api/v1/reviews/{review['id']}/export/json", json={}).json()
        assert exported["schema_version"] == "bytasm-review-export-1"
        assert "structure" not in exported
        compared = client.get(f"/api/v1/reviews/{review['id']}/compare/{review['id']}").json()
        assert compared["import_changes"] == {"added": [], "removed": []}
        assert any("Import deltas unavailable" in c for c in compared["cautions"])
        with ctx_of(client).sessions() as session:
            row = session.scalars(select(ReviewSnapshot)).one()
            assert row.canonical.encode() == raw
            assert json.loads(row.canonical)["schema_version"] == "bytasm-review-1"


def test_source_window_recovers_after_two_hundred_runs(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    from bytasm.db.models import AnalysisRun

    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        now = datetime.now(UTC)
        with ctx_of(client).sessions() as session, session.begin():
            for index in range(201):
                session.add(
                    AnalysisRun(
                        sample_version_id=version["id"],
                        kind="analysis",
                        profile_snapshot={},
                        status="cancelled",
                        queued_at=now + timedelta(seconds=index),
                        bytasm_version="test",
                    )
                )
        root = f"/api/v1/sample-versions/{version['id']}/reviews"
        newest = client.post(root, json={})
        assert newest.status_code == 201, newest.text
        assert newest.json()["source_runs_more"]
        assert newest.json()["source_run_offset"] == 0
        older = client.post(root, json={"run_offset": 200})
        assert older.status_code == 201, older.text
        assert older.json()["source_run_offset"] == 200
        assert not older.json()["source_runs_more"]
        assert any(s["selected"] for s in older.json()["sources"] if s["tool"] == "lief")
        refreshed = client.post(f"/api/v1/reviews/{older.json()['id']}/refresh", json={})
        assert refreshed.json()["source_run_offset"] == 200


def test_note_history_pages_keep_latest_editor_revision(tmp_path: Path) -> None:
    from test_ghidra_api import seed_document

    with api_client(make_settings(tmp_path)) as client:
        run_id, _ = seed_document(client)
        root = f"/api/v1/runs/{run_id}/ghidra/functions/0/review"
        for revision in range(27):
            response = client.post(
                root, json={"expected_revision": revision, "note": f"Note {revision + 1}"}
            )
            assert response.status_code == 201, response.text
        first = client.get(root).json()
        assert first["next_offset"] == 25 and len(first["revisions"]) == 25
        old = client.get(root + "?offset=25").json()
        assert old["current"]["revision"] == 27
        assert [r["revision"] for r in old["revisions"]] == [2, 1]
        assert old["next_offset"] is None
