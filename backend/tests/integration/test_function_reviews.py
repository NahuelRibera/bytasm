import hashlib
from pathlib import Path

from api_support import api_client, make_settings
from test_ghidra_api import seed_document


def test_function_overlays_are_revisioned_cited_and_export_opt_in(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        run, _ = seed_document(client)
        version = client.get(f"/api/v1/runs/{run}").json()["sample"]["version_id"]
        url = f"/api/v1/runs/{run}/ghidra/functions/0/review"
        initial = client.get(url)
        assert initial.status_code == 200, initial.text
        identity = initial.json()["identity"]
        body = {
            "expected_revision": 0,
            "alias": "Locally reviewed helper",
            "bookmarked": True,
            "collections": ["Configuration"],
            "state": "reviewed",
            "note": "My analyst note",
            "citation": {
                "text_sha256": hashlib.sha256(b"return <hostile>;").hexdigest(),
                "start_line": 1,
                "end_line": 1,
            },
        }
        first = client.post(url, json=body)
        assert first.status_code == 201, first.text
        assert first.json()["identity"] == identity
        assert first.json()["current"]["revision"] == 1
        assert client.post(url, json=body).status_code == 409
        body["expected_revision"] = 1
        body["note"] = "Revised analyst note"
        assert client.post(url, json=body).status_code == 201
        read = client.get(url).json()
        assert len(read["revisions"]) == 2
        assert read["revisions"][0]["note"] == "Revised analyst note"
        review = client.post(f"/api/v1/sample-versions/{version}/reviews", json={}).json()
        export = f"/api/v1/reviews/{review['id']}/export/json"
        assert "Revised analyst note" not in client.post(export, json={}).text
        included = client.post(export, json={"analyst_notes": True})
        assert "Revised analyst note" in included.text
        minimized = client.post(
            export, json={"analyst_notes": True, "technical_details": False}
        ).json()
        overlay = minimized["function_reviews"][0]
        assert "entry" not in overlay["identity"] and "record_pointer" not in overlay["identity"]
        assert set(overlay["citation"]) == {"text_sha256"}
        body["expected_revision"] = 2
        body["note"] = "Later revision"
        client.post(url, json=body)
        assert client.post(export, json={"analyst_notes": True}).content == included.content


def test_function_citation_must_bind_to_the_exact_retained_text(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        run, _ = seed_document(client)
        url = f"/api/v1/runs/{run}/ghidra/functions/0/review"
        body = {
            "expected_revision": 0,
            "note": "Invalid citation",
            "citation": {"text_sha256": "0" * 64, "start_line": 1, "end_line": 1},
        }
        assert client.post(url, json=body).status_code == 422
        assert client.get(url).json()["current"] is None
        assert client.post(url, json={"expected_revision": 0, "note": "One"}).status_code == 201
        with __import__("pytest").raises(RuntimeError, match="function review revisions"):
            from api_support import ctx_of

            from bytasm.db.session import migrate

            migrate(ctx_of(client).engine, "0008", downgrade=True)
        assert client.get(url).json()["current"]["note"] == "One"
