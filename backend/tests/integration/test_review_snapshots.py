"""Pinned review contracts exercised with real admitted fixtures and worker results."""

import hashlib
from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64
from test_analysis import process


def test_review_is_pinned_refresh_appends_and_exact_run_never_substitutes(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        root = f"/api/v1/sample-versions/{version['id']}/reviews"
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "default-static"}
        ).json()
        assert process(ctx_of(client)) == "succeeded"
        response = client.post(root, json={"scope": "combined"})
        assert response.status_code == 201, response.text
        frozen = response.json()
        assert frozen["sample"]["sha256"] == version["sha256"]
        selected = next(s for s in frozen["sources"] if s["tool"] == "strings")
        assert selected["selected"]["run_id"] == run["id"]
        later = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "default-static"}
        ).json()
        client.post(f"/api/v1/runs/{later['id']}/cancel")
        assert client.get(f"/api/v1/reviews/{frozen['id']}").json() == frozen
        updated = client.post(f"/api/v1/reviews/{frozen['id']}/refresh", json={}).json()
        assert updated["id"] != frozen["id"] and updated["supersedes_id"] == frozen["id"]
        source = next(s for s in updated["sources"] if s["tool"] == "strings")
        assert source["selected"]["run_id"] == run["id"]
        assert source["latest_attempt"]["run_id"] == later["id"]
        exact = client.post(root, json={"scope": "exact_run", "run_id": later["id"]}).json()
        assert all(s["selected"] is None for s in exact["sources"] if s["tool"] != "lief")
        other = do_import(client, create_project(client, "Other"), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        assert (
            client.post(
                f"/api/v1/sample-versions/{other['id']}/reviews",
                json={"scope": "exact_run", "run_id": run["id"]},
            ).status_code
            == 404
        )


def test_review_export_preview_matches_bytes_and_privacy_policy(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = do_import(
            client,
            create_project(client),
            ELF_X86_64.read_bytes(),
            declared_filename="private<script>.elf",
        ).json()["sample_version"]
        client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "default-static"}
        )
        assert process(ctx_of(client)) == "succeeded"
        review = client.post(f"/api/v1/sample-versions/{version['id']}/reviews", json={}).json()
        url = f"/api/v1/reviews/{review['id']}/export"
        policy = {"technical_details": False, "observations": False}
        preview = client.post(url + "/preview", json=policy)
        assert preview.status_code == 200, preview.text
        document = preview.json()["document"]
        downloaded = client.post(url + "/json", json=policy)
        assert downloaded.json() == document
        assert hashlib.sha256(downloaded.content).hexdigest() == preview.json()["sha256"]
        assert all("profile" not in (s["selected"] or {}) for s in document["sources"])
        assert document["observations"] == []
        html = client.post(url + "/html", json=policy)
        assert html.status_code == 200 and "default-src 'none'" in html.text
        assert "<script" not in html.text and "<form" not in html.text
        assert client.post(url + "/json", json={"raw_outputs": True}).status_code == 422
        assert document["strings"] == [] and "declared_filename" not in document
        included = client.post(url + "/json", json={"string_values": True, "original_names": True})
        assert (
            included.json()["strings"]
            and included.json()["declared_filename"] == "private<script>.elf"
        )
        assert included.content != downloaded.content
        html_with_name = client.post(url + "/html", json={"original_names": True}).text
        assert "&lt;script&gt;" in html_with_name and "<script" not in html_with_name


def test_review_refuses_normalized_text_that_disagrees_with_verified_output(tmp_path: Path) -> None:
    from sqlalchemy import select

    from bytasm.db.models import StringOccurrence

    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "default-static"}
        )
        assert process(ctx_of(client)) == "succeeded"
        with ctx_of(client).sessions() as session, session.begin():
            row = session.scalars(select(StringOccurrence)).first()
            assert row
            row.value = "CORRUPTED NORMALIZED TEXT"
        assert (
            client.post(f"/api/v1/sample-versions/{version['id']}/reviews", json={}).status_code
            == 409
        )


def test_review_refuses_rule_identity_not_supported_by_output(tmp_path: Path) -> None:
    from sqlalchemy import select

    from bytasm.db.models import RuleSet, ToolInvocation

    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "default-static"}
        )
        assert process(ctx_of(client)) == "succeeded"
        with ctx_of(client).sessions() as session, session.begin():
            row = session.scalars(select(RuleSet)).first()
            meta = session.scalars(
                select(ToolInvocation).where(ToolInvocation.tool_name == "lief")
            ).first()
            assert row and meta and meta.raw_output_sha256
            row.sha256 = meta.raw_output_sha256
        assert (
            client.post(f"/api/v1/sample-versions/{version['id']}/reviews", json={}).status_code
            == 409
        )


def test_combined_review_includes_real_capa_without_claiming_runtime_behavior(
    tmp_path: Path,
) -> None:
    from conftest import CAPA_PE

    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), CAPA_PE.read_bytes()).json()[
            "sample_version"
        ]
        client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        )
        assert process(ctx_of(client)) == "succeeded"
        response = client.post(f"/api/v1/sample-versions/{version['id']}/reviews", json={})
        assert response.status_code == 201, response.text
        observation = next(o for o in response.json()["observations"] if o["tool"] == "capa")
        assert "environment" in observation["title"]
        assert observation["evidence"][0]["virtual_address"] == 0x140001450
        assert observation["relevance"] > 20 and observation["reviewed"] is True
        run_id = next(
            source["selected"]["run_id"]
            for source in response.json()["sources"]
            if source["tool"] == "capa"
        )
        live = client.get(f"/api/v1/runs/{run_id}").json()["review"]
        assert live["selection_policy"] == "relevance-v1"
        assert live["observations"][0]["tool"] == "capa"
        assert "environment" in live["observations"][0]["title"]


def test_published_review_and_export_schemas_and_snapshot_integrity(tmp_path: Path) -> None:
    import json

    import jsonschema
    from sqlalchemy import select

    from bytasm.db.models import ReviewSnapshot

    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        snapshot = client.post(f"/api/v1/sample-versions/{version['id']}/reviews", json={}).json()
        schemas = Path(__file__).resolve().parents[3] / "schemas"
        jsonschema.validate(snapshot, json.loads((schemas / "review-v2.schema.json").read_text()))
        exported = client.post(f"/api/v1/reviews/{snapshot['id']}/export/json", json={}).json()
        jsonschema.validate(
            exported, json.loads((schemas / "review-export-v2.schema.json").read_text())
        )
        with ctx_of(client).sessions() as session, session.begin():
            row = session.scalars(select(ReviewSnapshot)).first()
            assert row
            row.canonical += "corrupt"
        assert client.get(f"/api/v1/reviews/{snapshot['id']}").status_code == 409
        assert (
            client.post(f"/api/v1/reviews/{snapshot['id']}/export/json", json={}).status_code == 409
        )
