"""Real admitted fixtures → review, scoped explorer and immutable report views."""

import hashlib
from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import CAPA_PE, ELF_AARCH64, ELF_X86_64
from sqlalchemy import select
from test_analysis import process

from bytasm.db.models import Report, SampleVersion
from bytasm.db.session import migrate
from bytasm.reports.generate import canonical_json


def test_full_review_explains_exact_capa_evidence_and_snapshot_survives_live_changes(
    tmp_path: Path,
) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        assert run["review"]["total"] == 0 and "capa: queued" in " ".join(run["summary"])
        assert process(ctx_of(client)) == "succeeded"
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        observation = next(
            item for item in result["review"]["observations"] if item["tool"] == "capa"
        )
        assert observation["rule_version"] == "10.0.0"
        assert observation["tool_version"] == "10.0.0"
        assert (
            "environment" in observation["hypothesis"]
            and "does not prove" in observation["hypothesis"]
        )
        assert "virtual address 0x140001450" in observation["locations"][0]
        assert observation["source_href"].startswith(f"/runs/{run['id']}#finding-")
        record = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
        url = f"/api/v1/reports/{record['id']}/review"
        frozen = client.get(url).json()
        before = client.get(record["download_url"]).content
        with ctx_of(client).sessions() as session, session.begin():
            session.get_one(SampleVersion, version["id"]).declared_filename = "later filename"
        assert client.get(url).json() == frozen
        migrate(ctx_of(client).engine)
        assert client.get(record["download_url"]).content == before
        assert client.get(f"/api/v1/reports/{'f' * 32}/review").status_code == 404


def test_strings_facets_sorting_section_links_and_cross_version_scope(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_AARCH64.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "default-static"}
        ).json()
        assert process(ctx_of(client)) == "succeeded"
        base = f"/api/v1/sample-versions/{version['id']}/strings"
        all_rows = client.get(base, params={"limit": 200, "run_id": run["id"]}).json()
        assert sum(all_rows["category_counts"].values()) == all_rows["summary"]["stored"]
        paths = client.get(base, params={"category": "path_like", "run_id": run["id"]}).json()
        assert paths["matched"] > 0 and all(
            item["category"] == "path_like" for item in paths["items"]
        )
        assert paths["category_counts"] == all_rows["category_counts"]
        assert all_rows["metadata_invocation_id"]
        assert any(item["section"] for item in all_rows["items"])
        first = client.get(base, params={"sort": "length", "limit": 5}).json()
        second = client.get(base, params={"sort": "length", "limit": 5, "offset": 5}).json()
        lengths = [item["length_chars"] for item in first["items"] + second["items"]]
        assert lengths == sorted(lengths, reverse=True)
        assert client.get(base, params={"query": "%_"}).json()["matched"] == 0
        for params in ({"sort": "unknown"}, {"category": "passwords"}, {"limit": 201}):
            assert client.get(base, params=params).status_code == 422
        other = do_import(client, create_project(client, "Other"), ELF_AARCH64.read_bytes()).json()[
            "sample_version"
        ]
        assert (
            client.get(
                f"/api/v1/sample-versions/{other['id']}/strings", params={"run_id": run["id"]}
            ).status_code
            == 404
        )
        assert client.get(f"/api/v1/sample-versions/{other['id']}/strings").json()["run_id"] is None


def test_historical_summary_and_json_bytes_are_not_reinterpreted_by_html(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        created = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
        document = client.get(created["download_url"]).json()
        hostile = '<img src=x onerror="alert(1)"> Historical summary'
        document["summary"] = [hostile]
        raw = canonical_json(document)
        digest = hashlib.sha256(raw).hexdigest()
        ctx = ctx_of(client)
        ctx.reports.put_bytes(raw, digest, tmp_path)
        with ctx.sessions() as session, session.begin():
            row = session.scalar(select(Report).where(Report.id == created["id"]))
            assert row is not None
            row.sha256, row.path = digest, ctx.reports.relative_path(digest)
        html = client.get(f"/api/v1/reports/{created['id']}/html")
        assert html.status_code == 200 and "Historical summary" in html.text
        assert "&lt;img" in html.text and "<img" not in html.text
        assert client.get(created["download_url"]).content == raw
        path = ctx.reports.path(digest)
        path.chmod(0o600)
        path.write_bytes(b"corrupt")
        assert client.get(f"/api/v1/reports/{created['id']}/review").status_code == 409


def test_explorer_rejects_oversized_persisted_observations_without_unbounded_read(
    tmp_path: Path,
) -> None:
    from sqlalchemy import insert

    from bytasm.db.models import StringOccurrence, ToolInvocation

    with api_client(make_settings(tmp_path)) as client:
        version = do_import(client, create_project(client), ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "default-static"}
        ).json()
        ctx = ctx_of(client)
        assert process(ctx) == "succeeded"
        # Deliberately corrupt database test data, not an admitted/analysed binary.
        with ctx.sessions() as session, session.begin():
            invocation = session.scalar(
                select(ToolInvocation).where(
                    ToolInvocation.run_id == run["id"], ToolInvocation.tool_name == "strings"
                )
            )
            assert invocation is not None
            session.execute(
                insert(StringOccurrence),
                [
                    {
                        "invocation_id": invocation.id,
                        "file_offset": 100_000 + i,
                        "encoding": "ascii",
                        "length_chars": 8,
                        "byte_length": 8,
                        "value": "testtext",
                        "value_truncated": False,
                    }
                    for i in range(5001)
                ],
            )
        assert client.get(f"/api/v1/sample-versions/{version['id']}/strings").status_code == 409
