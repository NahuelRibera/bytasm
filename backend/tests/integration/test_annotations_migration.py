"""Upgrade preserves populated v0.2 databases and protects immutable revisions."""

import json
from pathlib import Path

import pytest
from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from bytasm.db.session import migrate


def test_upgrade_preserves_existing_analysis_and_seeds_one_analyst(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]["id"]
        report_response = client.post(f"/api/v1/sample-versions/{version}/reports")
        assert report_response.status_code == 201
        response = client.post(
            f"/api/v1/sample-versions/{version}/runs", json={"profile_id": "default-static"}
        )
        assert response.status_code == 202
        engine = ctx_of(client).engine
        with engine.connect() as connection:
            report_before = connection.execute(
                text(
                    "SELECT id,sample_version_id,format,sha256,generated_at,"
                    "generator_version,path "
                    "FROM report"
                )
            ).all()
        migrate(engine, "0004", downgrade=True)
        with engine.connect() as connection:
            before = connection.execute(
                text("SELECT id,status FROM analysis_run ORDER BY id")
            ).all()
        migrate(engine)
        migrate(engine)
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT id,status FROM analysis_run ORDER BY id")).all()
                == before
            )
            assert connection.execute(text("SELECT id,display_name FROM analyst")).all() == [
                ("local", "Local analyst")
            ]
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT id,sample_version_id,format,sha256,generated_at,"
                        "generator_version,path "
                        "FROM report"
                    )
                ).all()
                == report_before
            )
            assert connection.execute(text("SELECT scope FROM report")).scalar_one() is None
        comparison_scope = {
            "kind": "comparison",
            "base_version_id": version,
            "target_version_id": version,
        }
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE report SET scope = :scope"), {"scope": json.dumps(comparison_scope)}
            )
        migrate(engine)
        with engine.connect() as connection:
            assert (
                json.loads(connection.execute(text("SELECT scope FROM report")).scalar_one())
                == comparison_scope
            )
            assert (
                connection.execute(
                    text(
                        "SELECT id,sample_version_id,format,sha256,generated_at,"
                        "generator_version,path "
                        "FROM report"
                    )
                ).all()
                == report_before
            )
        response = client.post(
            "/api/v1/annotations",
            json={
                "target_type": "sample_version",
                "target_id": version,
                "kind": "note",
                "body": "Preserved",
            },
        )
        assert response.status_code == 201
        for sql in ("UPDATE annotation SET body='changed'", "DELETE FROM annotation"):
            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.exec_driver_sql(sql)


@pytest.mark.parametrize("legacy_version", [2, 3])
def test_round_trip_preserves_populated_main_schema_and_legacy_report(
    tmp_path: Path, legacy_version: int
) -> None:
    import hashlib

    from jsonschema import Draft202012Validator
    from sqlalchemy import select
    from test_analysis import process, start_run

    from bytasm.db.models import Report
    from bytasm.reports.generate import canonical_json

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        ctx = ctx_of(client)
        start_run(client, version["id"])
        assert process(ctx) == "succeeded"
        created = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
        legacy = client.get(created["download_url"]).json()
        legacy["schema_version"] = legacy_version
        removed = ["summary", "analysis_context"]
        if legacy_version == 2:
            removed.extend(["scope", "annotations", "comparison"])
        for key in removed:
            del legacy[key]
        for finding in (legacy.get("pattern_analysis") or {}).get("findings", []):
            finding.pop("rule_set_sha256", None)
            for evidence in finding["evidence"]:
                evidence.pop("virtual_address", None)
                evidence.pop("virtual_address_hex", None)
        schema = (
            Path(__file__).resolve().parents[3] / f"schemas/report-v{legacy_version}.schema.json"
        )
        Draft202012Validator(json.loads(schema.read_text())).validate(legacy)
        raw = canonical_json(legacy)
        digest = hashlib.sha256(raw).hexdigest()
        # Representative already-stored v2 artifact: downloads must keep its bytes.
        ctx.reports.put_bytes(raw, digest, tmp_path)
        with ctx.sessions() as session, session.begin():
            record = session.get_one(Report, created["id"])
            record.sha256, record.path = digest, ctx.reports.relative_path(digest)

        migrate(ctx.engine, "0004", downgrade=True)
        tables = (
            "project",
            "sample",
            "sample_version",
            "authorization_record",
            "analysis_run",
            "tool_invocation",
            "finding",
            "evidence",
            "string_occurrence",
            "section",
            "symbol",
            "rule_set",
            "activity_event",
            "report",
        )

        def snapshot() -> dict[str, list[tuple[object, ...]]]:
            with ctx.engine.connect() as connection:
                return {
                    name: sorted(
                        [
                            tuple(row)
                            for row in connection.exec_driver_sql(f'SELECT * FROM "{name}"')  # noqa: S608
                        ],
                        key=repr,
                    )
                    for name in tables
                }

        before = snapshot()
        assert all(before[name] for name in tables)
        for _ in range(2):
            migrate(ctx.engine)
            assert client.get(created["download_url"]).content == raw
            note = client.post(
                "/api/v1/annotations",
                json={
                    "target_type": "sample_version",
                    "target_id": version["id"],
                    "kind": "note",
                    "body": "After migration",
                },
            )
            assert note.status_code == 201
            with ctx.engine.connect() as connection:
                assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            migrate(ctx.engine, "0004", downgrade=True)
            after = snapshot()
            # Downgrade retains the historical annotation event as an audit fact;
            # all original events and all prior state must be byte-for-byte intact.
            assert set(before["activity_event"]) <= set(after["activity_event"])
            for name in tables:
                if name != "activity_event":
                    assert after[name] == before[name]
        migrate(ctx.engine)
        assert client.get(created["download_url"]).content == raw
        with ctx.sessions() as session:
            assert session.scalar(select(Report.sha256)) == digest


def test_v04_upgrade_preserves_populated_v03_revisions_and_citations(tmp_path: Path) -> None:
    from sqlalchemy import MetaData, select
    from test_analysis import process, start_run

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        run = start_run(client, version["id"])
        ctx = ctx_of(client)
        assert process(ctx) == "succeeded"
        finding = client.get(f"/api/v1/runs/{run['id']}/findings").json()["findings"][0]
        cites = [{"target_type": "evidence", "target_id": str(finding["evidence"][0]["id"])}]
        created = client.post(
            "/api/v1/annotations",
            json={
                "target_type": "sample_version",
                "target_id": version["id"],
                "kind": "conclusion",
                "body": "Original cited conclusion",
                "confidence": "tentative",
                "cites": cites,
            },
        )
        assert created.status_code == 201
        history_url = f"/api/v1/annotations/{created.json()['id']}/revisions"
        revised = client.post(
            history_url,
            json={
                "expected_revision": 1,
                "kind": "conclusion",
                "body": "Revised cited conclusion",
                "confidence": "likely",
                "cites": cites,
            },
        )
        assert revised.status_code == 201
        record = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
        report_bytes = client.get(record["download_url"]).content
        migrate(ctx.engine, "0005", downgrade=True)
        previous = MetaData()
        previous.reflect(bind=ctx.engine)
        tables = {
            name: table for name, table in previous.tables.items() if name != "alembic_version"
        }
        with ctx.engine.connect() as connection:
            before = {
                name: sorted([tuple(row) for row in connection.execute(select(table))], key=repr)
                for name, table in tables.items()
            }
        assert before["annotation"] and before["annotation_citation"] and before["evidence"]
        migrate(ctx.engine)
        migrate(ctx.engine)
        with ctx.engine.connect() as connection:
            after = {
                name: sorted([tuple(row) for row in connection.execute(select(table))], key=repr)
                for name, table in tables.items()
            }
            assert after == before
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert client.get(record["download_url"]).content == report_bytes
        history = client.get(history_url).json()["items"]
        assert [item["body"] for item in history] == [
            "Original cited conclusion",
            "Revised cited conclusion",
        ]
        assert all(item["cites"][0]["target_id"] == cites[0]["target_id"] for item in history)
