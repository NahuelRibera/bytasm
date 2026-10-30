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


def test_round_trip_preserves_populated_main_schema_and_legacy_report(tmp_path: Path) -> None:
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
        legacy["schema_version"] = 2
        for key in ("scope", "annotations", "comparison"):
            del legacy[key]
        schema = Path(__file__).resolve().parents[3] / "schemas/report-v2.schema.json"
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
