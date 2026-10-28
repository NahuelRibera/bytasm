"""Migrations keep existing data: v0.1 rows survive 0001 -> 0002, and back.

A database created by v0.1 already holds imports when v0.2 first starts, and
SQLite's batch migrations copy and drop tables those rows reference.
"""

from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64, PE_X86_64_EXE
from fastapi.testclient import TestClient
from sqlalchemy import text

from bytasm.db.session import migrate


def _counts(client: TestClient) -> dict[str, int]:
    with ctx_of(client).engine.connect() as connection:
        return {
            table: int(connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one())  # noqa: S608
            for table in ("sample_version", "analysis_run", "tool_invocation", "section", "symbol")
        }


def test_downgrade_and_upgrade_with_v0_1_and_v0_2_rows(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    with api_client(settings) as client:
        project = create_project(client)
        imported = []
        for fixture, name in ((ELF_X86_64, "elf"), (PE_X86_64_EXE, "pe")):
            response = do_import(client, project, fixture.read_bytes(), sample_name=name)
            assert response.status_code == 201
            imported.append(response.json()["sample_version"]["id"])
        before = _counts(client)
        run = client.post(
            f"/api/v1/sample-versions/{imported[0]}/runs", json={"profile_id": "default-static"}
        )
        assert run.status_code == 202
        engine = ctx_of(client).engine

        # Back to the v0.1 schema: analysis runs go, every import stays.
        migrate(engine, "0001", downgrade=True)
        assert _counts(client) == before
        with engine.connect() as connection:
            columns = {
                row[1] for row in connection.execute(text("PRAGMA table_info(analysis_run)"))
            }
        assert "kind" not in columns

        # And forward again, as a v0.1 database meeting v0.2 for the first time.
        migrate(engine, "head")
        assert _counts(client) == before
        for version_id in imported:
            assert client.get(f"/api/v1/sample-versions/{version_id}").status_code == 200
            assert client.post(f"/api/v1/sample-versions/{version_id}/reports").status_code == 201
        with engine.connect() as connection:
            kinds = connection.execute(text("SELECT DISTINCT kind FROM analysis_run")).all()
            assert kinds == [("import",)]
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1


def test_a_failed_migration_changes_nothing(tmp_path: Path) -> None:
    """A violation found at the end rolls back every table change (DDL included)."""
    import pytest

    from bytasm.db.session import MigrationError, create_sqlite_engine

    engine = create_sqlite_engine(tmp_path / "db.sqlite3")
    migrate(engine, "0001")
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        connection.commit()
        # A dangling reference, as a damaged v0.1 database might hold.
        connection.execute(
            text(
                'INSERT INTO section (invocation_id, "index", name, file_offset, raw_size, '
                "virtual_address, virtual_size, flags) VALUES ('missing', 0, 'x', 0, 0, 0, 0, '[]')"
            )
        )
        connection.commit()
    with pytest.raises(MigrationError):
        migrate(engine, "head")
    with engine.connect() as connection:
        tables = {row[0] for row in connection.execute(text("SELECT name FROM sqlite_master"))}
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert version == "0001"
    assert "rule_set" not in tables and "finding" not in tables
    assert not any(name.startswith("_alembic_tmp") for name in tables)
    engine.dispose()


def test_0002_runs_survive_0003_and_multi_step_runs_downgrade_cleanly(tmp_path: Path) -> None:
    """A v0.2 database from the first slice (0002, one YARA-X step) meets 0003, and back."""
    import asyncio

    from sqlalchemy import select

    from bytasm.db.models import AnalysisRun, StringOccurrence
    from bytasm.jobs.worker import Worker
    from bytasm.runner.supervisor import yara_adapter_command

    settings = make_settings(tmp_path)
    with api_client(settings) as client:
        project = create_project(client)
        response = do_import(client, project, ELF_X86_64.read_bytes(), sample_name="elf")
        version_id = response.json()["sample_version"]["id"]
        ctx = ctx_of(client)

        # A multi-step run with strings rows and a finding.
        run = client.post(
            f"/api/v1/sample-versions/{version_id}/runs", json={"profile_id": "default-static"}
        ).json()
        from test_analysis import deps_for

        worker = Worker(deps_for(ctx, yara_adapter_command()), settings.data_dir, asyncio.Event())
        assert asyncio.run(worker.process_next()) == "succeeded"
        engine = ctx.engine
        before = _counts(client)

        # Down to 0002: the multi-step run and its rows go; the import stays.
        migrate(engine, "0002", downgrade=True)
        with engine.connect() as connection:
            tables = {row[0] for row in connection.execute(text("SELECT name FROM sqlite_master"))}
            runs_left = connection.execute(
                text("SELECT count(*) FROM analysis_run WHERE kind = 'analysis'")
            ).scalar_one()
            # A run as the first v0.2 slice recorded it: one YARA-X step.
            snapshot = (
                '{"id": "default-static", "name": "old", "steps": [{"tool": "yara-x", '
                '"adapter": "yara_x_scan", "rule_set": {"id": "r", "label": "l", '
                '"sha256": "' + "0" * 64 + '"}, "timeout_seconds": 30.0}]}'
            )
            connection.execute(
                text(
                    "INSERT INTO analysis_run (id, sample_version_id, kind, profile_snapshot, "
                    "status, failure_reason, queued_at, started_at, finished_at, "
                    "cancel_requested, bytasm_version) VALUES ('old', :v, 'analysis', :s, "
                    "'failed', 'timeout', '2026-10-27T00:00:00+00:00', "
                    "'2026-10-27T00:00:00+00:00', '2026-10-27T00:00:01+00:00', 0, '0.1.0')"
                ),
                {"v": version_id, "s": snapshot},
            )
            connection.commit()
        assert "string_occurrence" not in tables and runs_left == 0
        assert _counts(client)["sample_version"] == before["sample_version"]

        # Up again: the 0002 run is still shown, with its single step.
        migrate(engine, "head")
        old = client.get("/api/v1/runs/old").json()
        assert old["status"] == "failed" and old["failure_reason"] == "timeout"
        assert [(s["tool"], s["status"]) for s in old["steps"]] == [("yara-x", "skipped")]
        with ctx.sessions() as session:
            assert session.scalars(select(StringOccurrence)).all() == []
            assert session.get(AnalysisRun, run["id"]) is None
        assert client.post(f"/api/v1/sample-versions/{version_id}/reports").status_code == 201
