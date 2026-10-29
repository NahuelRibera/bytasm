"""Project audit events are atomic with creation, using disposable databases."""

from pathlib import Path

import pytest
from api_support import api_client, ctx_of, make_settings
from sqlalchemy import text


def test_project_creation_records_one_minimal_local_event(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        response = client.post(
            "/api/v1/projects", json={"name": "Private name", "description": "Private text"}
        )
        assert response.status_code == 201
        project = response.json()
        assert client.get(f"/api/v1/projects/{project['id']}").status_code == 200
        assert client.get("/api/v1/projects").status_code == 200
        with ctx_of(client).engine.connect() as connection:
            events = connection.execute(text("SELECT * FROM activity_event")).mappings().all()
        assert len(events) == 1
        event = events[0]
        assert len(event["id"]) == 32
        assert event["project_id"] == project["id"]
        assert event["actor_id"] == "local"
        assert event["type"] == "project.created"
        assert event["payload"] == "{}"
        assert event["at"] == project["created_at"].replace("+00:00", "Z")


@pytest.mark.parametrize("table", ["project", "activity_event"])
def test_project_and_event_roll_back_together(tmp_path: Path, table: str) -> None:
    with api_client(make_settings(tmp_path), raise_server_exceptions=False) as client:
        engine = ctx_of(client).engine
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE TRIGGER reject_creation BEFORE INSERT ON {table} "  # noqa: S608
                "BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END"
            )
        assert client.post("/api/v1/projects", json={"name": "Rejected"}).status_code == 500
        with engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM project")).scalar_one() == 0
            assert connection.execute(text("SELECT count(*) FROM activity_event")).scalar_one() == 0


@pytest.mark.parametrize("existing_sample", [False, True])
def test_import_records_only_version_references(tmp_path: Path, existing_sample: bool) -> None:
    import json

    from api_support import create_project, do_import
    from conftest import ELF_X86_64, PE_X86_64_EXE

    with api_client(make_settings(tmp_path)) as client:
        project_id = create_project(client)
        sample_fields = {"sample_name": "private-sample"}
        if existing_sample:
            first = do_import(client, project_id, ELF_X86_64.read_bytes()).json()["sample_version"]
            sample_fields = {"sample_id": first["sample_id"]}
        response = do_import(
            client,
            project_id,
            PE_X86_64_EXE.read_bytes(),
            **sample_fields,
            version_label="private-version",
            declared_filename="/private/secret.exe",
            authorization={"basis": "owned_or_built", "statement": "secret-attestation"},
        )
        assert response.status_code == 201
        version = response.json()["sample_version"]
        with ctx_of(client).engine.connect() as connection:
            events = (
                connection.execute(
                    text("SELECT * FROM activity_event WHERE type = 'sample_version.imported'")
                )
                .mappings()
                .all()
            )
        assert len(events) == (2 if existing_sample else 1)
        event = next(
            row
            for row in events
            if json.loads(row["payload"])["sample_version_id"] == version["id"]
        )
        assert event["project_id"] == project_id
        assert event["actor_id"] == "local"
        assert json.loads(event["payload"]) == {
            "sample_id": version["sample_id"],
            "sample_version_id": version["id"],
        }
        assert event["at"] == version["imported_at"].replace("+00:00", "Z")
        # Exact payload keys exclude names, paths, attestation, hashes and parsed content.
        assert len(event["payload"]) < 150
        assert all(len(value) == 32 for value in json.loads(event["payload"]).values())


@pytest.mark.parametrize("failure", ["event", "version", "blob", "commit"])
def test_import_failure_leaves_no_success_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from api_support import assert_nothing_imported, create_project, do_import
    from conftest import ELF_X86_64
    from sqlalchemy.orm import Session

    from bytasm.storage import ContentStore

    with api_client(make_settings(tmp_path), raise_server_exceptions=False) as client:
        project_id = create_project(client)
        ctx = ctx_of(client)
        with monkeypatch.context() as patch:
            if failure in ("event", "version"):
                table = "activity_event" if failure == "event" else "sample_version"
                with ctx.engine.begin() as connection:
                    connection.exec_driver_sql(
                        f"CREATE TRIGGER reject_import BEFORE INSERT ON {table} "  # noqa: S608
                        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
                    )
            elif failure == "blob":

                def fail_place(self: ContentStore, source: Path, sha256: str) -> bool:
                    raise OSError("injected storage failure")

                patch.setattr(ContentStore, "place", fail_place)
            else:

                def fail_commit(self: Session) -> None:
                    self.flush()  # include the event in the transaction before failing
                    raise RuntimeError("injected commit failure")

                patch.setattr(Session, "commit", fail_commit)
            response = do_import(client, project_id, ELF_X86_64.read_bytes())
        assert response.status_code == 500
        assert_nothing_imported(ctx)
        with ctx.engine.connect() as connection:
            events = connection.execute(text("SELECT type FROM activity_event")).all()
            assert events == [("project.created",)]


@pytest.mark.parametrize("rejected", [False, True])
def test_unsuccessful_parse_or_admission_emits_no_import_event(
    tmp_path: Path, rejected: bool
) -> None:
    from api_support import create_project, do_import, fake_adapter
    from conftest import ELF_X86_64

    with api_client(make_settings(tmp_path), fake_adapter("exit1")) as client:
        project_id = create_project(client)
        data = b"not an admitted binary" if rejected else ELF_X86_64.read_bytes()
        assert do_import(client, project_id, data).status_code in (403, 415, 422)
        with ctx_of(client).engine.connect() as connection:
            assert connection.execute(text("SELECT type FROM activity_event")).all() == [
                ("project.created",)
            ]
