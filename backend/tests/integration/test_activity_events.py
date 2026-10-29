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
