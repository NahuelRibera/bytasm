"""Project activity is atomic, scoped and safe to display."""

from datetime import datetime
from pathlib import Path

import pytest
from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64
from fastapi.testclient import TestClient
from sqlalchemy import select

from bytasm.db.models import ActivityEvent, AnalysisRun, utcnow
from bytasm.jobs import runs


def prepare(client: TestClient) -> tuple[str, str, str]:
    project_id = create_project(client)
    version_id = do_import(client, project_id, ELF_X86_64.read_bytes()).json()["sample_version"][
        "id"
    ]
    run = client.post(
        f"/api/v1/sample-versions/{version_id}/runs", json={"profile_id": "default-static"}
    )
    assert run.status_code == 202
    return project_id, version_id, run.json()["id"]


@pytest.mark.parametrize("target", ["succeeded", "partial", "failed", "cancelled"])
def test_transitions_record_once_and_rollback(tmp_path: Path, target: str) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project_id, version_id, run_id = prepare(client)
        ctx = ctx_of(client)
        with ctx.sessions() as session:
            assert runs.transition(session, run_id, "queued", "running")
            session.commit()
            assert runs.transition(
                session, run_id, "running", target, failure_reason="worker_interrupted"
            )
            session.rollback()
            assert session.get_one(AnalysisRun, run_id).status == "running"
            assert runs.transition(
                session, run_id, "running", target, failure_reason="worker_interrupted"
            )
            session.commit()
            assert not runs.transition(session, run_id, "running", target)
            session.commit()
            events = session.scalars(
                select(ActivityEvent).where(ActivityEvent.type.like("analysis_run.%"))
            ).all()
            assert [event.type for event in events] == [
                "analysis_run.queued",
                "analysis_run.running",
                f"analysis_run.{target}",
            ]
            for event in events:
                assert event.project_id == project_id and event.actor_id == "local"
                assert event.payload["run_id"] == run_id
                assert event.payload["sample_version_id"] == version_id
                assert set(event.payload) <= {"run_id", "sample_version_id", "status", "reason"}
            assert events[-1].payload["reason"] == "worker_interrupted"


def test_cancel_and_recovery_are_idempotent(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        _, _, run_id = prepare(client)
        with ctx_of(client).sessions() as session:
            assert runs.claim_next(session) == run_id
            assert runs.request_cancel(session, run_id) == "requested"
            assert runs.request_cancel(session, run_id) == "already_requested"
            assert runs.fail_interrupted_runs(session) == 1
            assert runs.fail_interrupted_runs(session) == 0
            assert runs.request_cancel(session, run_id) == "finished"
            kinds = session.scalars(
                select(ActivityEvent.type).where(ActivityEvent.type.like("analysis_run.%"))
            ).all()
            assert kinds.count("analysis_run.cancel_requested") == 1
            assert kinds.count("analysis_run.cancelled") == 1


def test_activity_pagination_and_projection(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project_id, version_id, run_id = prepare(client)
        other = create_project(client, "Other")
        with ctx_of(client).sessions() as session:
            # Corrupt references cannot generate links across project boundaries.
            session.add(
                ActivityEvent(
                    project_id=other,
                    actor_id="local",
                    type="analysis_run.failed",
                    payload={
                        "run_id": run_id,
                        "sample_version_id": version_id,
                        "status": "failed",
                        "reason": "/secret/path",
                        "secret": "private",
                    },
                    at=utcnow(),
                )
            )
            session.commit()
        url = f"/api/v1/projects/{project_id}/activity"
        all_events = client.get(url).json()["items"]
        assert len(all_events) == 3
        assert [e["type"] for e in all_events].count("project.created") == 1
        pages = []
        offset = 0
        while True:
            page = client.get(url, params={"offset": offset, "limit": 1}).json()
            pages.extend(page["items"])
            if page["next_offset"] is None:
                break
            offset = page["next_offset"]
        assert pages == all_events
        assert [(datetime.fromisoformat(e["at"]), e["id"]) for e in pages] == sorted(
            (datetime.fromisoformat(e["at"]), e["id"]) for e in pages
        )
        projected = client.get(f"/api/v1/projects/{other}/activity").json()["items"]
        forged = next(e for e in projected if e["type"] == "analysis_run.failed")
        assert forged["run_id"] is None and forged["sample_version_id"] is None
        assert forged["reason"] is None
        assert "private" not in str(projected) and "/secret" not in str(projected)
        assert client.get("/api/v1/projects/missing/activity").status_code == 404
        for query in ("limit=0", "limit=101", "offset=-1", "offset=x"):
            assert client.get(f"{url}?{query}").status_code == 422
        assert client.get(url, headers={"Host": "evil.invalid"}).status_code == 400
        assert client.get(url, headers={"Origin": "https://evil.invalid"}).status_code == 403
        assert client.post(url).status_code != 200


def test_event_failure_rolls_back_transition(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        _, _, run_id = prepare(client)
        ctx = ctx_of(client)
        with ctx.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TRIGGER reject_activity BEFORE INSERT ON activity_event "
                "BEGIN SELECT RAISE(ABORT, 'test'); END"
            )
        from sqlalchemy.exc import IntegrityError

        with ctx.sessions() as session:
            with pytest.raises(IntegrityError):
                runs.transition(session, run_id, "queued", "running")
                session.commit()
            session.rollback()
            assert session.get_one(AnalysisRun, run_id).status == "queued"


def test_timestamp_precision_and_id_ties(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    with api_client(make_settings(tmp_path)) as client:
        project_id = create_project(client)
        instant = datetime(2020, 1, 1, tzinfo=UTC)
        with ctx_of(client).sessions() as session:
            for identity, at in (
                ("c", instant.replace(microsecond=1)),
                ("b", instant),
                ("a", instant),
            ):
                session.add(
                    ActivityEvent(
                        id=identity * 32,
                        project_id=project_id,
                        actor_id="local",
                        type="project.created",
                        payload={},
                        at=at,
                    )
                )
            session.commit()
        response = client.get(f"/api/v1/projects/{project_id}/activity").json()
        assert [item["id"] for item in response["items"][:3]] == ["a" * 32, "b" * 32, "c" * 32]


def test_queued_cancel_and_creation_retry_emit_no_duplicates(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project_id, version_id, run_id = prepare(client)
        assert (
            client.post(
                f"/api/v1/sample-versions/{version_id}/runs", json={"profile_id": "default-static"}
            ).status_code
            == 409
        )
        with ctx_of(client).sessions() as session:
            assert runs.request_cancel(session, run_id) == "cancelled"
            assert runs.request_cancel(session, run_id) == "finished"
        items = client.get(f"/api/v1/projects/{project_id}/activity").json()["items"]
        assert [item["type"] for item in items if item["run_id"]] == [
            "analysis_run.queued",
            "analysis_run.cancelled",
        ]


@pytest.mark.parametrize(
    "steps_done,cancel,target",
    [(0, False, "failed"), (1, False, "partial"), (2, False, "succeeded"), (1, True, "cancelled")],
)
def test_recovery_records_the_actual_outcome_once(
    tmp_path: Path, steps_done: int, cancel: bool, target: str
) -> None:
    from test_run_steps import _interrupted_run

    with api_client(make_settings(tmp_path)) as client:
        run_id = _interrupted_run(client, steps_done, cancel)
        with ctx_of(client).sessions() as session:
            assert runs.fail_interrupted_runs(session) == 1
            assert runs.fail_interrupted_runs(session) == 0
            events = session.scalars(
                select(ActivityEvent).where(ActivityEvent.type == f"analysis_run.{target}")
            ).all()
            assert len(events) == 1
            assert events[0].payload["run_id"] == run_id
            if target in ("partial", "failed"):
                assert events[0].payload["reason"] == "worker_interrupted"


def test_failed_queued_event_rolls_back_run_creation(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path), raise_server_exceptions=False) as client:
        project_id = create_project(client)
        version_id = do_import(client, project_id, ELF_X86_64.read_bytes()).json()[
            "sample_version"
        ]["id"]
        ctx = ctx_of(client)
        with ctx.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TRIGGER reject_queue BEFORE INSERT ON activity_event "
                "WHEN NEW.type = 'analysis_run.queued' BEGIN SELECT RAISE(ABORT, 'test'); END"
            )
        assert (
            client.post(
                f"/api/v1/sample-versions/{version_id}/runs", json={"profile_id": "default-static"}
            ).status_code
            == 500
        )
        with ctx.sessions() as session:
            assert (
                session.scalars(select(AnalysisRun).where(AnalysisRun.kind == "analysis")).all()
                == []
            )
