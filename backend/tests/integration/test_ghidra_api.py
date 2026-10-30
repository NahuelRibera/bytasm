"""Ghidra API contract tests use explicitly test-authored stored documents."""

from pathlib import Path

from api_support import api_client, create_project, do_import, make_settings
from conftest import ELF_X86_64


def test_ghidra_run_requires_verified_provider(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        imported = do_import(client, project, ELF_X86_64.read_bytes())
        assert imported.status_code == 201
        version = imported.json()["sample_version"]["id"]
        response = client.post(
            f"/api/v1/sample-versions/{version}/runs", json={"profile_id": "ghidra-static"}
        )
        assert response.status_code == 503
        assert response.json()["type"].endswith("provider_unavailable")
        assert client.get(f"/api/v1/sample-versions/{version}/runs").json()["runs"] == []


def seed_document(
    client: object, *, state: str = "succeeded", capped: bool = False
) -> tuple[str, str]:
    """Persist test-authored protocol records, never presented as real Ghidra verification."""
    import hashlib
    from datetime import UTC, datetime
    from typing import cast

    from api_support import ctx_of
    from fastapi.testclient import TestClient

    from bytasm.db.models import ToolInvocation
    from bytasm.ghidra_protocol import GhidraResult
    from bytasm.ghidra_provider import profile_snapshot
    from bytasm.jobs import runs

    api = cast(TestClient, client)
    project = create_project(api)
    imported = do_import(api, project, ELF_X86_64.read_bytes()).json()
    version = imported["sample_version"]["id"]
    ctx = ctx_of(api)
    snapshot = profile_snapshot()
    step = snapshot["steps"][0]
    function = {
        "entry": {"space": "ram", "address": "00401000"},
        "name": "<script>alert('symbol')</script>",
        "namespace": "Global",
        "body_size": 7,
        "pseudocode": "return <hostile>;",
        "pseudocode_status": "available",
        "pseudocode_truncated": False,
        "instructions": [
            {"address": {"space": "ram", "address": "00401000"}, "bytes_hex": "c3", "text": "RET"}
        ],
        "instructions_truncated": False,
        "calls": [],
        "calls_truncated": False,
    }
    result = GhidraResult.model_validate(
        {
            "schema_version": "ghidra-1",
            "input_sha256": hashlib.sha256(ELF_X86_64.read_bytes()).hexdigest(),
            "ghidra_version": "12.2",
            "language_id": "x86:LE:64:default",
            "compiler": "gcc",
            "profile_sha256": step["profile_sha256"],
            "script_sha256": step["script_sha256"],
            "functions": [function],
            "function_count": 2 if capped else 1,
            "functions_truncated": capped,
            "analysis_timed_out": False,
            "limitations": ["Test-authored protocol records; no tool executed in this test."],
        }
    )
    raw = result.model_dump_json().encode()
    digest = hashlib.sha256(raw).hexdigest()
    ctx.outputs.put_bytes(raw, digest, ctx.tmp_dir)
    with ctx.sessions() as session:
        run = runs.new_queued_run(version, snapshot, datetime.now(UTC))
        run.status = state
        run.started_at = datetime.now(UTC)
        run.finished_at = datetime.now(UTC)
        session.add(run)
        session.flush()
        inv = ToolInvocation(
            run_id=run.id,
            step_index=0,
            tool_name="ghidra",
            tool_version="12.2",
            adapter_name="ghidra_headless",
            adapter_version="1",
            args=step,
            status=state,
            failure_reason=None,
            exit_code=0,
            duration_ms=12,
            warnings=[],
            raw_output_sha256=digest if state == "succeeded" else None,
            raw_output_path=ctx.outputs.relative_path(digest) if state == "succeeded" else None,
        )
        session.add(inv)
        session.commit()
        return run.id, digest


def test_scoped_function_views_summary_export_and_limits(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        run_id, _ = seed_document(client, capped=True)
        base = f"/api/v1/runs/{run_id}/ghidra"
        overview = client.get(base).json()
        assert overview["available"] is True
        assert overview["coverage"] == {"completed": 1, "total": 1}
        assert overview["function_count"] == 2 and overview["stored_functions"] == 1
        assert overview["functions_truncated"] is True
        assert (
            "Pseudocode is available for 1 functions"
            in overview["summary"]["observations"][0]["text"]
        )
        assert overview["summary"]["hypotheses"] == []
        assert "capped" in " ".join(overview["summary"]["limitations"])
        assert client.get(base + "/functions?limit=101").status_code == 422
        assert client.get(base + "/functions?offset=-1").status_code == 422
        assert client.get(base + "/functions?q=" + "x" * 129).status_code == 422
        assert client.get(base + "/functions?q=missing").json()["matched"] == 0
        page = client.get(base + "/functions?q=SCRIPT&limit=1").json()
        assert page["matched"] == 1 and len(page["items"]) == 1
        assert "pseudocode" not in page["items"][0]
        detail = client.get(base + "/functions/0").json()
        assert detail["function"]["entry"] == {"space": "ram", "address": "00401000"}
        assert detail["function"]["pseudocode"] == "return <hostile>;"
        assert detail["citation"].endswith("#/functions/0")
        assert client.get(base + "/functions/1").status_code == 404
        assert client.get(base + "/functions/-1").status_code == 404
        assert client.get("/api/v1/runs/does-not-exist/ghidra").status_code == 404
        exported = client.get(base + "/export?format=json")
        assert exported.status_code == 200
        assert exported.json()["overview"] == overview
        assert exported.json()["analysis"]["functions"][0] == {
            key: value for key, value in detail["function"].items() if key != "limitations"
        }
        assert exported.content == client.get(base + "/export?format=json").content
        rendered = client.get(base + "/export?format=html")
        assert rendered.status_code == 200
        assert "default-src 'none'" in rendered.headers["Content-Security-Policy"]
        assert "<script>" not in rendered.text and "&lt;script&gt;" in rendered.text
        assert "return &lt;hostile&gt;" in rendered.text
        assert "<script " not in rendered.text and "<img " not in rendered.text


def test_missing_results_and_tampered_output_are_not_empty_success(tmp_path: Path) -> None:
    from api_support import ctx_of

    with api_client(make_settings(tmp_path)) as client:
        run_id, digest = seed_document(client, state="failed")
        base = f"/api/v1/runs/{run_id}/ghidra"
        overview = client.get(base).json()
        assert overview["available"] is False
        assert overview["function_count"] is None
        assert overview["summary"]["observations"] == []
        assert overview["coverage"]["completed"] == 0
        assert client.get(base + "/functions").status_code == 404
        assert client.get(base + "/export").status_code == 404
    with api_client(make_settings(tmp_path / "other")) as client:
        run_id, digest = seed_document(client)
        path = ctx_of(client).outputs.path(digest)
        path.chmod(0o600)
        path.write_bytes(b"{}")
        base = f"/api/v1/runs/{run_id}/ghidra"
        for suffix in ("", "/functions", "/functions/0", "/export"):
            assert client.get(base + suffix).status_code == 409


def test_ghidra_downgrade_guard_and_legacy_report_selection(tmp_path: Path) -> None:
    import pytest
    from alembic import command
    from api_support import ctx_of

    from bytasm.db.models import AnalysisRun
    from bytasm.db.session import alembic_config
    from bytasm.reports.generate import pattern_run

    with api_client(make_settings(tmp_path)) as client:
        run_id, digest = seed_document(client)
        ctx = ctx_of(client)
        with ctx.sessions() as session:
            run = session.get_one(AnalysisRun, run_id)
            assert pattern_run(run.sample_version) is None
        with ctx.engine.connect() as connection:
            cfg = alembic_config()
            cfg.attributes["connection"] = connection
            with pytest.raises(RuntimeError, match="Cannot downgrade while Ghidra runs exist"):
                command.downgrade(cfg, "0006")
        assert ctx.outputs.read_verified(digest)
        assert client.get(f"/api/v1/runs/{run_id}/ghidra").status_code == 200


def test_worker_rechecks_profile_persists_once_and_reuses_lifecycle(
    tmp_path: Path, monkeypatch: object
) -> None:
    import asyncio
    from typing import cast

    import pytest
    from api_support import ctx_of

    from bytasm.api.analysis import _create_run
    from bytasm.db.models import AnalysisRun, ToolInvocation
    from bytasm.ghidra_protocol import GhidraResult
    from bytasm.jobs import ghidra_step
    from bytasm.jobs.worker import Worker, build_deps
    from bytasm.runner.supervisor import AdapterOutcome

    patch = cast(pytest.MonkeyPatch, monkeypatch)
    settings = make_settings(tmp_path)
    with api_client(settings) as client:
        original_id, digest = seed_document(client)
        ctx = ctx_of(client)
        result = GhidraResult.model_validate_json(ctx.outputs.read_verified(digest))
        with ctx.sessions() as session:
            version = session.get_one(AnalysisRun, original_id).sample_version_id
        run_id = _create_run(ctx, version, "ghidra-static")
        calls = []

        async def analyze(*args: object) -> AdapterOutcome[GhidraResult]:
            calls.append(args)
            return AdapterOutcome(
                status="succeeded", reason="ok", exit_code=0, duration_ms=1, result=result
            )

        patch.setattr(ghidra_step, "analyze", analyze)
        deps, engine = build_deps(settings)
        try:
            worker = Worker(deps, settings.data_dir, asyncio.Event())
            assert asyncio.run(worker.process_next()) == "succeeded"
            assert asyncio.run(worker.process_next()) is None
        finally:
            engine.dispose()
        assert len(calls) == 1
        with ctx.sessions() as session:
            run = session.get_one(AnalysisRun, run_id)
            assert run.status == "succeeded"
            assert len(run.invocations) == 1
            assert run.invocations[0].tool_name == "ghidra"
            assert run.invocations[0].summary is not None
            assert run.invocations[0].summary["function_count"] == 1
            assert run.invocations[0].args["provider_host"]["os"] in ("darwin", "linux")
            invocation = session.get_one(ToolInvocation, run.invocations[0].id)
            assert invocation.raw_output_sha256
        assert list(ctx.tmp_dir.iterdir()) == []
        assert client.get(f"/api/v1/runs/{run_id}/ghidra").json()["available"] is True
        run_view = client.get(f"/api/v1/runs/{run_id}")
        assert run_view.status_code == 200
        assert run_view.json()["steps"][0]["strings"] is None
        assert not any(
            "ghidra reported 0 rule matches" in line for line in run_view.json()["summary"]
        )


def test_project_cleanup_retries_without_logging_paths(tmp_path: Path, monkeypatch: object) -> None:
    import shutil
    from typing import cast

    import pytest

    from bytasm.jobs import ghidra_step

    patch = cast(pytest.MonkeyPatch, monkeypatch)
    folder = tmp_path / "private-project"
    folder.mkdir()
    remove = shutil.rmtree
    attempts = []

    def retry(path: Path) -> None:
        attempts.append(path)
        if len(attempts) == 1:
            raise PermissionError("private path not logged")
        remove(path)

    patch.setattr(shutil, "rmtree", retry)
    assert ghidra_step.cleanup_workdir(folder) is True
    assert len(attempts) == 2 and not folder.exists()
