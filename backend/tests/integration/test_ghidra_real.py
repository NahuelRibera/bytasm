"""Opt-in real offline Ghidra health and admitted fixture extraction.

Run only in an explicitly configured non-root, offline, resource-limited Linux
worker with a <=512 MiB tmpfs for pytest's basetemp. No fixture is executed.
"""

import asyncio
import hashlib
import os
from pathlib import Path

import pytest

from bytasm.ghidra import GhidraConfiguration
from bytasm.ghidra_provider import analyze, isolation_status, provider_health
from bytasm.runner import workspace

pytestmark = pytest.mark.skipif(
    os.environ.get("BYTASM_TEST_REAL_GHIDRA") != "1",
    reason="Real Ghidra verification requires explicit offline-worker opt-in and caller tools",
)
REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_SHA256 = "23bd6f9ee9dc6691bb6f4f7d0ab28a60f84ba4eb4e38b2ed8e88f0cc9bba4c80"


@pytest.mark.parametrize(
    "fixture_name,language",
    [
        ("hello_v1-x86_64.elf", "x86:LE:64:default"),
        ("hello_v1-aarch64.elf", "AARCH64:LE:64:v8A"),
        ("hello_v1-x86_64.exe", "x86:LE:64:default"),
    ],
)
def test_real_no_sample_health_and_authorized_static_fixture(
    tmp_path: Path,
    fixture_name: str,
    language: str,
) -> None:
    config = GhidraConfiguration.from_env()
    assert isolation_status() is None, "Run inside the documented offline Linux worker"
    health = asyncio.run(provider_health(config, tmp_path))
    assert health["health_check"] == "passed" and health["analysis_enabled"], health
    assert not list(tmp_path.iterdir()), "Self-check project/preferences must be removed"
    data = (REPO_ROOT / "fixtures/bin" / fixture_name).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    manifest = (REPO_ROOT / "fixtures/MANIFEST.sha256").read_text()
    assert f"{digest}  bin/{fixture_name}" in manifest
    work = workspace.create_workdir(tmp_path)
    try:
        sample = workspace.write_input(work, data)
        assert sample.stat().st_mode & 0o111 == 0
        outcome = asyncio.run(analyze(config, work, digest, lambda: False))
        assert outcome.status == "succeeded", outcome.reason
        result = outcome.result
        assert result is not None and result.input_sha256 == digest
        assert result.ghidra_version == "12.2"
        assert result.schema_version == "ghidra-3"
        assert any(f.body_ranges for f in result.functions if not f.external)
        assert any(f.references for f in result.functions)
        for function in result.functions:
            instructions = {(i.address.space, i.address.address) for i in function.instructions}
            assert all(
                (r.source.space, r.source.address) in instructions for r in function.references
            )
            assert all(r.provenance == "ghidra_instruction_reference" for r in function.references)
        assert result.language_id == language
        assert result.function_count >= len(result.functions) > 0
        assert any(f.pseudocode_status == "available" and f.pseudocode for f in result.functions)
        assert any(f.instructions for f in result.functions)
        assert any(f.calls for f in result.functions)
        assert all(f.entry.space and f.entry.address for f in result.functions)
        assert result.script_sha256 and result.profile_sha256
        assert result.provider_host != "unavailable"
    finally:
        workspace.remove_workdir(work)
    assert not list(tmp_path.iterdir())


def test_real_import_worker_summary_function_and_export(tmp_path: Path) -> None:
    """The actual API queues the actual worker; no provider output is substituted."""
    import json
    import subprocess
    import sys
    import time

    from api_support import api_client, create_project, do_import, make_settings

    config = GhidraConfiguration.from_env()
    settings = make_settings(tmp_path, ghidra=config)
    assert isolation_status() is None
    with api_client(settings) as client:
        project = create_project(client)
        data = (REPO_ROOT / "fixtures/bin/hello_v1-x86_64.elf").read_bytes()
        assert hashlib.sha256(data).hexdigest() == FIXTURE_SHA256
        imported = do_import(client, project, data)
        assert imported.status_code == 201
        version = imported.json()["sample_version"]["id"]
        env = {
            **os.environ,
            "BYTASM_DATA_DIR": str(settings.data_dir),
            "BYTASM_INPUT_POLICY": "fixtures",
        }
        worker = subprocess.Popen(  # noqa: S603 - fixed application, never sample
            [sys.executable, "-I", "-m", "bytasm", "worker"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        try:
            deadline = time.monotonic() + 100
            status_path = settings.data_dir / "ghidra-health.json"
            while not (settings.data_dir / "worker.heartbeat").exists():
                assert worker.poll() is None, "Worker exited during actual startup"
                assert time.monotonic() < deadline, "Worker health deadline"
                time.sleep(0.1)
            health = json.loads(status_path.read_text())
            assert health["available"] and health["analysis_enabled"]
            tools = client.get("/api/v1/tools").json()
            assert any(p["id"] == "ghidra-static" for p in tools["profiles"])
            queued = client.post(
                f"/api/v1/sample-versions/{version}/runs",
                json={"profile_id": "ghidra-static"},
            )
            assert queued.status_code == 202
            run_id = queued.json()["id"]
            deadline = time.monotonic() + 200
            while True:
                run = client.get(f"/api/v1/runs/{run_id}").json()
                if run["status"] not in ("queued", "running"):
                    break
                assert worker.poll() is None and time.monotonic() < deadline
                time.sleep(0.2)
            assert run["status"] == "succeeded", run["status"]
            base = f"/api/v1/runs/{run_id}/ghidra"
            overview = client.get(base).json()
            assert overview["project_id"] == project and overview["version_id"] == version
            assert overview["available"] and overview["coverage"] == {"completed": 1, "total": 1}
            inventory = client.get(base + "/functions?limit=1").json()
            assert len(inventory["items"]) == 1 and inventory["total"] > 0
            detail = client.get(base + "/functions/0").json()
            assert detail["function"]["entry"]["space"]
            assert detail["function"]["pseudocode_status"] == "available"
            canonical = client.get(base + "/export?format=json")
            assert canonical.status_code == 200
            assert canonical.json()["overview"] == overview
            assert canonical.content == client.get(base + "/export?format=json").content
            rendered = client.get(base + "/export?format=html")
            assert (
                rendered.status_code == 200
                and "default-src 'none'" in rendered.headers["Content-Security-Policy"]
            )
            assert "<script" not in rendered.text
            assert list(settings.tmp_dir.iterdir()) == []
            # Inspect a verified inventory entry outside the initial detail set.
            full = client.get(base + "/functions?limit=100").json()
            candidates = [
                item
                for item in full["items"]
                if item["pseudocode_status"] == "not_selected" and not item["external"]
            ]
            assert candidates, "The fixture must exercise on-demand internal detail"
            index = candidates[-1]["index"]
            selected = client.post(base + "/inspections", json={"indices": [0, index]})
            assert selected.status_code == 202
            selected_id = selected.json()["run_id"]
            assert selected_id != run_id and not selected.json()["reused"]
            duplicate = client.post(base + "/inspections", json={"indices": [0, index]})
            assert duplicate.json()["run_id"] == selected_id and duplicate.json()["reused"]
            deadline = time.monotonic() + 200
            while True:
                selected_run = client.get(f"/api/v1/runs/{selected_id}").json()
                if selected_run["status"] not in ("queued", "running"):
                    break
                assert worker.poll() is None and time.monotonic() < deadline
                time.sleep(0.2)
            assert selected_run["status"] == "succeeded", selected_run["status"]
            selected_base = f"/api/v1/runs/{selected_id}/ghidra"
            selected_detail = client.get(selected_base + f"/functions/{index}").json()
            assert selected_detail["function"]["entry"] == candidates[-1]["entry"]
            assert selected_detail["function"]["pseudocode_status"] == "available"
            # Ghidra can reconstruct a function without retaining any listing
            # instructions. Verify the other selected, populated function too.
            populated = client.get(selected_base + "/functions/0").json()["function"]
            assert populated["pseudocode_status"] == "available" and populated["instructions"]
            selected_overview = client.get(selected_base).json()
            assert selected_overview["source_run_id"] == run_id
            assert selected_overview["detailed_functions"] == 2
            assert {tuple(entry.values()) for entry in selected_overview["selected_entries"]} == {
                tuple(detail["function"]["entry"].values()),
                tuple(candidates[-1]["entry"].values()),
            }
            graph = client.get(selected_base + f"/functions/{index}/relationships").json()
            assert graph["center_index"] == index and len(graph["edges"]) <= 32
            export = client.get(selected_base + "/export?format=json")
            assert export.json()["schema_version"] == "bytasm-ghidra-report-2"
            assert export.json()["overview"] == selected_overview
            assert (
                client.get(base + f"/functions/{index}").json()["function"]["pseudocode_status"]
                == "not_selected"
            )
            assert list(settings.tmp_dir.iterdir()) == []
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)


@pytest.mark.parametrize("stop_kind", ["cancel", "timeout"])
def test_real_headless_deadline_cancellation_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stop_kind: str
) -> None:
    """Terminate an actual Headless process, discard output, remove its project."""
    import time
    from dataclasses import replace

    from bytasm import ghidra_provider
    from bytasm.jobs.ghidra_step import cleanup_workdir

    config = GhidraConfiguration.from_env()
    assert isolation_status() is None
    data = (REPO_ROOT / "fixtures/bin/hello_v1-x86_64.elf").read_bytes()
    assert hashlib.sha256(data).hexdigest() == FIXTURE_SHA256
    work = workspace.create_workdir(tmp_path)
    workspace.write_input(work, data)
    started = time.monotonic()
    if stop_kind == "timeout":
        monkeypatch.setattr(
            ghidra_provider, "LIMITS", replace(ghidra_provider.LIMITS, timeout_seconds=0.3)
        )
    try:
        outcome = asyncio.run(
            analyze(
                config,
                work,
                FIXTURE_SHA256,
                lambda: stop_kind == "cancel" and time.monotonic() - started > 2,
            )
        )
        assert outcome.status == ("cancelled" if stop_kind == "cancel" else "timed_out")
        assert outcome.result is None
        assert time.monotonic() - started < 10
    finally:
        assert cleanup_workdir(work)
    assert not list(tmp_path.iterdir())


def test_real_inventory_beyond_256_and_selected_dossier(tmp_path: Path) -> None:
    """A never-executed authored fixture verifies the expanded retention window."""
    config = GhidraConfiguration.from_env()
    assert isolation_status() is None
    data = (REPO_ROOT / "fixtures/bin/inventory_many-x86_64.elf").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == "0148454cba98bda8f1ec99f334cf16c8d570618f669ac4114b1ef22c03454852"
    work = workspace.create_workdir(tmp_path)
    try:
        workspace.write_input(work, data)
        baseline = asyncio.run(analyze(config, work, digest, lambda: False))
        assert baseline.status == "succeeded", baseline.reason
        result = baseline.result
        assert result is not None and 400 < len(result.functions) <= 1024
        assert not result.functions_truncated
        index, fn = next(
            (i, f) for i, f in enumerate(result.functions) if f.name == "inventory_39_9"
        )
        assert index > 256 and fn.pseudocode_status == "not_selected"
    finally:
        workspace.remove_workdir(work)
    work = workspace.create_workdir(tmp_path)
    try:
        workspace.write_input(work, data)
        selected = asyncio.run(analyze(config, work, digest, lambda: False, [fn.entry]))
        assert selected.status == "succeeded", selected.reason
        assert selected.result is not None
        detailed = [f for f in selected.result.functions if f.pseudocode_status != "not_selected"]
        assert len(detailed) == 1
        assert detailed[0].entry == fn.entry and detailed[0].name == "inventory_39_9"
        assert detailed[0].pseudocode_status == "available" and detailed[0].instructions
    finally:
        workspace.remove_workdir(work)
    assert not list(tmp_path.iterdir())
