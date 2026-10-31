"""Exact scoped inventory and selected jobs, with synthetic stored records."""

from pathlib import Path

import pytest
from api_support import api_client, ctx_of, make_settings
from test_ghidra_api import seed_document

from bytasm.db.models import AnalysisRun
from bytasm.function_selection import SelectionRefused, queue_selection


@pytest.mark.parametrize("terminal", ["failed", "cancelled"])
def test_selection_reuses_exact_job_and_retries_terminal_failures(
    tmp_path: Path,
    terminal: str,
) -> None:
    with api_client(make_settings(tmp_path)) as client:
        source, _ = seed_document(client)
        ctx = ctx_of(client)
        queued, reused = queue_selection(ctx, source, [0])
        assert not reused and queued != source
        assert queue_selection(ctx, source, [0]) == (queued, True)
        with ctx.sessions() as session:
            original = session.get_one(AnalysisRun, source)
            new = session.get_one(AnalysisRun, queued)
            assert new.sample_version_id == original.sample_version_id
            assert new.profile_snapshot["source_run_id"] == source
            assert new.profile_snapshot["selected_indices"] == [0]
            options = new.profile_snapshot["steps"][0]["options"]
            assert options["selected_entries"] == [{"space": "ram", "address": "00401000"}]
            assert options["max_functions"] == 1024
            assert original.status == "succeeded" and len(original.invocations) == 1
            new.status = terminal
            session.commit()
        retry, reused = queue_selection(ctx, source, [0])
        assert retry != queued and not reused


@pytest.mark.parametrize("indices", [[], [1], [0, 0], [-1], [True], list(range(9))])
def test_invalid_selection_never_creates_a_run(tmp_path: Path, indices: list[int]) -> None:
    with api_client(make_settings(tmp_path)) as client:
        source, _ = seed_document(client)
        with pytest.raises(SelectionRefused) as failure:
            queue_selection(ctx_of(client), source, indices)
        assert failure.value.code == "invalid_request"


def test_selected_endpoint_requires_actual_provider_and_bounded_request(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        source, _ = seed_document(client)
        url = f"/api/v1/runs/{source}/ghidra/inspections"
        assert client.post(url, json={"indices": [0]}).status_code == 503
        assert client.post(url, json={"indices": [True]}).status_code == 422
        assert client.post(url, json={"indices": list(range(9))}).status_code == 422
        assert client.post(url, json={"indices": [0], "script": "arbitrary"}).status_code == 422
        assert (
            client.post("/api/v1/runs/absent/ghidra/inspections", json={"indices": [0]}).status_code
            == 404
        )


def test_inventory_search_facets_and_cursor_cross_run_refusal(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        source, _ = seed_document(client, capped=True)
        base = f"/api/v1/runs/{source}/ghidra/functions"
        for query in (
            "q=Global&field=namespace&exact=true",
            "q=ram:00401000&field=address&exact=true",
            "pseudocode=available",
            "has_calls=false",
            "external=false",
        ):
            page = client.get(base + "?" + query).json()
            assert page["matched"] == 1
            assert page["identified"] == 2 and not page["inventory_complete"]
            assert page["functions_truncated"] and len(page["scope_sha256"]) == 64
        assert client.get(base + "?field=unknown").status_code == 422
        assert client.get(base + "?cursor=hostile!").status_code == 422
        assert client.get(base + "?cursor=" + "x" * 257).status_code == 422
        second, _ = seed_document(client)
        other = client.get(f"/api/v1/runs/{second}/ghidra/functions").json()
        assert other["scope_sha256"] != client.get(base).json()["scope_sha256"]


def test_selected_worker_stores_explicit_details_and_exact_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from bytasm.ghidra_protocol import Address, GhidraResult
    from bytasm.ghidra_provider import profile_digest
    from bytasm.jobs import ghidra_step
    from bytasm.jobs.worker import Worker, build_deps
    from bytasm.runner.supervisor import AdapterOutcome

    settings = make_settings(tmp_path)
    with api_client(settings) as client:
        source, digest = seed_document(client)
        ctx = ctx_of(client)
        queued, _ = queue_selection(ctx, source, [0])
        result = GhidraResult.model_validate_json(ctx.outputs.read_verified(digest))
        entries = [result.functions[0].entry]
        result.profile_sha256 = profile_digest(entries)
        result.schema_version = "ghidra-2"
        observed = []

        async def analyze(
            config: object, work: Path, sha: str, cancel: object, selected: list[Address]
        ) -> AdapterOutcome[GhidraResult]:
            observed.append(selected)
            return AdapterOutcome(
                status="succeeded", reason="ok", exit_code=0, duration_ms=1, result=result
            )

        monkeypatch.setattr(ghidra_step, "analyze", analyze)
        deps, engine = build_deps(settings)
        try:
            assert (
                asyncio.run(Worker(deps, settings.data_dir, asyncio.Event()).process_next())
                == "succeeded"
            )
        finally:
            engine.dispose()
        assert observed == [entries]
        assert queue_selection(ctx, source, [0]) == (queued, True)
        detail = client.get(f"/api/v1/runs/{queued}/ghidra/functions/0").json()
        assert detail["function"]["pseudocode_status"] == "available"
        assert not list(ctx.tmp_dir.iterdir())
        report = client.get(f"/api/v1/runs/{queued}/ghidra/export?format=html")
        assert report.status_code == 200
        assert "Function inventory" in report.text and "Selected function dossiers" in report.text
        assert "return &lt;hostile&gt;" in report.text and "<script" not in report.text


def test_selection_isolated_between_projects_and_invalid_output_refused(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        first, digest = seed_document(client)
        second, _ = seed_document(client)
        ctx = ctx_of(client)
        first_job, _ = queue_selection(ctx, first, [0])
        second_job, _ = queue_selection(ctx, second, [0])
        assert first_job != second_job
        with ctx.sessions() as session:
            a = session.get_one(AnalysisRun, first_job)
            b = session.get_one(AnalysisRun, second_job)
            assert a.sample_version.sample.project_id != b.sample_version.sample.project_id
        path = ctx.outputs.path(digest)
        path.chmod(0o600)
        path.write_bytes(b"{}")
        with pytest.raises(SelectionRefused) as failure:
            queue_selection(ctx, first, [0])
        assert failure.value.code == "integrity_error"
        for suffix in ("/functions", "/functions/0/relationships"):
            assert client.get(f"/api/v1/runs/{first}/ghidra" + suffix).status_code == 409


def test_relationship_api_bounds_and_missing_function(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        source, _ = seed_document(client)
        base = f"/api/v1/runs/{source}/ghidra/functions/0/relationships"
        response = client.get(base)
        assert response.status_code == 200
        assert response.json()["edges"] == []
        for query in ("edge_limit=65", "node_limit=34", "node_limit=1", "edge_limit=0"):
            assert client.get(base + "?" + query).status_code == 422
        assert client.get(base.replace("/0/", "/1024/")).status_code == 404


def test_concurrent_selection_requests_record_one_job(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    with api_client(make_settings(tmp_path)) as client:
        source, _ = seed_document(client)
        ctx = ctx_of(client)
        barrier = Barrier(2)

        def request() -> tuple[str, bool]:
            barrier.wait(timeout=5)
            return queue_selection(ctx, source, [0])

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(request), pool.submit(request)]
            results = [future.result(timeout=10) for future in futures]
        assert results[0][0] == results[1][0]
        assert sorted(reused for _, reused in results) == [False, True]


def test_export_bound_is_an_explicit_cap_not_integrity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bytasm.api import ghidra

    with api_client(make_settings(tmp_path)) as client:
        source, _ = seed_document(client)
        monkeypatch.setattr(ghidra, "MAX_EXPORT_BYTES", 1)
        for format in ("json", "html"):
            response = client.get(f"/api/v1/runs/{source}/ghidra/export?format={format}")
            assert response.status_code == 413
            assert response.json()["type"].endswith("report_too_large")
            assert "hostile" not in response.text
