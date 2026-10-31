"""Pinned capa compatibility and the complete admitted sample → worker → API path."""

from pathlib import Path

import pytest
from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import CAPA_PE, ELF_X86_64
from test_analysis import process

from bytasm.annotations import resolve_target


def test_capa_positive_full_profile_and_raw_provenance(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        imported = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        created = client.post(
            f"/api/v1/sample-versions/{imported['id']}/runs", json={"profile_id": "full-static"}
        )
        assert created.status_code == 202, created.text
        run = created.json()
        assert process(ctx_of(client)) == "succeeded"
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert [s["status"] for s in result["steps"]] == ["succeeded"] * 3
        capa = result["steps"][-1]
        findings = client.get(f"/api/v1/runs/{run['id']}/findings?tool=capa").json()["findings"]
        assert [f["rule_id"] for f in findings] == ["query environment variable"]
        rules = client.get(f"/api/v1/rule-sets/{findings[0]['rule_set_id']}")
        assert rules.status_code == 200
        assert rules.json()["tool"] == "capa" and rules.json()["rule_count"] == 7
        assert rules.json()["installed_tool_version"] == "10.0.0"
        assert [key for key, _ in findings[0]["metadata"]] == ["source", "ATT&CK", "MBC"]
        assert findings[0]["evidence"][0]["virtual_address"] is not None
        assert findings[0]["evidence"][0]["virtual_address_hex"] == "0x140001450"
        assert findings[0]["evidence"][0]["file_offset"] is None
        raw = client.get(f"/api/v1/invocations/{capa['invocation_id']}/raw").json()
        # Actual pinned CLI output, independently of Bytasm's normalizer.
        assert raw["meta"]["version"] == "10.0.0"
        assert raw["meta"]["sample"]["sha256"] == imported["sha256"]
        assert "query environment variable" in raw["rules"]
        assert (
            raw["rules"]["query environment variable"]["matches"][0][0]["value"]
            == findings[0]["evidence"][0]["virtual_address"]
        )
        with ctx_of(client).sessions() as session:
            version, citation = resolve_target(
                session, "evidence", str(findings[0]["evidence"][0]["id"])
            )
            assert version.id == imported["id"] and citation is not None
        exported = client.post(f"/api/v1/sample-versions/{imported['id']}/reports")
        assert exported.status_code == 201, exported.text
        report = client.get(exported.json()["download_url"]).json()
        assert report["schema_version"] == 4
        assert any(f["tool"] == "capa" for f in report["pattern_analysis"]["findings"])


def test_unsupported_capa_preserves_quick_results_and_says_partial(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        assert process(ctx_of(client)) == "partial"
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert result["steps"][-1]["status"] == "unsupported"
        assert result["counts"]["strings"] > 0
        assert result["steps"][-1]["raw_output_sha256"] is None


def test_capa_timeout_preserves_prior_results(tmp_path: Path) -> None:

    from test_analysis import fake_yara

    from bytasm.runner.limits import ParserLimits

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        # The existing fake adapter's hang mode is a real hanging child process.
        assert (
            process(
                ctx_of(client),
                capa_command=fake_yara("hang"),
                limits=ParserLimits(timeout_seconds=2),
            )
            == "partial"
        )
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert result["steps"][-1]["status"] == "timed_out"
        assert [s["status"] for s in result["steps"][:2]] == ["succeeded", "succeeded"]
        assert not list(ctx_of(client).tmp_dir.iterdir())


def test_capa_invalid_output_is_not_a_no_match(tmp_path: Path) -> None:
    from test_analysis import fake_yara

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        assert process(ctx_of(client), capa_command=fake_yara("invalid_json")) == "partial"
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert result["steps"][-1]["status"] == "failed"
        assert result["steps"][-1]["raw_output_sha256"] is None
        assert not client.get(f"/api/v1/runs/{run['id']}/findings?tool=capa").json()["findings"]
        assert not any("capa reported 0" in line for line in result["summary"])


@pytest.mark.parametrize("cancel", [True, False])
def test_admission_and_cancel_before_capa_never_start_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    from typing import Any

    from test_analysis import fake_yara

    from bytasm.jobs import pipeline, runs

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        ctx = ctx_of(client)
        record = pipeline._record

        def record_then_cancel(deps: Any, rid: str, index: int, *rest: Any) -> str:
            status = record(deps, rid, index, *rest)
            if index == 1:
                if cancel:
                    with ctx.sessions() as session:
                        runs.request_cancel(session, rid)
                else:
                    blob = ctx.blobs.path(version["sha256"])
                    blob.chmod(0o600)
                    blob.write_bytes(b"changed after the second verified stage")
            return status

        monkeypatch.setattr(pipeline, "_record", record_then_cancel)
        marker = tmp_path / "capa-started"
        assert process(ctx, capa_command=fake_yara(f"spy:{marker}")) == (
            "cancelled" if cancel else "partial"
        )
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert [step["status"] for step in result["steps"]] == ["succeeded", "succeeded", "skipped"]
        assert result["counts"]["strings"] > 0 and not marker.exists()


def test_tools_are_read_only_and_profiles_snapshot_versions(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        tools = client.get("/api/v1/tools").json()
        assert [tool["tool"] for tool in tools["tools"]] == ["lief", "strings", "yara-x", "capa"]
        assert all(tool["available"] for tool in tools["tools"])
        assert tools["tools"][-1]["version"] == "10.0.0"
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        result = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        from bytasm.db.models import AnalysisRun

        with ctx_of(client).sessions() as session:
            run = session.get_one(AnalysisRun, result["id"])
            assert all(
                step["tool_version"] and step["adapter_version"]
                for step in run.profile_snapshot["steps"]
            )


def test_capa_late_cancellation_discards_step_results_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typing import Any

    from bytasm.jobs import capa_step, runs
    from bytasm.runner.supervisor import run_child

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        ctx = ctx_of(client)

        async def finish_then_cancel(*args: Any, **kwargs: Any) -> Any:
            outcome = await run_child(*args, **kwargs)
            with ctx.sessions() as session:
                runs.request_cancel(session, run["id"])
            return outcome

        monkeypatch.setattr(capa_step, "run_child", finish_then_cancel)
        assert process(ctx) == "cancelled"
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert [step["status"] for step in result["steps"]] == [
            "succeeded",
            "succeeded",
            "cancelled",
        ]
        assert result["counts"]["strings"] > 0
        assert not client.get(f"/api/v1/runs/{run['id']}/findings?tool=capa").json()["findings"]
        assert not list(ctx.tmp_dir.iterdir())


def test_capa_worker_recovery_marks_missing_third_step_partial(tmp_path: Path) -> None:
    from bytasm.db.models import AnalysisRun, ToolInvocation
    from bytasm.jobs import runs

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        with ctx_of(client).sessions() as session:
            row = session.get_one(AnalysisRun, run["id"])
            row.status = "running"
            for index, tool in enumerate(("strings", "yara-x")):
                session.add(
                    ToolInvocation(
                        run_id=row.id,
                        step_index=index,
                        tool_name=tool,
                        adapter_name=tool,
                        tool_version="test",
                        adapter_version="test",
                        status="succeeded",
                        duration_ms=1,
                        args={},
                        warnings=[],
                    )
                )
            session.commit()
            assert runs.fail_interrupted_runs(session) == 1
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert result["status"] == "partial"
        assert [step["status"] for step in result["steps"]] == ["succeeded", "succeeded", "skipped"]
        assert "worker" in result["failure_message"]


def test_unavailable_tool_is_persisted_without_a_false_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from importlib.metadata import PackageNotFoundError

    from bytasm.jobs import capa_step

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()

        def missing(package: str) -> str:
            raise PackageNotFoundError(package)

        monkeypatch.setattr(capa_step, "version", missing)
        assert process(ctx_of(client)) == "partial"
        result = client.get(f"/api/v1/runs/{run['id']}").json()
        assert result["steps"][-1]["status"] == "unavailable"
        assert result["steps"][-1]["tool_version"] == "unavailable"
        assert result["steps"][-1]["raw_output_sha256"] is None


def test_downgrade_refuses_to_discard_capa_citations(tmp_path: Path) -> None:
    from sqlalchemy import text

    from bytasm.db.session import migrate

    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, CAPA_PE.read_bytes()).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{version['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        ctx = ctx_of(client)
        assert process(ctx) == "succeeded"
        finding = client.get(f"/api/v1/runs/{run['id']}/findings?tool=capa").json()["findings"][0]
        note = client.post(
            "/api/v1/annotations",
            json={
                "target_type": "evidence",
                "target_id": str(finding["evidence"][0]["id"]),
                "kind": "note",
                "body": "Retain this exact virtual address reference.",
            },
        )
        assert note.status_code == 201
        record = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
        raw = client.get(record["download_url"]).content
        with pytest.raises(RuntimeError, match="Cannot downgrade while capa evidence exists"):
            migrate(ctx.engine, "0005", downgrade=True)
        assert client.get(record["download_url"]).content == raw
        with ctx.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0009"
            )


AUTHORED_POSITIVES = (
    ("capa_create_process-x86_64.exe", "create process via Windows API", "create-process.yml"),
    ("capa_http_request-x86_64.exe", "send HTTP request via Windows API", "send-http-request.yml"),
    ("capa_read_file-x86_64.exe", "read file via Windows API", "read-file.yml"),
    (
        "capa_read_configuration-x86_64.exe",
        "read INI configuration via Windows API",
        "read-configuration.yml",
    ),
    ("capa_load_library-x86_64.exe", "load library via Windows API", "load-library.yml"),
)


@pytest.mark.parametrize("fixture,rule,filename", AUTHORED_POSITIVES)
def test_authored_rule_matches_compiled_call_site(
    tmp_path: Path, fixture: str, rule: str, filename: str
) -> None:
    """Actual capa over a never-executed, self-authored PE; no injected features."""
    from conftest import FIXTURES_DIR

    from bytasm import capa_rules

    data = (FIXTURES_DIR / "bin" / fixture).read_bytes()
    with api_client(make_settings(tmp_path)) as client:
        imported = do_import(client, create_project(client), data).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{imported['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        assert process(ctx_of(client)) == "succeeded"
        steps = client.get(f"/api/v1/runs/{run['id']}").json()["steps"]
        assert [s["status"] for s in steps] == ["succeeded"] * 3
        findings = client.get(f"/api/v1/runs/{run['id']}/findings?tool=capa").json()["findings"]
        assert [f["rule_id"] for f in findings] == [rule]
        # The authored noinline helper; independently checked with objdump.
        assert [e["virtual_address_hex"] for e in findings[0]["evidence"]] == ["0x140001450"]
        rules = client.get(f"/api/v1/rule-sets/{findings[0]['rule_set_id']}").json()
        assert rules["sha256"] == capa_rules.snapshot()[1]
        raw = client.get(f"/api/v1/invocations/{steps[-1]['invocation_id']}/raw").json()
        assert raw["meta"]["sample"]["sha256"] == imported["sha256"]
        assert list(raw["rules"]) == [rule]
        # The filename differs from the rule name; the exact packaged text is kept.
        assert raw["rules"][rule]["source"] == (capa_rules.RULES_DIR / filename).read_text()
        assert raw["rules"][rule]["matches"][0][0] == {"type": "absolute", "value": 0x140001450}


@pytest.mark.parametrize(
    "fixture", ["capa_control_unrelated-x86_64.exe", "capa_control_reference-x86_64.exe"]
)
def test_benign_controls_have_no_capa_match(tmp_path: Path, fixture: str) -> None:
    """Unrelated calls, API names as text and stored-but-uncalled imports do not match."""
    from conftest import FIXTURES_DIR

    data = (FIXTURES_DIR / "bin" / fixture).read_bytes()
    with api_client(make_settings(tmp_path)) as client:
        imported = do_import(client, create_project(client), data).json()["sample_version"]
        run = client.post(
            f"/api/v1/sample-versions/{imported['id']}/runs", json={"profile_id": "full-static"}
        ).json()
        assert process(ctx_of(client)) == "succeeded"
        steps = client.get(f"/api/v1/runs/{run['id']}").json()["steps"]
        assert [s["status"] for s in steps] == ["succeeded"] * 3
        assert client.get(f"/api/v1/runs/{run['id']}/findings?tool=capa").json()["findings"] == []
        raw = client.get(f"/api/v1/invocations/{steps[-1]['invocation_id']}/raw").json()
        assert raw["rules"] == {}


def test_compiled_match_reaches_pinned_answer_and_private_export(tmp_path: Path) -> None:
    from conftest import FIXTURES_DIR

    data = (FIXTURES_DIR / "bin" / "capa_read_file-x86_64.exe").read_bytes()
    with api_client(make_settings(tmp_path)) as client:
        imported = do_import(client, create_project(client), data).json()["sample_version"]
        client.post(
            f"/api/v1/sample-versions/{imported['id']}/runs", json={"profile_id": "full-static"}
        )
        assert process(ctx_of(client)) == "succeeded"
        review = client.post(f"/api/v1/sample-versions/{imported['id']}/reviews", json={})
        assert review.status_code == 201, review.text
        pinned = review.json()
        observation = next(
            o for o in pinned["observations"] if o["rule_id"] == "read file via Windows API"
        )
        files = next(a for a in pinned["answers"] if a["id"] == "files")
        matched = [o for o in files["observations"] if o["level"] == "static_rule_match"]
        assert [o["evidence"]["finding_id"] for o in matched] == [observation["finding_id"]]
        exported = client.post(f"/api/v1/reviews/{pinned['id']}/export/json", json={})
        assert exported.status_code == 200, exported.text
        answer = next(a for a in exported.json()["answers"] if a["id"] == "files")
        assert any(o["level"] == "static_rule_match" for o in answer["observations"])
        assert client.get(f"/api/v1/reviews/{pinned['id']}").json() == pinned
