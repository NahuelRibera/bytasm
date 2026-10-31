"""M3: the import endpoint (blueprint 9.1 "Input policy", "Upload validation & lifecycle").

Only committed fixtures and bytes generated in memory are used. Nothing is
executed.
"""

import io
import json
import os
import stat
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from api_support import (
    STATEMENT,
    api_client,
    assert_nothing_imported,
    create_project,
    ctx_of,
    do_import,
    fake_adapter,
    import_headers,
    make_settings,
    row_counts,
    stored_files,
    temp_entries,
)
from conftest import (
    ALL_FIXTURES,
    ELF_AARCH64,
    ELF_X86_64,
    PE_X86_64_DLL,
    PE_X86_64_EXE,
    run_cli,
    sha256_of,
)
from fastapi.testclient import TestClient
from generated_inputs import minimal_pe64, truncated, with_elf64_section_renamed
from sqlalchemy.orm import Session

import bytasm.api.imports
from bytasm.intake.import_metadata import encode_import_header
from bytasm.runner.limits import ParserLimits

HOSTILE_NAME = '<script>alert("bytasm")</script>'

# file name -> (format, architecture)
EXPECTED = {
    "capa_environment-x86_64.exe": ("PE", "x86_64"),
    "hello_v1-aarch64.elf": ("ELF", "aarch64"),
    "hello_v1-aarch64-stripped.elf": ("ELF", "aarch64"),
    "entropy_blob-aarch64.elf": ("ELF", "aarch64"),
    "hello_v1-x86_64.o": ("ELF", "x86_64"),
    "hello_v1-x86_64.elf": ("ELF", "x86_64"),
    "hello_v2-x86_64.elf": ("ELF", "x86_64"),
    "inventory_many-x86_64.elf": ("ELF", "x86_64"),
    "hello_v1-x86_64-stripped.elf": ("ELF", "x86_64"),
    "hello_v1-x86_64.exe": ("PE", "x86_64"),
    "exports_v1-x86_64.dll": ("PE", "x86_64"),
}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with api_client(make_settings(tmp_path)) as test_client:
        yield test_client


@pytest.fixture
def project(client: TestClient) -> str:
    return create_project(client)


@pytest.fixture
def parser_spy(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Records every attempt to start the adapter child (and fails it)."""
    calls: list[object] = []

    async def spy(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise AssertionError("the parser was started")

    monkeypatch.setattr(bytasm.api.imports, "run_adapter", spy)
    return calls


class BodySpy:
    """A streamed request body that records whether the server read it."""

    def __init__(self, data: bytes, chunk: int = 4096) -> None:
        self.data = data
        self.chunk = chunk
        self.read = False

    def __iter__(self) -> Iterator[bytes]:
        self.read = True
        for start in range(0, len(self.data), self.chunk):
            yield self.data[start : start + self.chunk]


# --- default fixtures mode --------------------------------------------------


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_every_fixture_is_imported_with_expected_metadata(
    client: TestClient, project: str, fixture: Path
) -> None:
    data = fixture.read_bytes()
    response = do_import(
        client, project, data, sample_name=fixture.stem, declared_filename=fixture.name
    )
    assert response.status_code == 201, response.text
    version = response.json()["sample_version"]
    file_format, architecture = EXPECTED[fixture.name]
    assert version["sha256"] == sha256_of(data)
    assert version["size_bytes"] == len(data)
    assert version["detected_format"] == file_format
    assert version["header"]["architecture"] == architecture
    assert version["admitted_under"] == "fixture_manifest"
    assert version["manifest_entry"] == f"bin/{fixture.name}"
    assert version["authorization"]["basis"] == "owned_or_built"
    assert version["authorization"]["statement"] == STATEMENT
    assert version["authorization"]["type"] == "self_attestation"
    assert "not proof of permission" in version["authorization"]["notice"]
    assert version["invocation"]["tool"] == "lief"
    assert version["invocation"]["status"] == "succeeded"
    assert temp_entries(ctx_of(client)) == []


def test_imported_metadata_matches_the_cli_report(client: TestClient, project: str) -> None:
    cli = json.loads(run_cli("inspect", str(PE_X86_64_DLL)).stdout)
    version = do_import(client, project, PE_X86_64_DLL.read_bytes()).json()["sample_version"]
    vid = version["id"]
    sections = client.get(f"/api/v1/sample-versions/{vid}/sections").json()["sections"]
    assert [s["name"] for s in sections] == [s["name"] for s in cli["sections"]]
    assert [s["entropy"] for s in sections] == [s["entropy"] for s in cli["sections"]]
    assert [s["raw_size"] for s in sections] == [s["file_size"] for s in cli["sections"]]
    imports = client.get(f"/api/v1/sample-versions/{vid}/imports").json()
    assert imports == cli["imports"]
    exports = client.get(f"/api/v1/sample-versions/{vid}/exports").json()
    assert exports["functions"] == cli["exports"]
    assert version["header"]["declared_header"] == cli["declared_header"]
    assert version["header"]["entry_point"] == cli["entry_point"]


@pytest.mark.usefixtures("parser_spy")
@pytest.mark.parametrize(
    "data",
    [
        ELF_AARCH64.read_bytes()[:-1] + bytes([ELF_AARCH64.read_bytes()[-1] ^ 0xFF]),
        PE_X86_64_EXE.read_bytes() + b"\x00",  # appended overlay byte
        minimal_pe64(),  # a valid PE that is not in the manifest
    ],
    ids=["modified-elf", "appended-pe", "generated-pe"],
)
def test_file_not_in_manifest_is_refused_before_parsing(
    client: TestClient, project: str, data: bytes, parser_spy: list[object]
) -> None:
    response = do_import(client, project, data)
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == "input_policy"
    assert "not parsed or stored" in body["detail"]
    assert parser_spy == []
    assert_nothing_imported(ctx_of(client))
    assert row_counts(ctx_of(client))["sample"] == 0


def test_admission_depends_on_bytes_not_on_name(client: TestClient, project: str) -> None:
    response = do_import(client, project, ELF_AARCH64.read_bytes(), declared_filename="renamed.txt")
    assert response.status_code == 201
    assert response.json()["sample_version"]["manifest_entry"] == "bin/hello_v1-aarch64.elf"


# --- metadata header, validated before the body ------------------------------


@pytest.mark.parametrize(
    "header",
    [
        None,
        "not base64 !!!",
        encode_import_header({"sample_name": "x"}),  # no authorization
        encode_import_header(  # basis other than owned_or_built
            {
                "sample_name": "x",
                "authorization": {"basis": "written_permission", "statement": "ok"},
            }
        ),
        encode_import_header(  # empty statement
            {"sample_name": "x", "authorization": {"basis": "owned_or_built", "statement": " "}}
        ),
        encode_import_header(  # both targets
            {
                "sample_name": "x",
                "sample_id": "0" * 32,
                "authorization": {"basis": "owned_or_built", "statement": "s"},
            }
        ),
        encode_import_header(  # no such field: requests cannot change the policy
            {
                "sample_name": "x",
                "input_policy": "self_built",
                "authorization": {"basis": "owned_or_built", "statement": "s"},
            }
        ),
        "A" * (8 * 1024 + 1),
    ],
    ids=[
        "missing",
        "not-base64",
        "no-authorization",
        "other-basis",
        "empty-statement",
        "two-targets",
        "policy-field",
        "too-long",
    ],
)
def test_invalid_import_metadata_is_refused_before_reading_the_body(
    client: TestClient, project: str, header: str | None, parser_spy: list[object]
) -> None:
    body = BodySpy(ELF_AARCH64.read_bytes())
    headers = {"Content-Type": "application/octet-stream"}
    if header is not None:
        headers["X-Bytasm-Import"] = header
    response = client.post(f"/api/v1/projects/{project}/imports", content=body, headers=headers)
    assert response.status_code == 422
    assert response.json()["code"] == "invalid_import_metadata"
    assert not body.read, "the body was read before the metadata was validated"
    assert parser_spy == []
    assert_nothing_imported(ctx_of(client))


def test_unknown_project_is_refused_before_reading_the_body(client: TestClient) -> None:
    body = BodySpy(ELF_AARCH64.read_bytes())
    response = client.post(
        f"/api/v1/projects/{'0' * 32}/imports", content=body, headers=import_headers()
    )
    assert response.status_code == 404
    assert not body.read


def test_wrong_content_type_is_refused(client: TestClient, project: str) -> None:
    headers = import_headers()
    headers["Content-Type"] = "multipart/form-data; boundary=x"
    body = BodySpy(ELF_AARCH64.read_bytes())
    response = client.post(f"/api/v1/projects/{project}/imports", content=body, headers=headers)
    assert response.status_code == 415
    assert response.json()["code"] == "unsupported_media_type"
    assert not body.read


def test_request_headers_cannot_switch_the_policy(
    client: TestClient, project: str, parser_spy: list[object]
) -> None:
    headers = import_headers()
    headers |= {"X-Bytasm-Input-Policy": "self_built", "X-Input-Policy": "self_built"}
    response = client.post(
        f"/api/v1/projects/{project}/imports", content=minimal_pe64(), headers=headers
    )
    assert response.status_code == 403
    assert client.get("/api/v1/health").json()["input_policy"]["mode"] == "fixtures"
    assert parser_spy == []


def test_no_endpoint_can_change_the_input_policy(client: TestClient) -> None:
    """The complete v0.1 + v0.2 API surface. Nothing in it touches configuration."""
    spec = client.get("/api/openapi.json").json()
    routes = {(path, method) for path, item in spec["paths"].items() for method in item}
    assert routes == {
        # Pinned reviews and exact-function analyst overlays cannot alter admission.
        ("/api/v1/reviews/{left_id}/compare/{right_id}", "get"),
        ("/api/v1/sample-versions/{version_id}/reviews", "get"),
        ("/api/v1/sample-versions/{version_id}/reviews", "post"),
        ("/api/v1/reviews/{review_id}", "get"),
        ("/api/v1/reviews/{review_id}/refresh", "post"),
        ("/api/v1/reviews/{review_id}/export/{format}", "post"),
        ("/api/v1/sample-versions/{version_id}/bytes", "get"),
        ("/api/v1/runs/{run_id}/ghidra/functions/{index}/review", "get"),
        ("/api/v1/runs/{run_id}/ghidra/functions/{index}/review", "post"),
        ("/api/v1/health", "get"),
        ("/api/v1/tools", "get"),
        ("/api/v1/reports/{report_id}/review", "get"),
        ("/api/v1/reports/{report_id}/html", "get"),
        ("/api/v1/sample-versions/{version_id}/reports", "get"),
        ("/api/v1/compare", "get"),
        ("/api/v1/annotations", "get"),
        ("/api/v1/annotations", "post"),
        ("/api/v1/annotations/{annotation_id}/revisions", "get"),
        ("/api/v1/annotations/{annotation_id}/revisions", "post"),
        ("/api/v1/sample-versions/{version_id}/citation-targets", "get"),
        ("/api/v1/projects", "get"),
        ("/api/v1/projects", "post"),
        ("/api/v1/projects/{project_id}", "get"),
        ("/api/v1/projects/{project_id}/samples", "get"),
        ("/api/v1/projects/{project_id}/activity", "get"),
        ("/api/v1/projects/{project_id}/imports", "post"),
        ("/api/v1/sample-versions/{version_id}", "get"),
        ("/api/v1/sample-versions/{version_id}/sections", "get"),
        ("/api/v1/sample-versions/{version_id}/imports", "get"),
        ("/api/v1/sample-versions/{version_id}/exports", "get"),
        ("/api/v1/sample-versions/{version_id}/reports", "post"),
        ("/api/v1/reports/{report_id}/download", "get"),
        # v0.2: the bundled rule set is read-only; runs and findings.
        ("/api/v1/rule-sets/current", "get"),
        ("/api/v1/rule-sets/current/validation", "post"),
        ("/api/v1/rule-sets/{rule_set_id}", "get"),
        ("/api/v1/sample-versions/{version_id}/runs", "post"),
        ("/api/v1/sample-versions/{version_id}/runs", "get"),
        ("/api/v1/runs/{run_id}", "get"),
        ("/api/v1/runs/{run_id}/cancel", "post"),
        ("/api/v1/runs/{run_id}/findings", "get"),
        ("/api/v1/runs/{run_id}/log", "get"),
        # v0.5: read-only scoped Ghidra evidence; admission has no new controls.
        ("/api/v1/runs/{run_id}/ghidra", "get"),
        ("/api/v1/runs/{run_id}/ghidra/functions", "get"),
        ("/api/v1/runs/{run_id}/ghidra/functions/{index}", "get"),
        ("/api/v1/runs/{run_id}/ghidra/export", "get"),
        ("/api/v1/runs/{run_id}/ghidra/inspections", "post"),
        ("/api/v1/runs/{run_id}/ghidra/functions/{index}/relationships", "get"),
        # v0.2: read-only views of stored results.
        ("/api/v1/sample-versions/{version_id}/strings", "get"),
        ("/api/v1/invocations/{invocation_id}/raw", "get"),
    }


# --- size limits, empty and wrong-format bodies -------------------------------


def test_declared_oversize_is_refused_without_reading(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path, max_upload_bytes=1024)) as client:
        project = create_project(client)
        body = BodySpy(b"\x7fELF" + bytes(4000))
        headers = import_headers() | {"Content-Length": "4004"}
        response = client.post(f"/api/v1/projects/{project}/imports", content=body, headers=headers)
        assert response.status_code == 413
        assert response.json()["code"] == "upload_too_large"
        assert response.headers["connection"] == "close"
        assert not body.read
        assert_nothing_imported(ctx_of(client))


@pytest.mark.usefixtures("parser_spy")
def test_empty_body_is_refused(client: TestClient, project: str) -> None:
    response = do_import(client, project, b"")
    assert response.status_code == 422
    assert response.json()["code"] == "empty_file"
    assert_nothing_imported(ctx_of(client))


@pytest.mark.usefixtures("parser_spy")
@pytest.mark.parametrize(
    ("data", "words"),
    [
        (b"PK\x03\x04" + bytes(200), "ZIP archive"),
        (b"plain text, not a binary\n", "Unrecognised"),
        (b"\xcf\xfa\xed\xfe" + bytes(60), "Mach-O"),
        (b"M", "Unrecognised"),
    ],
    ids=["zip", "text", "macho", "too-short"],
)
def test_wrong_format_is_refused_early(
    client: TestClient, project: str, data: bytes, words: str
) -> None:
    response = do_import(client, project, data)
    assert response.status_code == 415
    assert response.json()["code"] == "unsupported_format"
    assert words in response.json()["detail"]
    assert_nothing_imported(ctx_of(client))


def test_renamed_zip_fixture_copy_is_rejected_by_content(client: TestClient, project: str) -> None:
    """A ZIP whose declared name says .exe is still a ZIP (OWASP: never trust the name)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("hello.exe", PE_X86_64_EXE.read_bytes())
    response = do_import(client, project, buffer.getvalue(), declared_filename="hello.exe")
    assert response.status_code == 415
    assert "ZIP" in response.json()["detail"]


# --- duplicates, samples, busy slot -------------------------------------------


def test_duplicate_in_sample_is_refused_without_parsing(
    client: TestClient, project: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = ELF_AARCH64.read_bytes()
    first = do_import(client, project, data, version_label="v1").json()["sample_version"]
    calls: list[object] = []

    async def spy(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise AssertionError("parsed a duplicate")

    monkeypatch.setattr(bytasm.api.imports, "run_adapter", spy)
    response = do_import(client, project, data, sample_id=first["sample_id"])
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == "duplicate_version"
    assert body["existing_version_id"] == first["id"]
    assert "v1" in body["detail"]
    assert calls == []
    assert row_counts(ctx_of(client))["sample_version"] == 1


def test_same_bytes_in_another_sample_reuse_the_blob(client: TestClient, project: str) -> None:
    data = ELF_AARCH64.read_bytes()
    assert do_import(client, project, data, sample_name="a").status_code == 201
    assert do_import(client, project, data, sample_name="b").status_code == 201
    ctx = ctx_of(client)
    assert row_counts(ctx)["sample_version"] == 2
    blobs = [p for p in stored_files(ctx) if p.is_relative_to(ctx.blobs.root)]
    assert len(blobs) == 1


def test_new_version_of_an_existing_sample(client: TestClient, project: str) -> None:
    first = do_import(client, project, ELF_AARCH64.read_bytes(), version_label="v1").json()
    sample_id = first["sample_version"]["sample_id"]
    second = do_import(
        client, project, ELF_X86_64.read_bytes(), sample_id=sample_id, version_label="v2"
    )
    assert second.status_code == 201
    samples = client.get(f"/api/v1/projects/{project}/samples").json()
    assert [v["version_label"] for v in samples[0]["versions"]] == ["v1", "v2"]


def test_sample_name_collision_is_refused(client: TestClient, project: str) -> None:
    assert do_import(client, project, ELF_AARCH64.read_bytes()).status_code == 201
    response = do_import(client, project, ELF_X86_64.read_bytes())
    assert response.status_code == 409
    assert response.json()["code"] == "sample_exists"


def test_busy_parser_slot_returns_503_without_reading(client: TestClient, project: str) -> None:
    slot = ctx_of(client).parser_slot
    assert slot.try_acquire()
    try:
        body = BodySpy(ELF_AARCH64.read_bytes())
        response = client.post(
            f"/api/v1/projects/{project}/imports", content=body, headers=import_headers()
        )
        assert response.status_code == 503
        assert response.headers["retry-after"] == "5"
        assert "Another file is being validated" in response.json()["detail"]
        assert not body.read
    finally:
        slot.release()
    assert do_import(client, project, ELF_AARCH64.read_bytes()).status_code == 201


# --- storage ---------------------------------------------------------------------


def test_files_are_stored_by_hash_read_only_outside_served_paths(
    client: TestClient, project: str
) -> None:
    data = ELF_AARCH64.read_bytes()
    response = do_import(client, project, data, declared_filename="../../etc/passwd")
    assert response.status_code == 201
    assert response.json()["sample_version"]["declared_filename"] == "../../etc/passwd"
    ctx = ctx_of(client)
    sha = sha256_of(data)
    blob = ctx.blobs.root / "sha256" / sha[:2] / sha[2:4] / sha
    assert blob.read_bytes() == data
    assert stat.S_IMODE(blob.stat().st_mode) == 0o400
    assert stat.S_IMODE(ctx.settings.data_dir.stat().st_mode) == 0o700
    assert not any("passwd" in str(p) for p in ctx.settings.data_dir.rglob("*"))
    # The data directory is not reachable over HTTP.
    assert client.get(f"/data/blobs/sha256/{sha[:2]}/{sha[2:4]}/{sha}").status_code == 503
    assert client.get("/api/v1/../../data/bytasm.sqlite3").status_code in (404, 503)


def test_data_survives_a_restart(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    with api_client(settings) as client:
        project = create_project(client)
        vid = do_import(client, project, ELF_AARCH64.read_bytes()).json()["sample_version"]["id"]
    with api_client(settings) as client:
        assert client.get(f"/api/v1/sample-versions/{vid}").status_code == 200
        assert client.get("/api/v1/projects").json()[0]["sample_count"] == 1


# --- failures after admission: nothing persisted ----------------------------------


@pytest.mark.parametrize(
    ("behaviour", "code"),
    [
        ("hang", "parse_timeout"),
        ("exit1", "adapter_failed"),
        ("reject_known", "parse_failed"),
        ("reject_unknown", "adapter_failed"),
        ("invalid_json", "adapter_failed"),
        ("huge_stdout", "adapter_failed"),
        ("fork_orphan", "adapter_failed"),
    ],
)
def test_adapter_failure_persists_nothing(tmp_path: Path, behaviour: str, code: str) -> None:
    limits = ParserLimits(timeout_seconds=1, kill_grace_seconds=0.5, pipe_close_seconds=0.5)
    settings = make_settings(tmp_path, limits=limits)
    with api_client(settings, fake_adapter(behaviour)) as client:
        project = create_project(client)
        response = do_import(client, project, ELF_AARCH64.read_bytes())
        assert response.status_code == 422
        body = response.json()
        assert body["code"] == code
        assert "It was not imported" in body["detail"]
        # Adapter output is never echoed.
        assert "not a known code" not in response.text
        assert_nothing_imported(ctx_of(client))
        assert not ctx_of(client).parser_slot.busy


def test_commit_failure_leaves_no_orphan_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_commit(self: Session) -> None:
        raise RuntimeError("simulated commit failure")

    with api_client(make_settings(tmp_path), raise_server_exceptions=False) as client:
        project = create_project(client)
        monkeypatch.setattr(Session, "commit", failing_commit)
        response = do_import(client, project, ELF_AARCH64.read_bytes())
        monkeypatch.undo()
        assert response.status_code == 500
        assert response.json()["code"] == "internal_error"
        assert "simulated" not in response.text
        assert_nothing_imported(ctx_of(client))
        assert not ctx_of(client).parser_slot.busy


def test_failure_to_create_the_work_directory_frees_the_parser_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_space(root: Path) -> Path:
        raise OSError("simulated: no space left on device")

    with api_client(make_settings(tmp_path), raise_server_exceptions=False) as client:
        project = create_project(client)
        monkeypatch.setattr("bytasm.api.imports.workspace.create_workdir", no_space)
        response = do_import(client, project, ELF_AARCH64.read_bytes())
        monkeypatch.undo()
        assert response.status_code == 500
        assert response.json()["code"] == "internal_error"
        assert "simulated" not in response.text
        assert not ctx_of(client).parser_slot.busy
        assert do_import(client, project, ELF_AARCH64.read_bytes()).status_code == 201


# --- self_built mode (local configuration only) -----------------------------------


def test_self_built_is_off_by_default(client: TestClient) -> None:
    policy = client.get("/api/v1/health").json()["input_policy"]
    assert policy == {"mode": "fixtures", "self_built_enabled": False}


def test_self_built_mode_admits_test_authored_bytes_and_records_it(tmp_path: Path) -> None:
    hostile = with_elf64_section_renamed(
        ELF_X86_64.read_bytes(), b".comment", HOSTILE_NAME.encode()
    )
    with api_client(make_settings(tmp_path, input_policy="self_built")) as client:
        assert client.get("/api/v1/health").json()["input_policy"]["self_built_enabled"]
        project = create_project(client)
        response = do_import(client, project, hostile, sample_name="hostile")
        assert response.status_code == 201, response.text
        version = response.json()["sample_version"]
        assert version["admitted_under"] == "self_built_optin"
        assert version["manifest_entry"] is None
        sections = client.get(f"/api/v1/sample-versions/{version['id']}/sections").json()
        assert HOSTILE_NAME in [s["name"] for s in sections["sections"]]

        fixture = do_import(client, project, ELF_AARCH64.read_bytes(), sample_name="fixture")
        assert fixture.json()["sample_version"]["admitted_under"] == "fixture_manifest"


@pytest.mark.usefixtures("parser_spy")
def test_malformed_input_is_refused_by_bytasm_before_parsing(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path, input_policy="self_built")) as client:
        project = create_project(client)
        response = do_import(client, project, truncated(ELF_AARCH64.read_bytes(), 40))
        assert response.status_code == 422
        assert response.json()["code"] == "malformed_input"
        assert_nothing_imported(ctx_of(client))


# --- start-up sweep --------------------------------------------------------------


def test_startup_sweep_removes_stale_temp_dirs_and_orphan_blobs(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    with api_client(settings) as client:
        project = create_project(client)
        kept = sha256_of(ELF_AARCH64.read_bytes())
        do_import(client, project, ELF_AARCH64.read_bytes())
        ctx = ctx_of(client)
        orphan = sha256_of(b"orphan")
        orphan_path = ctx.blobs.path(orphan)
        orphan_path.parent.mkdir(parents=True)
        orphan_path.write_bytes(b"orphan")
        fresh = sha256_of(b"fresh")
        ctx.blobs.path(fresh).parent.mkdir(parents=True)
        ctx.blobs.path(fresh).write_bytes(b"fresh")
        stale_tmp = ctx.tmp_dir / "stale"
        stale_tmp.mkdir()
        (stale_tmp / "upload.bin").write_bytes(b"x")
        old = 1_000_000_000
        os.utime(orphan_path, (old, old))
        os.utime(stale_tmp, (old, old))
        os.utime(ctx.blobs.path(kept), (old, old))

    with api_client(settings) as client:
        ctx = ctx_of(client)
        assert not orphan_path.exists()
        assert not stale_tmp.exists()
        assert ctx.blobs.path(kept).exists(), "a referenced blob was swept"
        assert ctx.blobs.path(fresh).exists(), "a recent file was swept"
