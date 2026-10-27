"""M5: the JSON report (blueprint 9.1 "Report reproducibility", 2 J9)."""

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from api_support import api_client, create_project, ctx_of, do_import, make_settings, row_counts
from conftest import (
    ALL_FIXTURES,
    ELF_ENTROPY,
    ELF_X86_64,
    PE_X86_64_DLL,
    REPO_ROOT,
    run_cli,
    sha256_of,
)
from fastapi.testclient import TestClient
from generated_inputs import with_elf64_section_renamed
from jsonschema import Draft202012Validator

from bytasm.reports import model

SCHEMA_PATH = REPO_ROOT / "schemas" / "report.schema.json"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with api_client(make_settings(tmp_path)) as test_client:
        yield test_client


def import_fixture(client: TestClient, fixture: Path, **fields: Any) -> dict[str, Any]:
    project = create_project(client, f"Reports {fixture.name}")
    response = do_import(client, project, fixture.read_bytes(), **fields)
    assert response.status_code == 201, response.text
    version: dict[str, Any] = response.json()["sample_version"]
    return version


def export(client: TestClient, version_id: str) -> tuple[dict[str, Any], bytes]:
    created = client.post(f"/api/v1/sample-versions/{version_id}/reports")
    assert created.status_code == 201, created.text
    body: dict[str, Any] = created.json()
    download = client.get(body["download_url"])
    assert download.status_code == 200
    return body, download.content


def keys_anywhere(document: object) -> set[str]:
    if isinstance(document, dict):
        return set(document) | {k for v in document.values() for k in keys_anywhere(v)}
    if isinstance(document, list):
        return {k for item in document for k in keys_anywhere(item)}
    return set()


def test_committed_schema_matches_the_models() -> None:
    committed = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert committed == model.json_schema()
    Draft202012Validator.check_schema(committed)


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_report_validates_and_carries_identity_and_provenance(
    client: TestClient, fixture: Path
) -> None:
    version = import_fixture(client, fixture, declared_filename=fixture.name, version_label="v1")
    created, data = export(client, version["id"])
    assert hashlib.sha256(data).hexdigest() == created["sha256"]
    report = json.loads(data)

    Draft202012Validator(json.loads(SCHEMA_PATH.read_text())).validate(report)
    assert report["report_kind"] == "bytasm.sample_version_report"
    assert report["schema_version"] == 1
    assert report["generator"]["name"] == "bytasm"
    assert report["sample"]["sha256"] == sha256_of(fixture.read_bytes())
    assert report["sample"]["format"] == version["detected_format"]
    assert report["sample"]["declared_filename"] == {
        "value": fixture.name,
        "trust": "untrusted_as_uploaded",
    }
    assert report["sample"]["blob_sha256_verified_at_export"] is True
    assert (
        report["metadata"]["declared_in_header"]["architecture"]
        == version["header"]["architecture"]
    )
    assert report["input_policy"]["admitted_under"] == "fixture_manifest"
    assert report["input_policy"]["manifest_entry"] == f"bin/{fixture.name}"
    assert report["authorization"]["type"] == "self_attestation"
    assert "not proof of permission" in report["authorization"]["notice"]
    (invocation,) = report["analysis"]["tool_invocations"]
    assert invocation["tool"] == "lief" and invocation["tool_version"].startswith("1.0.")
    assert invocation["adapter"] == "metadata_lief"
    assert invocation["result_sha256"] == version["invocation"]["result_sha256"]
    for section in report["metadata"]["sections"]:
        entropy = section["entropy"]
        assert entropy["unit"] == "bits_per_byte"
        assert entropy["method"] == "shannon-bits-per-byte"
        assert entropy["computed_by"] == "bytasm metadata_lief 0.1.0"
        assert (entropy["value"] is None) == (entropy["note"] is not None)
    assert any("did not execute" in item for item in report["limitations"])
    assert any("not a verdict" in item for item in report["limitations"])


def test_report_metadata_matches_the_cli(client: TestClient) -> None:
    cli = json.loads(run_cli("inspect", str(PE_X86_64_DLL)).stdout)
    version = import_fixture(client, PE_X86_64_DLL)
    report = json.loads(export(client, version["id"])[1])
    metadata = report["metadata"]
    assert metadata["declared_in_header"]["fields"] == cli["declared_header"]
    assert metadata["declared_in_header"]["entry_point"] == cli["entry_point"]
    assert [s["name"] for s in metadata["sections"]] == [s["name"] for s in cli["sections"]]
    assert [s["entropy"]["value"] for s in metadata["sections"]] == [
        s["entropy"] for s in cli["sections"]
    ]
    assert metadata["imports"] == cli["imports"]
    assert metadata["exports"] == cli["exports"]


def test_two_exports_differ_only_in_generated_at(client: TestClient) -> None:
    version = import_fixture(client, ELF_ENTROPY)
    _, first = export(client, version["id"])
    _, second = export(client, version["id"])
    a, b = json.loads(first), json.loads(second)
    a.pop("generated_at")
    b.pop("generated_at")
    assert a == b
    # Canonical bytes: sorted keys, fixed indent, so equal data gives equal text.
    assert first.decode().replace(
        json.loads(first)["generated_at"], "T"
    ) == second.decode().replace(json.loads(second)["generated_at"], "T")
    assert list(json.loads(first)) == sorted(json.loads(first))


def test_report_contains_no_verdict_fields_or_local_paths(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        version = import_fixture(client, ELF_ENTROPY)
        text = export(client, version["id"])[1].decode()
    keys = keys_anywhere(json.loads(text))
    for word in ("verdict", "score", "risk", "malicious", "benign", "safe", "severity"):
        assert not any(word in key for key in keys), word
    assert str(tmp_path) not in text
    assert str(REPO_ROOT) not in text


def test_entropy_measurement_on_the_high_entropy_fixture(client: TestClient) -> None:
    version = import_fixture(client, ELF_ENTROPY)
    sections = {
        s["name"]: s for s in json.loads(export(client, version["id"])[1])["metadata"]["sections"]
    }
    assert sections[".blob"]["entropy"]["value"] > 7.9
    assert sections[".bss"]["entropy"] == {
        "value": None,
        "unit": "bits_per_byte",
        "method": "shannon-bits-per-byte",
        "computed_by": "bytasm metadata_lief 0.1.0",
        "measured_over": "section_bytes_in_file",
        "note": "no file data",
    }


def test_download_is_an_attachment(client: TestClient) -> None:
    version = import_fixture(client, ELF_X86_64)
    created = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
    response = client.get(created["download_url"])
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-disposition"].startswith("attachment; filename=")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-bytasm-report-sha256"] == created["sha256"]


def test_blob_hash_mismatch_refuses_the_export(client: TestClient) -> None:
    version = import_fixture(client, ELF_X86_64)
    ctx = ctx_of(client)
    blob = ctx.blobs.path(version["sha256"])
    blob.chmod(0o600)
    blob.write_bytes(blob.read_bytes() + b"tampered")
    response = client.post(f"/api/v1/sample-versions/{version['id']}/reports")
    assert response.status_code == 409
    assert response.json()["code"] == "integrity_error"
    assert "Nothing was exported" in response.json()["detail"]
    assert row_counts(ctx)["report"] == 0
    assert not any(ctx.reports.root.rglob("*.json")) and not [
        p for p in ctx.reports.root.rglob("*") if p.is_file()
    ]


def test_missing_blob_or_raw_output_refuses_the_export(client: TestClient) -> None:
    version = import_fixture(client, ELF_X86_64)
    ctx = ctx_of(client)
    ctx.outputs.remove(version["invocation"]["result_sha256"])
    response = client.post(f"/api/v1/sample-versions/{version['id']}/reports")
    assert response.status_code == 409
    assert row_counts(ctx)["report"] == 0


def test_tampered_report_file_is_not_served(client: TestClient) -> None:
    version = import_fixture(client, ELF_X86_64)
    created = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
    path = ctx_of(client).reports.path(created["sha256"])
    path.chmod(0o600)
    path.write_text("{}")
    response = client.get(created["download_url"])
    assert response.status_code == 409
    assert response.json()["code"] == "integrity_error"


def test_unknown_version_and_report_are_404(client: TestClient) -> None:
    assert client.post(f"/api/v1/sample-versions/{'0' * 32}/reports").status_code == 404
    assert client.get(f"/api/v1/reports/{'0' * 32}/download").status_code == 404


def test_report_creation_requires_the_custom_header(client: TestClient) -> None:
    version = import_fixture(client, ELF_X86_64)
    client.headers.pop("X-Bytasm-Request")
    response = client.post(f"/api/v1/sample-versions/{version['id']}/reports")
    assert response.status_code == 403


def test_self_built_report_records_policy_and_keeps_hostile_names_as_data(tmp_path: Path) -> None:
    hostile = '<script>alert("bytasm")</script>'
    data = with_elf64_section_renamed(ELF_X86_64.read_bytes(), b".comment", hostile.encode())
    with api_client(make_settings(tmp_path, input_policy="self_built")) as client:
        project = create_project(client)
        version = do_import(client, project, data, declared_filename=hostile).json()[
            "sample_version"
        ]
        report = json.loads(export(client, version["id"])[1])
    assert report["input_policy"]["admitted_under"] == "self_built_optin"
    assert report["input_policy"]["manifest_entry"] is None
    assert hostile in [s["name"] for s in report["metadata"]["sections"]]
    assert report["sample"]["declared_filename"]["value"] == hostile
