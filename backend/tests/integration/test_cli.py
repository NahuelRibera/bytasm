"""Run the real `bytasm inspect` command against the committed fixtures."""

import json
from pathlib import Path

import pytest
from conftest import ALL_FIXTURES, ELF_ENTROPY, REPO_ROOT, run_cli, sha256_of

# file name -> (format, architecture, (declared_header key, value), entry_point)
EXPECTED = {
    "capa_environment-x86_64.exe": ("PE", "x86_64", ("pe_machine", "AMD64"), 0x1400013F0),
    "hello_v1-aarch64.elf": ("ELF", "aarch64", ("elf_file_type", "DYN"), 0x660),
    "hello_v1-aarch64-stripped.elf": ("ELF", "aarch64", ("elf_file_type", "DYN"), 0x660),
    "entropy_blob-aarch64.elf": ("ELF", "aarch64", ("elf_file_type", "DYN"), 0x660),
    "hello_v1-x86_64.o": ("ELF", "x86_64", ("elf_file_type", "REL"), None),
    "hello_v1-x86_64.elf": ("ELF", "x86_64", ("elf_file_type", "DYN"), 0x1050),
    "hello_v2-x86_64.elf": ("ELF", "x86_64", ("elf_file_type", "DYN"), 0x1060),
    "inventory_many-x86_64.elf": ("ELF", "x86_64", ("elf_file_type", "DYN"), 0x1040),
    "hello_v1-x86_64-stripped.elf": ("ELF", "x86_64", ("elf_file_type", "DYN"), 0x1050),
    "hello_v1-x86_64.exe": ("PE", "x86_64", ("pe_machine", "AMD64"), 0x1_4000_13F0),
    "exports_v1-x86_64.dll": ("PE", "x86_64", ("pe_machine", "AMD64"), 0x1_E01E_1330),
}

TOP_LEVEL_KEYS = {
    "adapter",
    "architecture",
    "bitness",
    "bytasm_version",
    "declared_header",
    "endianness",
    "entry_point",
    "exports",
    "file",
    "format",
    "imports",
    "input_policy",
    "notes",
    "report_kind",
    "schema_version",
    "sections",
    "warnings",
}
SECTION_KEYS = {
    "name",
    "type",
    "file_offset",
    "file_size",
    "virtual_address",
    "declared_size",
    "flags",
    "entropy",
    "entropy_note",
}


def test_every_listed_fixture_has_expectations() -> None:
    assert {p.name for p in ALL_FIXTURES} == set(EXPECTED)


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_listed_fixture_produces_expected_json(fixture: Path) -> None:
    result = run_cli("inspect", str(fixture))
    assert result.returncode == 0, result.stdout
    assert result.stderr == b""

    report = json.loads(result.stdout)
    assert set(report) == TOP_LEVEL_KEYS
    assert report["report_kind"] == "bytasm.inspect"
    assert report["file"] == {
        "sha256": sha256_of(fixture.read_bytes()),
        "size_bytes": fixture.stat().st_size,
    }
    assert report["input_policy"] == {
        "mode": "fixtures",
        "admitted_under": "fixture_manifest",
        "manifest_entry": f"bin/{fixture.name}",
    }
    assert report["adapter"]["parser"] == "lief"
    assert report["adapter"]["parser_version"].startswith("1.0.")

    file_format, architecture, (header_key, header_value), entry_point = EXPECTED[fixture.name]
    assert report["format"] == file_format
    assert report["architecture"] == architecture
    assert report["bitness"] == 64
    assert report["endianness"] == "little"
    assert report["declared_header"][header_key] == header_value
    assert report["entry_point"] == entry_point

    assert report["sections"], "every fixture has sections"
    for section in report["sections"]:
        assert set(section) == SECTION_KEYS
        entropy = section["entropy"]
        assert entropy is None or 0.0 <= entropy <= 8.0


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_repeated_inspection_is_byte_identical(fixture: Path) -> None:
    first = run_cli("inspect", str(fixture))
    second = run_cli("inspect", str(fixture))
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout


def test_output_does_not_depend_on_path_or_file_name(tmp_path: Path) -> None:
    absolute = run_cli("inspect", str(ELF_ENTROPY))
    relative = run_cli("inspect", "fixtures/bin/entropy_blob-aarch64.elf", cwd=REPO_ROOT)
    copied = tmp_path / "copy-with-another-name"
    copied.write_bytes(ELF_ENTROPY.read_bytes())
    elsewhere = run_cli("inspect", str(copied))

    assert absolute.returncode == relative.returncode == elsewhere.returncode == 0
    assert absolute.stdout == relative.stdout == elsewhere.stdout
    assert str(REPO_ROOT).encode() not in absolute.stdout
    assert str(tmp_path).encode() not in elsewhere.stdout


def test_output_contains_no_verdict() -> None:
    for fixture in ALL_FIXTURES:
        text = run_cli("inspect", str(fixture)).stdout.decode().lower()
        for word in ("verdict", "malicious", "benign", '"safe"', "is safe"):
            assert word not in text


def test_unknown_file_is_refused_with_json_error(tmp_path: Path) -> None:
    unknown = tmp_path / "notes.txt"
    unknown.write_text("not a fixture\n", encoding="utf-8")
    result = run_cli("inspect", str(unknown))
    assert result.returncode == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "unknown_hash"
    assert sha256_of(unknown.read_bytes()) in error["message"]


@pytest.mark.parametrize(
    ("setup", "code", "exit_code"),
    [
        ("missing", "file_not_found", 1),
        ("directory", "file_not_found", 1),
        ("empty", "empty_file", 2),
    ],
)
def test_operational_and_empty_inputs(
    tmp_path: Path, setup: str, code: str, exit_code: int
) -> None:
    target = tmp_path / "target"
    if setup == "directory":
        target.mkdir()
    elif setup == "empty":
        target.write_bytes(b"")
    result = run_cli("inspect", str(target))
    assert result.returncode == exit_code
    assert json.loads(result.stdout)["error"]["code"] == code


def test_usage_error_without_path() -> None:
    result = run_cli("inspect")
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"usage:" in result.stderr
