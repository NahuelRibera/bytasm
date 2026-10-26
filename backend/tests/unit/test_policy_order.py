"""The manifest check happens before identification and before LIEF.

These tests are the evidence for the fixtures-only rule: a file whose hash is
not listed never reaches the parser.
"""

import subprocess
import sys
from pathlib import Path

import pytest
from conftest import ALL_FIXTURES, ELF_AARCH64, PE_X86_64_DLL, run_cli

import bytasm.inspection
from bytasm.adapters import metadata_lief
from bytasm.errors import UNKNOWN_HASH, InspectError
from bytasm.intake.manifest import Manifest


def _fail_if_called(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("the parser path was reached for a file not in the manifest")


@pytest.fixture
def parser_spies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metadata_lief, "extract_metadata", _fail_if_called)
    monkeypatch.setattr(bytasm.inspection, "identify_format", _fail_if_called)


def _modified_copy(tmp_path: Path, fixture: Path = ELF_AARCH64) -> Path:
    data = bytearray(fixture.read_bytes())
    data[-1] ^= 0xFF  # one changed byte gives a different SHA-256
    path = tmp_path / fixture.name
    path.write_bytes(bytes(data))
    return path


@pytest.mark.usefixtures("parser_spies")
@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_modified_fixture_is_rejected_before_parsing(
    tmp_path: Path, manifest: Manifest, fixture: Path
) -> None:
    with pytest.raises(InspectError) as caught:
        bytasm.inspection.inspect_file(_modified_copy(tmp_path, fixture), manifest)
    assert caught.value.code == UNKNOWN_HASH


@pytest.mark.usefixtures("parser_spies")
def test_appended_byte_to_pe_fixture_is_rejected_before_parsing(
    tmp_path: Path, manifest: Manifest
) -> None:
    """Overlay data after the last section still changes the hash."""
    path = tmp_path / PE_X86_64_DLL.name
    path.write_bytes(PE_X86_64_DLL.read_bytes() + b"\x00")
    with pytest.raises(InspectError) as caught:
        bytasm.inspection.inspect_file(path, manifest)
    assert caught.value.code == UNKNOWN_HASH


@pytest.mark.usefixtures("parser_spies")
@pytest.mark.parametrize(
    "content",
    [b"\x7fELF" + bytes(60), b"MZ" + bytes(100), b"PK\x03\x04zip", b"plain text\n"],
    ids=["elf-magic", "mz-magic", "zip", "text"],
)
def test_unlisted_files_are_rejected_before_parsing(
    tmp_path: Path, manifest: Manifest, content: bytes
) -> None:
    path = tmp_path / "unlisted.bin"
    path.write_bytes(content)
    with pytest.raises(InspectError) as caught:
        bytasm.inspection.inspect_file(path, manifest)
    assert caught.value.code == UNKNOWN_HASH


@pytest.mark.parametrize("fixture", [ELF_AARCH64, PE_X86_64_DLL], ids=lambda p: p.name)
def test_rejected_file_never_loads_lief(tmp_path: Path, fixture: Path) -> None:
    """In a fresh interpreter, refusing a file must not even import LIEF."""
    script = (
        "import sys\n"
        "from bytasm.cli import main\n"
        "code = main(['inspect', sys.argv[1]])\n"
        "print('LIEF_LOADED=' + str('lief' in sys.modules))\n"
        "print('EXIT=' + str(code))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(_modified_copy(tmp_path, fixture))],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert '"code": "unknown_hash"' in result.stdout
    assert "LIEF_LOADED=False" in result.stdout
    assert "EXIT=2" in result.stdout


def test_cli_rejects_modified_fixture_with_controlled_error(tmp_path: Path) -> None:
    result = run_cli("inspect", str(_modified_copy(tmp_path)))
    assert result.returncode == 2
    assert b'"code": "unknown_hash"' in result.stdout
    assert b"The file was not parsed." in result.stdout
    assert result.stderr == b""


def test_admission_depends_on_bytes_not_on_name(tmp_path: Path, manifest: Manifest) -> None:
    renamed = tmp_path / "renamed-anything.txt"
    renamed.write_bytes(ELF_AARCH64.read_bytes())
    report = bytasm.inspection.inspect_file(renamed, manifest)
    assert report["input_policy"]["manifest_entry"] == "bin/hello_v1-aarch64.elf"


def test_oversized_file_is_refused_before_hashing(tmp_path: Path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"\x00" * 11)
    with pytest.raises(InspectError) as caught:
        bytasm.inspection.read_bounded(path, limit=10)
    assert caught.value.code == "file_too_large"
    assert bytasm.inspection.read_bounded(path, limit=11) == b"\x00" * 11
