"""The committed manifest must match the committed fixture bytes exactly."""

from pathlib import Path

import pytest
from conftest import ALL_FIXTURES, FIXTURES_DIR, MANIFEST_PATH, sha256_of

from bytasm.errors import MANIFEST_ERROR, InspectError
from bytasm.intake.manifest import Manifest


def test_every_listed_fixture_exists_and_matches_its_hash(manifest: Manifest) -> None:
    for sha256, relative_path in manifest.entries.items():
        assert sha256_of((FIXTURES_DIR / relative_path).read_bytes()) == sha256


def test_every_committed_fixture_is_listed(manifest: Manifest) -> None:
    listed = set(manifest.entries.values())
    on_disk = {f"bin/{p.name}" for p in (FIXTURES_DIR / "bin").iterdir() if p.is_file()}
    assert on_disk == listed
    assert {f"bin/{p.name}" for p in ALL_FIXTURES} == listed


def test_fixtures_are_small_and_not_marked_executable() -> None:
    for fixture in ALL_FIXTURES:
        assert fixture.stat().st_size < 100 * 1024
        assert fixture.stat().st_mode & 0o111 == 0, f"{fixture.name} has an executable bit"


def test_lookup_returns_path_for_listed_hash_and_none_otherwise(manifest: Manifest) -> None:
    fixture = ALL_FIXTURES[0]
    assert manifest.lookup(sha256_of(fixture.read_bytes())) == f"bin/{fixture.name}"
    assert manifest.lookup("0" * 64) is None


@pytest.mark.parametrize(
    "content",
    [
        "",
        "# only a comment\n",
        "not-a-hash  bin/x\n",
        "ABCDEF" + "0" * 58 + "  bin/uppercase-hex\n",
        "0" * 64 + "\n",
    ],
)
def test_malformed_manifest_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "MANIFEST.sha256"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InspectError) as caught:
        Manifest.load(path)
    assert caught.value.code == MANIFEST_ERROR


def test_missing_manifest_is_an_operational_error(tmp_path: Path) -> None:
    with pytest.raises(InspectError) as caught:
        Manifest.load(tmp_path / "missing.sha256")
    assert caught.value.code == MANIFEST_ERROR
    assert caught.value.exit_code == 1


def test_manifest_uses_shasum_format() -> None:
    for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
        digest, path = line.split("  ", 1)
        assert len(digest) == 64
        assert path.startswith("bin/")
