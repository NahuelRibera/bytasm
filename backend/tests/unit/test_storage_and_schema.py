"""Content-addressed storage and the database schema."""

import hashlib
import stat
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from bytasm.db.models import U64, Base
from bytasm.db.session import create_sqlite_engine, upgrade_to_head
from bytasm.storage import ContentStore, IntegrityError


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_place_and_read_verified(tmp_path: Path) -> None:
    store = ContentStore(tmp_path / "blobs")
    source = tmp_path / "upload.bin"
    source.write_bytes(b"hello")
    sha = _sha(b"hello")
    assert store.place(source, sha) is True
    path = store.path(sha)
    assert path == tmp_path / "blobs" / "sha256" / sha[:2] / sha[2:4] / sha
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert store.read_verified(sha) == b"hello"

    again = tmp_path / "again.bin"
    again.write_bytes(b"hello")
    assert store.place(again, sha) is False  # identical bytes already stored
    assert again.exists()


def test_tampered_or_missing_file_fails_verification(tmp_path: Path) -> None:
    store = ContentStore(tmp_path)
    sha = _sha(b"original")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    store.put_bytes(b"original", sha, scratch)
    path = store.path(sha)
    path.chmod(0o600)
    path.write_bytes(b"tampered")
    with pytest.raises(IntegrityError):
        store.read_verified(sha)
    with pytest.raises(IntegrityError):
        store.verify(sha)
    path.unlink()
    with pytest.raises(IntegrityError):
        store.read_verified(sha)


def test_corrupt_copy_is_replaced_on_place(tmp_path: Path) -> None:
    store = ContentStore(tmp_path / "s")
    sha = _sha(b"good")
    store.path(sha).parent.mkdir(parents=True)
    store.path(sha).write_bytes(b"bad")
    source = tmp_path / "good.bin"
    source.write_bytes(b"good")
    assert store.place(source, sha) is True
    assert store.read_verified(sha) == b"good"


@pytest.mark.parametrize("bad", ["../../etc/passwd", "A" * 64, "abc", "g" * 64])
def test_paths_come_only_from_a_valid_hash(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError):
        ContentStore(tmp_path).path(bad)


def test_put_bytes_refuses_mismatched_hash(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError):
        ContentStore(tmp_path).put_bytes(b"data", "0" * 64, tmp_path)


def test_migrations_match_the_models(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "db.sqlite3")
    upgrade_to_head(engine)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        assert compare_metadata(context, Base.metadata) == []


@pytest.mark.parametrize("value", [0, 1, 2**63 - 1, 2**63, 2**64 - 1])
def test_u64_round_trips_full_unsigned_range(value: int) -> None:
    column = U64()
    stored = column.process_bind_param(value, None)  # type: ignore[arg-type]
    assert stored is not None and -(2**63) <= stored < 2**63
    assert column.process_result_value(stored, None) == value  # type: ignore[arg-type]


def test_u64_refuses_out_of_range() -> None:
    with pytest.raises(ValueError):
        U64().process_bind_param(2**64, None)  # type: ignore[arg-type]


def test_verified_output_crosses_scratch_filesystem_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import errno
    import os

    from bytasm.storage import ContentStore

    store = ContentStore(tmp_path / "outputs")
    scratch = tmp_path / "tmpfs"
    scratch.mkdir()
    data = b"bounded validated tool document"
    digest = hashlib.sha256(data).hexdigest()
    replace = os.replace
    attempts = []

    def cross_device(source: object, target: object) -> None:
        source_path = Path(str(source))
        attempts.append(source_path)
        if source_path.parent == scratch:
            raise OSError(errno.EXDEV, "Cross-device rename")
        assert source_path.parent == store.path(digest).parent
        assert source_path.stat().st_mode & 0o777 == 0o400
        replace(source_path, Path(str(target)))

    monkeypatch.setattr(os, "replace", cross_device)
    assert store.put_bytes(data, digest, scratch)
    assert len(attempts) == 2
    assert store.read_verified(digest) == data
    assert not list(scratch.iterdir())
    assert not list(store.path(digest).parent.glob("*.part"))
    assert not store.put_bytes(data, digest, scratch)


def test_cross_device_failure_cleans_staging_without_replacing_old_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import errno
    import os

    store = ContentStore(tmp_path / "outputs")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    data = b"verified replacement"
    digest = _sha(data)
    target = store.path(digest)
    target.parent.mkdir(parents=True)
    target.write_bytes(b"old corrupt bytes")

    def refuse(source: object, destination: object) -> None:
        code = errno.EXDEV if Path(str(source)).parent == scratch else errno.ENOSPC
        raise OSError(code, "Bounded test transfer failure")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(OSError):
        store.put_bytes(data, digest, scratch)
    assert target.read_bytes() == b"old corrupt bytes"
    assert not list(scratch.iterdir())
    assert list(target.parent.iterdir()) == [target]


def test_stale_destination_staging_cleanup_keeps_fresh_and_unrelated_files(tmp_path: Path) -> None:
    import os
    import time

    store = ContentStore(tmp_path / "outputs")
    directory = store.path("a" * 64).parent
    directory.mkdir(parents=True)
    old = directory / ("." + "a" * 64 + ".abcdefgh.part")
    fresh = directory / ("." + "a" * 64 + ".12345678.part")
    unrelated = directory / "analyst-notes.part"
    for file in (old, fresh, unrelated):
        file.write_bytes(b"private validated output")
    for file in (old, unrelated):
        os.utime(file, (time.time() - 7200,) * 2)
    link = directory / ("." + "b" * 64 + ".abcdefgh.part")
    link.symlink_to(unrelated)
    assert store.remove_stale_staging(3600) == 1
    assert not old.exists()
    assert fresh.is_file() and unrelated.is_file() and link.is_symlink()


def test_staging_cleanup_tolerates_a_concurrent_publisher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentStore(tmp_path / "outputs")
    directory = store.path("a" * 64).parent
    directory.mkdir(parents=True)
    stage = directory / ("." + "a" * 64 + ".abcdefgh.part")
    stage.write_bytes(b"verified bytes")
    lstat = Path.lstat

    def published(path: Path, *, follow_symlinks: bool = False) -> object:
        if path == stage:
            stage.unlink()
            raise FileNotFoundError
        return lstat(path)

    monkeypatch.setattr(Path, "lstat", published)
    assert store.remove_stale_staging(3600) == 0
    assert not stage.exists()
