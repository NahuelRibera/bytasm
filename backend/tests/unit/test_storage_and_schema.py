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
