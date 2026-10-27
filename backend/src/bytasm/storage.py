"""Content-addressed file stores: `<root>/sha256/<aa>/<bb>/<sha256>` (blueprint 5.5).

Paths come only from the SHA-256, never from a user-supplied name. Files are
read-only (0400) and directories private (0700). The data directory is never
served over HTTP; files leave it only through API endpoints that re-verify
the hash first.
"""

import hashlib
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Final

_HEX: Final = frozenset("0123456789abcdef")


class IntegrityError(Exception):
    """A stored file is missing or no longer matches its SHA-256."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _check_sha(sha256: str) -> None:
    if len(sha256) != 64 or not set(sha256) <= _HEX:
        raise ValueError("not a lowercase hex SHA-256")


class ContentStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def relative_path(self, sha256: str) -> str:
        _check_sha(sha256)
        return f"sha256/{sha256[:2]}/{sha256[2:4]}/{sha256}"

    def path(self, sha256: str) -> Path:
        return self.root / self.relative_path(sha256)

    def contains_valid(self, sha256: str) -> bool:
        path = self.path(sha256)
        return path.is_file() and sha256_file(path) == sha256

    def place(self, source: Path, sha256: str) -> bool:
        """Move `source` (on the same filesystem) into the store.

        Returns True if this call created the stored file, False if an intact
        copy already existed (then `source` is left for the caller to delete).
        """
        if self.contains_valid(sha256):
            return False
        target = self.path(sha256)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(source, 0o400)
        os.replace(source, target)  # atomic on one filesystem; replaces a corrupt copy
        return True

    def put_bytes(self, data: bytes, sha256: str, scratch_dir: Path) -> bool:
        """Store `data` via a temp file in `scratch_dir` (same filesystem)."""
        if hashlib.sha256(data).hexdigest() != sha256:
            raise IntegrityError("data does not match the given SHA-256")
        if self.contains_valid(sha256):
            return False
        temp = scratch_dir / f".{sha256}.part"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return self.place(temp, sha256)

    def read_verified(self, sha256: str) -> bytes:
        """Return the stored bytes, or raise IntegrityError if they changed."""
        path = self.path(sha256)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise IntegrityError(f"stored file for {sha256} is missing") from exc
        if hashlib.sha256(data).hexdigest() != sha256:
            raise IntegrityError(f"stored file for {sha256} does not match its SHA-256")
        return data

    def verify(self, sha256: str) -> None:
        """Like read_verified, without keeping the bytes in memory."""
        path = self.path(sha256)
        try:
            actual = sha256_file(path)
        except OSError as exc:
            raise IntegrityError(f"stored file for {sha256} is missing") from exc
        if actual != sha256:
            raise IntegrityError(f"stored file for {sha256} does not match its SHA-256")

    def remove(self, sha256: str) -> None:
        path = self.path(sha256)
        if path.exists():
            os.chmod(path, 0o600)
            path.unlink()

    def stored_hashes(self) -> Iterator[tuple[str, float]]:
        """Yield (sha256, age in seconds) for every stored file."""
        base = self.root / "sha256"
        if not base.is_dir():
            return
        now = time.time()
        for path in base.glob("*/*/*"):
            if path.is_file() and len(path.name) == 64 and set(path.name) <= _HEX:
                yield path.name, now - path.stat().st_mtime
