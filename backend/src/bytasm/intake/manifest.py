"""The fixture manifest: Bytasm's input allowlist during M0-M1.

`fixtures/MANIFEST.sha256` lists the SHA-256 of every committed fixture, in the
same format as `shasum -a 256` output:

    <64 lowercase hex characters><two spaces><path relative to fixtures/>

A file is admitted only if its SHA-256 appears in this list. This check is the
main safety control of the fixtures-only phase (ADR-0001, D2), so it always
runs before the bytes reach LIEF.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from bytasm.errors import MANIFEST_ERROR, InspectError

_LINE = re.compile(r"^(?P<sha256>[0-9a-f]{64}) [ *](?P<path>\S.*)$")


def default_manifest_path() -> Path:
    """Locate `fixtures/MANIFEST.sha256` in the repository checkout.

    This file lives at backend/src/bytasm/intake/manifest.py, so the repository
    root is four directories up. There is deliberately no command-line option
    or environment variable to point at another manifest.
    """
    return Path(__file__).resolve().parents[4] / "fixtures" / "MANIFEST.sha256"


@dataclass(frozen=True)
class Manifest:
    """Maps an allowed SHA-256 to the fixture path recorded for it."""

    entries: dict[str, str]

    @classmethod
    def load(cls, path: Path) -> "Manifest":
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise InspectError(MANIFEST_ERROR, f"Cannot read fixture manifest: {path}") from exc

        entries: dict[str, str] = {}
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip() or line.startswith("#"):
                continue
            match = _LINE.match(line)
            if match is None:
                raise InspectError(
                    MANIFEST_ERROR, f"Malformed line {number} in fixture manifest {path}"
                )
            entries[match["sha256"]] = match["path"]
        if not entries:
            raise InspectError(MANIFEST_ERROR, f"Fixture manifest is empty: {path}")
        return cls(entries)

    def lookup(self, sha256: str) -> str | None:
        """Return the manifest path for this hash, or None if it is not listed."""
        return self.entries.get(sha256)
