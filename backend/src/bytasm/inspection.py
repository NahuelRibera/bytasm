"""`bytasm inspect`: the order of operations is the safety design.

1. Read the file once, with a size limit, into memory.
2. Compute its SHA-256.
3. Input policy: refuse the file unless that hash is in the fixture manifest.
4. Identify the format from magic bytes and basic header sanity checks.
5. Only now import LIEF and parse the *same bytes* that were hashed. Parsing the
   in-memory bytes (rather than re-opening the path) means the file cannot be
   swapped between the hash check and the parse.

Bytasm never executes the file.
"""

import hashlib
from pathlib import Path
from typing import Any

from bytasm import __version__
from bytasm.adapters.entropy import METHOD as ENTROPY_METHOD
from bytasm.errors import (
    EMPTY_FILE,
    FILE_NOT_FOUND,
    FILE_TOO_LARGE,
    UNKNOWN_HASH,
    InspectError,
)
from bytasm.intake.identify import identify_format
from bytasm.intake.manifest import Manifest

REPORT_KIND = "bytasm.inspect"
SCHEMA_VERSION = 1
# Provisional v0.1 size limit (ADR-0001, D4), reviewed after M1 measurements.
MAX_FILE_SIZE = 64 * 1024 * 1024

NOTES = (
    "Bytasm did not execute this file.",
    "Architecture, entry point, flags, and everything under declared_header are "
    "values the file declares about itself. Bytasm does not verify them.",
    "Entropy is a measurement in bits per byte (0-8), not a judgement about the file.",
)


def read_bounded(path: Path, limit: int = MAX_FILE_SIZE) -> bytes:
    """Read at most `limit` bytes; refuse empty or larger files."""
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError) as exc:
        raise InspectError(FILE_NOT_FOUND, f"No readable file at {path}") from exc
    except OSError as exc:
        raise InspectError(FILE_NOT_FOUND, f"Cannot read {path}: {exc.strerror}") from exc
    if not data:
        raise InspectError(EMPTY_FILE, "The file is empty.")
    if len(data) > limit:
        raise InspectError(FILE_TOO_LARGE, f"The file is larger than {limit} bytes.")
    return data


def inspect_file(path: Path, manifest: Manifest) -> dict[str, Any]:
    """Run the steps above and return the report as a JSON-ready dict."""
    data = read_bounded(path)
    sha256 = hashlib.sha256(data).hexdigest()

    manifest_entry = manifest.lookup(sha256)
    if manifest_entry is None:
        raise InspectError(
            UNKNOWN_HASH,
            f"SHA-256 {sha256} is not in the fixture manifest. During M0-M1 Bytasm "
            "only inspects its own committed fixtures. The file was not parsed.",
        )

    file_format = identify_format(data)

    # Imported here, after the policy check, so that a refused file never even
    # causes LIEF to be loaded.
    from bytasm.adapters import metadata_lief

    metadata = metadata_lief.extract_metadata(data, file_format)

    return {
        "report_kind": REPORT_KIND,
        "schema_version": SCHEMA_VERSION,
        "bytasm_version": __version__,
        "adapter": {
            "name": metadata_lief.ADAPTER_NAME,
            "version": metadata_lief.ADAPTER_VERSION,
            "parser": "lief",
            "parser_version": metadata_lief.lief_version(),
            "entropy_method": ENTROPY_METHOD,
        },
        "input_policy": {
            "mode": "fixtures",
            "admitted_under": "fixture_manifest",
            "manifest_entry": manifest_entry,
        },
        "file": {"sha256": sha256, "size_bytes": len(data)},
        **metadata,
        "notes": list(NOTES),
    }
