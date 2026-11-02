"""Deep structural tables of a version, read from its verified import output.

The tables live only in the content-addressed raw LIEF output (metadata
adapter 0.3.0 and later), not in the database header. Every read re-verifies
the output digest, its size bound and its input identity. Imports made with
an earlier adapter have no tables, and that is reported, never reconstructed.
"""

from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock

from pydantic import ValidationError

from bytasm.adapters.result import AdapterResult, DeepStructureResult
from bytasm.db.imported import ImportRecord
from bytasm.db.models import SampleVersion
from bytasm.storage import ContentStore, IntegrityError

MAX_IMPORT_OUTPUT_BYTES = 32 * 1024 * 1024
CACHE_SIZE = 16

_cache: "OrderedDict[str, DeepStructureResult | None]" = OrderedDict()
_lock = Lock()


@dataclass(frozen=True)
class StructureState:
    tables: DeepStructureResult | None
    adapter_version: str
    unavailable_reason: str | None


def deep_structure(
    outputs: ContentStore, version: SampleVersion, record: ImportRecord
) -> StructureState:
    """Tables of the import output, or the reason there are none. Raises IntegrityError."""
    from bytasm.review_snapshot import bounded_read

    adapter_version = record.invocation.adapter_version
    digest = record.raw_output_sha256
    with _lock:
        if digest in _cache:
            _cache.move_to_end(digest)
            cached = _cache[digest]
            return _state(cached, adapter_version)
    raw = bounded_read(outputs, digest, MAX_IMPORT_OUTPUT_BYTES)
    try:
        result = AdapterResult.model_validate_json(raw)
    except ValidationError as exc:
        raise IntegrityError("Import output no longer validates") from exc
    if (
        result.input.sha256 != version.sha256
        or result.input.size_bytes != version.size_bytes
        or result.adapter_version != adapter_version
    ):
        raise IntegrityError("Import output identity mismatch")
    tables = result.metadata.deep_structure
    with _lock:
        _cache[digest] = tables
        while len(_cache) > CACHE_SIZE:
            _cache.popitem(last=False)
    return _state(tables, adapter_version)


def _state(tables: DeepStructureResult | None, adapter_version: str) -> StructureState:
    if tables is not None:
        return StructureState(tables, adapter_version, None)
    reason = (
        f"This version was imported with metadata adapter {adapter_version}, which predates "
        "the deep structural tables (0.3.0). They are not reconstructed for an existing "
        "import."
        if adapter_version in ("0.1.0", "0.2.0")
        else "The metadata adapter could not extract the deep structural tables for this file."
    )
    return StructureState(None, adapter_version, reason)
