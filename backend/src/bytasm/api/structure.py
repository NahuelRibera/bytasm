"""Deep PE/ELF structural tables of a version (v0.11), read-only and paginated."""

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bytasm.api.problems import problem
from bytasm.db.imported import ImportRecordMissing, import_record
from bytasm.db.models import SampleVersion
from bytasm.storage import IntegrityError
from bytasm.structure_source import deep_structure

router = APIRouter()
INLINE_ROWS = 50
TABLES = (
    "import_slots",
    "structural_observations",
    "pe.sections",
    "pe.data_directories",
    "pe.import_descriptors",
    "pe.exports",
    "pe.debug_entries",
    "elf.segments",
    "elf.dynamic_entries",
    "elf.dynamic_symbols",
    "elf.notes",
)
PROVENANCE = {
    "import_slots": "parsed (PE import address table; ELF JUMP_SLOT/GLOB_DAT relocations); "
    "file offsets derived through declared sections (PE) or PT_LOAD headers (ELF)",
    "structural_observations": "derived from declarations; not maliciousness indicators",
    "pe.sections": "declared section headers; file ranges verified against the file size",
    "pe.data_directories": "declared optional-header directories; offsets derived, ranges verified",
    "pe.import_descriptors": "parsed import descriptors",
    "pe.exports": "parsed export directory; offsets derived",
    "pe.debug_entries": "declared debug directory entries; payloads not read",
    "elf.segments": "declared program headers; file ranges verified; section mapping parsed",
    "elf.dynamic_entries": "declared dynamic table",
    "elf.dynamic_symbols": "parsed dynamic symbol table",
    "elf.notes": "parsed notes; descriptions retained up to 64 bytes",
}


class TableOut(BaseModel):
    name: str
    provenance: str
    count: int
    offset: int
    limit: int
    rows: list[dict[str, Any]]
    next_offset: int | None


class StructureOut(BaseModel):
    version_id: str
    state: Literal["available", "unavailable"]
    unavailable_reason: str | None
    adapter: str
    adapter_version: str
    tool_version: str
    output_sha256: str
    schema_version: str | None = None
    format: str | None = None
    file_size: int | None = None
    header: dict[str, Any] = {}
    tables: list[TableOut] = []
    truncated: list[str] = []
    limitations: str | None = None


def _rows(document: dict[str, Any], name: str) -> list[dict[str, Any]] | None:
    group, _, key = name.rpartition(".")
    container = document.get(group) if group else document
    if not isinstance(container, dict):
        return None
    value = container.get(key)
    return value if isinstance(value, list) else None


@router.get("/sample-versions/{version_id}/structure", response_model=StructureOut)
def structure(
    request: Request,
    version_id: str,
    table: Literal[TABLES] | None = None,  # type: ignore[valid-type]
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = INLINE_ROWS,
) -> StructureOut | JSONResponse:
    ctx = request.app.state.ctx
    rid = request.state.request_id
    with ctx.sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            return problem("not_found", request_id=rid)
        try:
            record = import_record(version)
            state = deep_structure(ctx.outputs, version, record)
        except (ImportRecordMissing, IntegrityError):
            return problem("integrity_error", request_id=rid)
        base = {
            "version_id": version.id,
            "adapter": record.invocation.adapter_name,
            "adapter_version": record.invocation.adapter_version,
            "tool_version": record.invocation.tool_version,
            "output_sha256": record.raw_output_sha256,
        }
    if state.tables is None:
        return StructureOut(
            state="unavailable", unavailable_reason=state.unavailable_reason, **base
        )
    document = state.tables.model_dump(mode="json")
    tables = []
    for name in (table,) if table else TABLES:
        rows = _rows(document, name)
        if rows is None:
            continue
        start = offset if table else 0
        end = start + (limit if table else INLINE_ROWS)
        tables.append(
            TableOut(
                name=name,
                provenance=PROVENANCE[name],
                count=len(rows),
                offset=start,
                limit=end - start,
                rows=rows[start:end],
                next_offset=end if end < len(rows) else None,
            )
        )
    if table and not tables:
        return problem("not_found", request_id=rid)
    header = {}
    for group in ("pe", "elf"):
        if isinstance(document.get(group), dict):
            header = {k: v for k, v in document[group].items() if not isinstance(v, list)}
    return StructureOut(
        state="available",
        unavailable_reason=None,
        schema_version=document["schema_version"],
        format=document["format"],
        file_size=document["file_size"],
        header=header,
        tables=tables,
        truncated=document["truncated"],
        limitations=document["limitations"],
        **base,
    )
