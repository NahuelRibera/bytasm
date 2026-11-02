"""Schema of the metadata adapter's `result.json`, validated by the parent.

The parent treats the child's output as untrusted: it is size-capped before it
is read, then validated against these models. Unknown fields, wrong types,
out-of-range values, or oversized strings and lists make the whole result
invalid, and nothing from it is used.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

RESULT_SCHEMA_VERSION = 1

# Generous caps: far above anything the fixtures contain, small enough that a
# hostile result cannot balloon the database.
_MAX_NAME = 4096
_MAX_ITEMS = 100_000

Name = Annotated[StrictStr, Field(max_length=_MAX_NAME)]
Count = Annotated[StrictInt, Field(ge=0)]
Sha256 = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SectionResult(_Strict):
    name: Name
    type: Annotated[StrictStr, Field(max_length=64)] | None
    file_offset: Count
    file_size: Count
    virtual_address: Count
    declared_size: Count
    flags: Annotated[list[Annotated[StrictStr, Field(max_length=64)]], Field(max_length=64)]
    entropy: Annotated[float, Field(ge=0.0, le=8.0)] | None
    entropy_note: Literal["no file data", "declared range exceeds file size"] | None


class ImportsResult(_Strict):
    libraries: Annotated[list[Name], Field(max_length=_MAX_ITEMS)]
    functions: Annotated[list[Name], Field(max_length=_MAX_ITEMS)]


StructureScalar = Name | StrictInt | StrictBool | None


class VersionStringResult(_Strict):
    table: Annotated[StrictStr, Field(max_length=256)]
    key: Annotated[StrictStr, Field(max_length=256)]
    value: Name


class StructureResult(_Strict):
    schema_version: Literal[1]
    provenance: Literal["lief_static_declarations"]
    declarations: Annotated[
        dict[Name, StructureScalar | Annotated[list[StructureScalar], Field(max_length=128)]],
        Field(max_length=32),
    ]
    measurements: Annotated[dict[Name, StructureScalar], Field(max_length=16)]
    version_strings: Annotated[list[VersionStringResult], Field(max_length=128)] = []
    explanations: Annotated[dict[Name, Name], Field(max_length=32)] = {}
    truncated: Annotated[list[Name], Field(max_length=32)]
    limitations: Name


Short = Annotated[StrictStr, Field(max_length=256)]
Offset = Annotated[StrictInt, Field(ge=0)]
RangeState = Literal["within_file", "outside_file", "not_file_backed", "empty", "not_present"]


class ImportSlotResult(_Strict):
    library: Short | None
    name: Short | None
    name_truncated: StrictBool
    ordinal: Offset | None
    hint: Offset | None
    slot_rva: Offset | None
    slot_virtual_address: Offset
    slot_file_offset: Offset | None
    slot_basis: Literal["lief_import_address_table", "lief_elf_relocation_load_segment"]
    relocation_type: Short | None


class ObservationResult(_Strict):
    code: Short
    subject: Short
    detail: Short


class PeSectionResult(_Strict):
    index: Offset
    name: Short
    rva: Offset
    virtual_size: Offset
    raw_offset: Offset
    raw_size: Offset
    file_range_state: RangeState
    characteristics: Annotated[list[Short], Field(max_length=64)]


class DataDirectoryResult(_Strict):
    index: Offset
    type: Short
    declared_rva: Offset
    declared_size: Offset
    address_kind: Literal["rva", "file_offset"]
    section: Short | None
    file_offset: Offset | None
    file_range_state: RangeState


class ImportDescriptorResult(_Strict):
    library: Short
    library_truncated: StrictBool
    import_lookup_table_rva: Offset
    import_address_table_rva: Offset
    entry_count: Offset


class ExportResult(_Strict):
    name: Short | None
    name_truncated: StrictBool
    ordinal: Offset
    rva: Offset
    forwarded: StrictBool
    file_offset: Offset | None


class RelocationSummary(_Strict):
    blocks: Offset | None = None
    entries: Offset
    entries_by_type: Annotated[dict[Short, Offset], Field(max_length=256)]


class DebugEntryResult(_Strict):
    type: Short
    declared_rva: Offset
    declared_file_offset: Offset
    declared_size: Offset
    file_range_state: RangeState


class TlsResult(_Strict):
    raw_data_start_va: Offset
    raw_data_end_va: Offset
    index_va: Offset
    callbacks_va: Offset
    callback_count: Offset


class PeDeepResult(_Strict):
    image_base: Offset
    section_alignment: Offset
    file_alignment: Offset
    size_of_image: Offset
    size_of_headers: Offset
    checksum_declared: Offset
    entry_point_rva: Offset
    sections: Annotated[list[PeSectionResult], Field(max_length=65_536)]
    data_directories: Annotated[list[DataDirectoryResult], Field(max_length=16)]
    import_descriptors: Annotated[list[ImportDescriptorResult], Field(max_length=4096)]
    exports: Annotated[list[ExportResult], Field(max_length=4096)]
    relocations: RelocationSummary
    debug_entries: Annotated[list[DebugEntryResult], Field(max_length=32)]
    tls: TlsResult | None


class SegmentResult(_Strict):
    index: Offset
    type: Short
    flags: Annotated[StrictStr, Field(pattern=r"^[r-][w-][x-]$")]
    file_offset: Offset
    file_size: Offset
    virtual_address: Offset
    memory_size: Offset
    alignment: Offset
    file_range_state: RangeState
    sections: Annotated[list[Short], Field(max_length=64)]


class DynamicEntryResult(_Strict):
    tag: Short
    value: Offset
    text: Short | None = None
    text_truncated: StrictBool | None = None


class DynamicSymbolResult(_Strict):
    name: Short
    name_truncated: StrictBool
    value: Offset
    size: Offset
    type: Short
    binding: Short
    visibility: Short
    section_index: Offset
    imported: StrictBool
    exported: StrictBool


class NoteResult(_Strict):
    type: Short
    owner: Short
    description_size: Offset
    description_hex: Annotated[StrictStr, Field(max_length=128, pattern=r"^[0-9a-f]*$")]
    description_truncated: StrictBool


class ElfDeepResult(_Strict):
    file_type: Short
    entry_point: Offset
    interpreter: Short | None
    build_id: Annotated[StrictStr, Field(max_length=128, pattern=r"^[0-9a-f]*$")] | None
    segments: Annotated[list[SegmentResult], Field(max_length=64)]
    dynamic_entries: Annotated[list[DynamicEntryResult], Field(max_length=256)]
    dynamic_symbols: Annotated[list[DynamicSymbolResult], Field(max_length=1024)]
    symtab_symbol_count: Offset
    relocations: RelocationSummary
    notes: Annotated[list[NoteResult], Field(max_length=32)]


class DeepStructureResult(_Strict):
    """metadata_lief 0.3.0 tables; see bytasm.adapters.deep_structure_lief."""

    schema_version: Literal["bytasm-lief-deep-1"]
    format: Literal["ELF", "PE"]
    file_size: Offset
    pe: PeDeepResult | None = None
    elf: ElfDeepResult | None = None
    import_slots: Annotated[list[ImportSlotResult], Field(max_length=4096)]
    structural_observations: Annotated[list[ObservationResult], Field(max_length=64)]
    truncated: Annotated[list[Short], Field(max_length=32)]
    limitations: Name


class MetadataResult(_Strict):
    structure: StructureResult | None = None
    # metadata_lief 0.3.0 (v0.11); absent from earlier imports.
    deep_structure: DeepStructureResult | None = None
    format: Literal["ELF", "PE"]
    architecture: Annotated[StrictStr, Field(max_length=64)]
    bitness: Literal[32, 64]
    endianness: Annotated[StrictStr, Field(max_length=16)]
    entry_point: Count | None
    declared_header: Annotated[
        dict[Annotated[StrictStr, Field(max_length=64)], Name | StrictInt],
        Field(max_length=32),
    ]
    sections: Annotated[list[SectionResult], Field(max_length=65_536)]
    imports: ImportsResult
    exports: Annotated[list[Name], Field(max_length=_MAX_ITEMS)]
    warnings: Annotated[list[Name], Field(max_length=1_000)]


class InputResult(_Strict):
    sha256: Sha256
    size_bytes: Count


class ResourceLimitsResult(_Strict):
    """Limits the child applied to itself; None where the platform refused one."""

    address_space_bytes: Count | None
    cpu_seconds: Count | None
    file_size_bytes: Count | None
    core_bytes: Count | None


class AdapterResult(_Strict):
    schema_version: Literal[1]
    adapter: Literal["metadata_lief"]
    adapter_version: Annotated[StrictStr, Field(max_length=32)]
    tool: Literal["lief"]
    tool_version: Annotated[StrictStr, Field(max_length=32)]
    entropy_method: Literal["shannon-bits-per-byte"]
    input: InputResult
    resource_limits: ResourceLimitsResult
    metadata: MetadataResult
