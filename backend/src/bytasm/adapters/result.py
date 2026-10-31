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


class MetadataResult(_Strict):
    structure: StructureResult | None = None
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
