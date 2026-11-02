"""Strict bounded Ghidra document. Addresses are tool text, never file offsets."""

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

Text = Annotated[str, Field(max_length=256)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Address(Record):
    space: Annotated[str, Field(min_length=1, max_length=64)]
    address: Annotated[str, Field(min_length=1, max_length=128)]


class Instruction(Record):
    address: Address
    bytes_hex: Annotated[str, Field(max_length=64, pattern=r"^(?:[0-9a-f]{2})*$")]
    text: Text
    text_truncated: bool = False
    bytes_truncated: bool = False


class Call(Record):
    source: Address
    target: Address


class BodyRange(Record):
    start: Address
    end: Address
    provenance: Literal["ghidra_function_body"] = "ghidra_function_body"

    @model_validator(mode="after")
    def same_space(self) -> "BodyRange":
        if self.start.space != self.end.space:
            raise ValueError("Body range crosses address spaces")
        return self


class FunctionReference(Record):
    source: Address
    target: Address
    kind: Literal["string", "data", "external_symbol"]
    reference_type: Text
    resolved_external_target: Address | None = None
    resolved_external_provenance: Literal["ghidra_function_thunk"] | None = None
    provenance: Literal["ghidra_instruction_reference"]
    target_name: Text | None = None
    target_name_truncated: bool = False
    preview: Annotated[str, Field(max_length=512)] | None = None
    preview_truncated: bool = False

    @model_validator(mode="after")
    def consistent_resolution(self) -> "FunctionReference":
        if (self.resolved_external_target is None) != (self.resolved_external_provenance is None):
            raise ValueError("External resolution provenance mismatch")
        if self.resolved_external_target is not None and self.kind != "external_symbol":
            raise ValueError("External resolution requires an external-symbol reference")
        return self


class BlockFlow(Record):
    """A static control-flow edge Ghidra's BasicBlockModel reports from a block."""

    target: Address | None  # None: a computed destination Ghidra did not resolve
    kind: Literal["fallthrough", "conditional_jump", "unconditional_jump", "computed_jump"]
    internal: bool  # target lies inside this function's body
    provenance: Literal["ghidra_basic_block_model"] = "ghidra_basic_block_model"

    @model_validator(mode="after")
    def resolved_unless_computed(self) -> "BlockFlow":
        if self.target is None and self.kind != "computed_jump":
            raise ValueError("Only computed flows may lack a target")
        if self.target is None and self.internal:
            raise ValueError("An unresolved flow cannot be internal")
        return self


class BasicBlock(Record):
    start: Address
    end: Address  # inclusive
    instruction_count: Annotated[int, Field(ge=0, le=4096)]
    terminal: bool  # the last instruction's flow is terminal (for example a return)
    flows: Annotated[list[BlockFlow], Field(max_length=8)]
    flows_truncated: bool

    @model_validator(mode="after")
    def same_space(self) -> "BasicBlock":
        if self.start.space != self.end.space:
            raise ValueError("Basic block crosses address spaces")
        return self


class CallSite(Record):
    source: Address
    kind: Literal["direct", "indirect"]
    # A target exists only where Ghidra recorded a call reference; indirect
    # calls without one stay unresolved and are never guessed.
    target: Address | None
    target_basis: Literal["ghidra_call_reference"] | None
    provenance: Literal["ghidra_instruction_flow"] = "ghidra_instruction_flow"

    @model_validator(mode="after")
    def target_has_basis(self) -> "CallSite":
        if (self.target is None) != (self.target_basis is None):
            raise ValueError("Call target basis mismatch")
        return self


class PointerSlot(Record):
    """Initialized memory that Ghidra reports as a data reference to a function entry."""

    address: Address
    reference_type: Text
    provenance: Literal["ghidra_reference_to_entry"] = "ghidra_reference_to_entry"


V5_FUNCTION_KEYS = (
    "thunk_target",
    "pointer_slots",
    "pointer_slots_truncated",
    "basic_blocks",
    "basic_blocks_truncated",
    "basic_block_count",
    "basic_block_count_capped",
    "instruction_count",
    "instruction_count_capped",
    "call_sites",
    "call_sites_truncated",
)


class Function(Record):
    entry: Address
    name: Text
    namespace: Text
    external: bool = False
    name_truncated: bool = False
    namespace_truncated: bool = False
    body_size: Annotated[int, Field(ge=0)] | None
    pseudocode: Annotated[str, Field(max_length=4096)] | None
    pseudocode_status: Literal["available", "not_selected", "failed"]
    pseudocode_truncated: bool
    instructions: Annotated[list[Instruction], Field(max_length=64)]
    instructions_truncated: bool
    calls: Annotated[list[Call], Field(max_length=64)]
    calls_truncated: bool

    body_ranges: Annotated[list[BodyRange], Field(max_length=64)] = Field(default_factory=list)
    body_ranges_truncated: bool = False
    references: Annotated[list[FunctionReference], Field(max_length=64)] = Field(
        default_factory=list
    )
    references_truncated: bool = False

    # ghidra-5 only. Inventory level: exact thunk resolution and pointer slots.
    thunk_target: Address | None = None
    pointer_slots: Annotated[list[PointerSlot], Field(max_length=4)] = Field(default_factory=list)
    pointer_slots_truncated: bool = False
    # ghidra-5 only, selected functions: static structure (None when not collected).
    basic_blocks: Annotated[list[BasicBlock], Field(max_length=128)] = Field(default_factory=list)
    basic_blocks_truncated: bool = False
    basic_block_count: Annotated[int, Field(ge=0, le=4096)] | None = None
    basic_block_count_capped: bool = False
    instruction_count: Annotated[int, Field(ge=0, le=65536)] | None = None
    instruction_count_capped: bool = False
    call_sites: Annotated[list[CallSite], Field(max_length=128)] = Field(default_factory=list)
    call_sites_truncated: bool = False

    @model_validator(mode="after")
    def consistent_structure(self) -> "Function":
        selected = self.pseudocode_status != "not_selected"
        structure = (
            self.basic_blocks
            or self.basic_blocks_truncated
            or self.basic_block_count is not None
            or self.instruction_count is not None
            or self.call_sites
            or self.call_sites_truncated
        )
        if structure and not selected:
            raise ValueError("Inventory-only function contains structure")
        if self.basic_block_count is not None and len(self.basic_blocks) > self.basic_block_count:
            raise ValueError("Basic block count is below retained blocks")
        if (
            self.basic_blocks_truncated
            and self.basic_block_count is not None
            and (
                len(self.basic_blocks) >= self.basic_block_count
                and not self.basic_block_count_capped
            )
        ):
            raise ValueError("Basic block truncation mismatch")
        return self

    @model_validator(mode="after")
    def consistent_pseudocode(self) -> "Function":
        if (self.pseudocode is not None) != (self.pseudocode_status == "available"):
            raise ValueError("Pseudocode availability mismatch")
        if self.pseudocode_status == "not_selected" and (
            self.instructions
            or self.calls
            or self.pseudocode_truncated
            or self.instructions_truncated
            or self.calls_truncated
            or self.references
            or self.references_truncated
        ):
            raise ValueError("Inventory-only function contains unexpected details")
        instruction_addresses = {(i.address.space, i.address.address) for i in self.instructions}
        if any(
            (r.source.space, r.source.address) not in instruction_addresses for r in self.references
        ):
            raise ValueError("Reference source is outside the retained instruction window")
        return self


class FileRange(Record):
    """Ghidra-reported mapping of an inclusive address range onto input file bytes."""

    start: Address
    end: Address
    file_offset: Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
    provenance: Literal["ghidra_memory_block_file_bytes"] = "ghidra_memory_block_file_bytes"

    @model_validator(mode="after")
    def same_space(self) -> "FileRange":
        if self.start.space != self.end.space:
            raise ValueError("File range crosses address spaces")
        return self


class MemoryBlock(Record):
    name: Text
    name_truncated: bool = False
    start: Address
    end: Address
    read: bool
    write: bool
    execute: bool
    initialized: bool
    file_ranges: Annotated[list[FileRange], Field(max_length=16)]
    file_ranges_truncated: bool

    @model_validator(mode="after")
    def same_space(self) -> "MemoryBlock":
        spaces = {self.start.space, self.end.space}
        spaces.update(r.start.space for r in self.file_ranges)
        if len(spaces) != 1:
            raise ValueError("Memory block crosses address spaces")
        return self


V4_KEYS = ("image_base", "memory_blocks", "memory_blocks_truncated")
REFERENCE_PROTOCOLS = ("ghidra-3", "ghidra-4", "ghidra-5")
MEMORY_MAP_PROTOCOLS = ("ghidra-4", "ghidra-5")


class GhidraResult(Record):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"schema_version": {"const": "ghidra-1"}}},
                    "then": {"properties": {"functions": {"maxItems": 256}}},
                }
            ],
        },
    )
    schema_version: Literal["ghidra-1", "ghidra-2", "ghidra-3", "ghidra-4", "ghidra-5"]
    input_sha256: Digest
    ghidra_version: Literal["12.2"]
    language_id: Text
    compiler: Text
    provider_host: Text = "unavailable"
    profile_sha256: Digest
    script_sha256: Digest
    functions: Annotated[list[Function], Field(max_length=1024)]
    function_count: Annotated[int, Field(ge=0)]
    functions_truncated: bool
    analysis_timed_out: bool
    limitations: Annotated[list[Text], Field(max_length=32)]
    # ghidra-4 and later: Ghidra's program image base and memory map.
    image_base: Address | None = None
    memory_blocks: Annotated[list[MemoryBlock], Field(max_length=64)] = Field(default_factory=list)
    memory_blocks_truncated: bool = False

    @model_serializer(mode="wrap")
    def preserve_historical_shape(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.schema_version not in MEMORY_MAP_PROTOCOLS:
            for key in V4_KEYS:
                result.pop(key, None)
        if self.schema_version != "ghidra-5":
            for function in result.get("functions", []):
                for key in V5_FUNCTION_KEYS:
                    function.pop(key, None)
        if self.schema_version not in REFERENCE_PROTOCOLS:
            for function in result.get("functions", []):
                for key in (
                    "body_ranges",
                    "body_ranges_truncated",
                    "references",
                    "references_truncated",
                ):
                    function.pop(key, None)
        return result

    @model_validator(mode="after")
    def consistent_inventory(self) -> "GhidraResult":
        if self.schema_version == "ghidra-1" and len(self.functions) > 256:
            raise ValueError("Legacy inventory exceeds bounds")
        if self.function_count < len(self.functions):
            raise ValueError("Invalid function count")
        if self.functions_truncated != (self.function_count > len(self.functions)):
            raise ValueError("Inventory truncation mismatch")
        if self.schema_version in MEMORY_MAP_PROTOCOLS and self.image_base is None:
            raise ValueError("Protocol version 4 and later require an image base")
        if self.schema_version not in MEMORY_MAP_PROTOCOLS and (
            self.image_base is not None or self.memory_blocks or self.memory_blocks_truncated
        ):
            raise ValueError("Legacy protocol contains version 4 memory map")
        if self.schema_version != "ghidra-5" and any(
            f.thunk_target is not None
            or f.pointer_slots
            or f.pointer_slots_truncated
            or f.basic_blocks
            or f.basic_blocks_truncated
            or f.basic_block_count is not None
            or f.basic_block_count_capped
            or f.instruction_count is not None
            or f.instruction_count_capped
            or f.call_sites
            or f.call_sites_truncated
            for f in self.functions
        ):
            raise ValueError("Legacy protocol contains version 5 structure")
        if self.schema_version not in REFERENCE_PROTOCOLS and any(
            f.body_ranges or f.body_ranges_truncated or f.references or f.references_truncated
            for f in self.functions
        ):
            raise ValueError("Legacy protocol contains version 3 evidence")
        entries = [(f.entry.space, f.entry.address) for f in self.functions]
        if len(entries) != len(set(entries)):
            raise ValueError("Duplicate function entry")
        return self
