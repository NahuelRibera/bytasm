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
    schema_version: Literal["ghidra-1", "ghidra-2", "ghidra-3"]
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

    @model_serializer(mode="wrap")
    def preserve_historical_shape(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.schema_version != "ghidra-3":
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
        if self.schema_version != "ghidra-3" and any(
            f.body_ranges or f.body_ranges_truncated or f.references or f.references_truncated
            for f in self.functions
        ):
            raise ValueError("Legacy protocol contains version 3 evidence")
        entries = [(f.entry.space, f.entry.address) for f in self.functions]
        if len(entries) != len(set(entries)):
            raise ValueError("Duplicate function entry")
        return self
