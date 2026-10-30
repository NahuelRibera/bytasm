"""Strict bounded Ghidra document. Addresses are tool text, never file offsets."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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

    @model_validator(mode="after")
    def consistent_pseudocode(self) -> "Function":
        if (self.pseudocode is not None) != (self.pseudocode_status == "available"):
            raise ValueError("Pseudocode availability mismatch")
        return self


class GhidraResult(Record):
    schema_version: Literal["ghidra-1"]
    input_sha256: Digest
    ghidra_version: Literal["12.2"]
    language_id: Text
    compiler: Text
    provider_host: Text = "unavailable"
    profile_sha256: Digest
    script_sha256: Digest
    functions: Annotated[list[Function], Field(max_length=256)]
    function_count: Annotated[int, Field(ge=0)]
    functions_truncated: bool
    analysis_timed_out: bool
    limitations: Annotated[list[Text], Field(max_length=32)]

    @model_validator(mode="after")
    def consistent_inventory(self) -> "GhidraResult":
        if self.function_count < len(self.functions):
            raise ValueError("Invalid function count")
        if self.functions_truncated != (self.function_count > len(self.functions)):
            raise ValueError("Inventory truncation mismatch")
        entries = [(f.entry.space, f.entry.address) for f in self.functions]
        if len(entries) != len(set(entries)):
            raise ValueError("Duplicate function entry")
        return self
