"""Strict bounded envelope; the raw capa document is retained byte-for-byte."""

from typing import Annotated, Any, Literal

from pydantic import Field, StrictInt, StrictStr

from bytasm.adapters.result import Sha256, _Strict

Text = Annotated[StrictStr, Field(max_length=200)]
Address = Annotated[StrictInt, Field(ge=0, le=2**64 - 1)]


class CapaMatch(_Strict):
    address: Address
    pointer: Annotated[StrictStr, Field(max_length=256)]


class CapaFinding(_Strict):
    name: Text
    namespace: Annotated[StrictStr, Field(max_length=128)]
    source: Annotated[StrictStr, Field(max_length=32768)]
    classifications: Annotated[list[tuple[Literal["ATT&CK", "MBC"], Text]], Field(max_length=16)]
    matches: Annotated[list[CapaMatch], Field(max_length=32)]
    match_count: Annotated[StrictInt, Field(ge=0, le=1_000_000)]


class CapaResult(_Strict):
    schema_version: Literal[1]
    tool_version: Literal["10.0.0"]
    sample_sha256: Sha256
    rules_sha256: Sha256
    raw: Annotated[StrictStr, Field(max_length=8 * 1024 * 1024)]
    findings: Annotated[list[CapaFinding], Field(max_length=16)]


def classifications(meta: dict[str, Any]) -> list[tuple[str, str]]:
    """Labels supplied by the pinned rule result, not Bytasm behavior claims."""
    labels = []
    for field, label in (("attack", "ATT&CK"), ("mbc", "MBC")):
        for item in meta.get(field, []):
            labels.append((label, "::".join(item["parts"]) + " [" + item["id"] + "]"))
    if len(labels) > 16 or any(len(text) > 200 for _, text in labels):
        raise ValueError("Too many or oversized capa classification labels")
    return labels
