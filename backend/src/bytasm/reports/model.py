"""The v0.1 JSON report: schema (as Pydantic models) and its fixed texts.

The committed JSON Schema, `schemas/report.schema.json`, is generated from
these models (`make schemas`), and a test keeps the two identical.

There is deliberately no field for a verdict, a score, or a "malicious/safe"
judgement. Entropy is a measurement with its unit and method.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

REPORT_KIND = "bytasm.sample_version_report"
SCHEMA_VERSION = 1
SCHEMA_ID = "https://github.com/NahuelRibera/bytasm/blob/main/schemas/report.schema.json"

LABELS: dict[str, str] = {
    "declared_in_header": (
        "Values the file declares about itself in its headers. Bytasm reports them as "
        "read and does not verify them; a timestamp, for example, can be forged or zeroed."
    ),
    "sections": (
        "Section names, offsets, sizes and flags are as declared in the file's section "
        "table. bytes_in_file is 0 for sections that occupy no bytes in the file."
    ),
    "entropy": (
        "Shannon entropy in bits per byte (0-8), measured by Bytasm over each section's "
        "bytes in the file. A descriptive measurement, not a verdict: high values are "
        "common in compressed data and ordinary resources. null means it was not measured "
        "(see note)."
    ),
    "untrusted_text": (
        "Section, symbol and library names, the sample name, and the declared file name "
        "come from the file or the uploader. Treat them as untrusted text."
    ),
    "generated_at": "The only field that differs between two exports of the same data.",
}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Generator(_Model):
    name: Literal["bytasm"]
    version: str
    source_revision: str | None = Field(
        description="`git describe --always --dirty` of the running checkout, or null."
    )
    image_id: str | None = Field(description="Container image ID; null when run natively.")


class DeclaredFilename(_Model):
    value: str | None
    trust: Literal["untrusted_as_uploaded"]


class SampleIdentity(_Model):
    project_name: str
    sample_name: str
    version_label: str | None
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1)
    format: Literal["ELF", "PE"]
    format_basis: Literal["identified_from_bytes_and_parsed"]
    declared_filename: DeclaredFilename
    blob_sha256_verified_at_export: Literal[True]


class InputPolicy(_Model):
    admitted_under: Literal["fixture_manifest", "self_built_optin"]
    manifest_entry: str | None
    notice: str


class Authorization(_Model):
    type: Literal["self_attestation"]
    basis: Literal["owned_or_built"]
    statement: str
    terms_reference: str | None
    recorded_at: datetime
    notice: str


class ToolInvocation(_Model):
    step_index: int
    tool: str
    tool_version: str
    adapter: str
    adapter_version: str
    status: Literal["succeeded"]
    exit_code: int
    duration_ms: int
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution: Literal["separate_resource_limited_process"]


class Run(_Model):
    status: Literal["succeeded"]
    profile: dict[str, Any]
    bytasm_version: str
    started_at: datetime
    finished_at: datetime


class Analysis(_Model):
    run: Run
    tool_invocations: list[ToolInvocation]


class Entropy(_Model):
    value: float | None = Field(ge=0.0, le=8.0)
    unit: Literal["bits_per_byte"]
    method: str
    computed_by: str
    measured_over: Literal["section_bytes_in_file"]
    note: str | None


class Section(_Model):
    index: int
    name: str
    type: str | None
    file_offset: int
    bytes_in_file: int
    virtual_address: int
    declared_size: int
    flags: list[str]
    entropy: Entropy


class DeclaredInHeader(_Model):
    architecture: str
    bitness: int
    endianness: str
    entry_point: int | None
    fields: dict[str, str | int]


class Imports(_Model):
    libraries: list[str]
    functions: list[str]


class Metadata(_Model):
    declared_in_header: DeclaredInHeader
    sections: list[Section]
    imports: Imports
    exports: list[str]
    warnings: list[str]


class Report(_Model):
    model_config = ConfigDict(
        extra="forbid",
        title="Bytasm sample version report",
        json_schema_extra={"$id": SCHEMA_ID},
    )

    report_kind: Literal["bytasm.sample_version_report"]
    schema_version: Literal[1]
    generated_at: datetime
    generator: Generator
    sample: SampleIdentity
    input_policy: InputPolicy
    authorization: Authorization
    analysis: Analysis
    metadata: Metadata
    labels: dict[str, str]
    limitations: list[str]


def json_schema() -> dict[str, Any]:
    schema = Report.model_json_schema()
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **schema}


if __name__ == "__main__":
    import json
    import sys

    sys.stdout.write(json.dumps(json_schema(), indent=2, sort_keys=True) + "\n")
