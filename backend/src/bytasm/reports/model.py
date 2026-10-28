"""The JSON report: schema (as Pydantic models) and its fixed texts.

Schema version 2 (v0.2) keeps every version-1 field unchanged and adds
`pattern_analysis`: the newest succeeded or partial analysis run of the
version (steps, rule set, string counts, findings with byte evidence), or
null if there is none.

The committed JSON Schema, `schemas/report.schema.json`, is generated from
these models (`make schemas`), and a test keeps the two identical.

There is deliberately no field for a verdict, a score, or a "malicious/safe"
judgement. Entropy is a measurement with its unit and method.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

REPORT_KIND = "bytasm.sample_version_report"
SCHEMA_VERSION = 2
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
    "pattern_analysis": (
        "The newest analysis run of this version that kept results (succeeded or partial), "
        "or null. Findings are YARA-X rule matches with the exact byte ranges matched: "
        "observations, not verdicts. Strings appear as counts only."
    ),
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


class PatternRun(_Model):
    id: str
    status: Literal["succeeded", "partial"]
    failure_reason: str | None
    status_message: str | None = Field(
        description="For a partial run, which steps did not complete and what that means."
    )
    profile: dict[str, Any]
    bytasm_version: str
    queued_at: datetime
    started_at: datetime
    finished_at: datetime


class PatternStep(_Model):
    index: int
    tool: str
    adapter: str
    status: Literal["succeeded", "failed", "timed_out", "cancelled", "skipped"]
    message: str | None
    tool_version: str | None
    adapter_version: str | None
    duration_ms: int | None
    result_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    execution: Literal["separate_resource_limited_process"]


class PatternRuleSet(_Model):
    tool: Literal["yara-x"]
    name: str
    version: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: Literal["bytasm-repo"]
    rule_count: int


class StringsCounts(_Model):
    encodings: list[Literal["ascii", "utf-16le"]]
    min_length: int
    total_found: int
    found_by_encoding: dict[str, int]
    stored: int
    truncated: bool
    values_included: Literal[False]


class PatternEvidence(_Model):
    kind: Literal["byte_range"]
    pattern_id: str
    file_offset: int = Field(ge=0)
    length: int = Field(ge=0)
    xor_key: int | None
    excerpt_hex: str = Field(pattern=r"^([0-9a-f]{2}){0,32}$")
    excerpt_truncated: bool
    raw_json_pointer: str


class PatternFinding(_Model):
    kind: Literal["yara_match"]
    tool: Literal["yara-x"]
    tool_version: str
    rule_id: str
    rule_namespace: str
    title: str
    tags: list[str]
    metadata: list[tuple[str, str | int | float | bool]]
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    match_count: int
    evidence_truncated: bool
    evidence: list[PatternEvidence] = Field(min_length=1)


class PatternAnalysis(_Model):
    run: PatternRun
    steps: list[PatternStep]
    rule_set: PatternRuleSet | None
    strings: StringsCounts | None
    findings: list[PatternFinding]
    notices: list[str]


class Report(_Model):
    model_config = ConfigDict(
        extra="forbid",
        title="Bytasm sample version report",
        json_schema_extra={"$id": SCHEMA_ID},
    )

    report_kind: Literal["bytasm.sample_version_report"]
    schema_version: Literal[2]
    generated_at: datetime
    generator: Generator
    sample: SampleIdentity
    input_policy: InputPolicy
    authorization: Authorization
    analysis: Analysis
    metadata: Metadata
    pattern_analysis: PatternAnalysis | None
    labels: dict[str, str]
    limitations: list[str]


def json_schema() -> dict[str, Any]:
    schema = Report.model_json_schema()
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **schema}


if __name__ == "__main__":
    import json
    import sys

    sys.stdout.write(json.dumps(json_schema(), indent=2, sort_keys=True) + "\n")
