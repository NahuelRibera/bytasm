"""Request and response bodies of the v0.1 API (blueprint 7.2)."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ProjectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""


class ProjectOut(_Out):
    id: str
    name: str
    description: str
    created_at: datetime
    sample_count: int


class VersionSummary(_Out):
    id: str
    version_label: str | None
    sha256: str
    size_bytes: int
    detected_format: str
    architecture: str
    admitted_under: str
    imported_at: datetime


class SampleOut(_Out):
    id: str
    name: str
    versions: list[VersionSummary]


class InputPolicyOut(BaseModel):
    mode: Literal["fixtures", "self_built"]
    self_built_enabled: bool


class HealthOut(BaseModel):
    status: Literal["ok"]
    bytasm_version: str
    input_policy: InputPolicyOut
    max_upload_bytes: int
    parser_timeout_seconds: float
    platform: str
    # False when the platform could not apply every parser resource limit
    # (macOS cannot apply RLIMIT_AS).
    parser_memory_limit_enforced: bool


class AuthorizationOut(_Out):
    type: Literal["self_attestation"] = "self_attestation"
    basis: str
    statement: str
    terms_reference: str | None
    recorded_at: datetime
    notice: str


class InvocationOut(BaseModel):
    tool: str
    tool_version: str
    adapter: str
    adapter_version: str
    status: str
    exit_code: int
    duration_ms: int
    result_sha256: str
    entropy_method: str


class SampleVersionOut(BaseModel):
    id: str
    project_id: str
    project_name: str
    sample_id: str
    sample_name: str
    version_label: str | None
    sha256: str
    size_bytes: int
    declared_filename: str | None
    detected_format: str
    admitted_under: str
    manifest_entry: str | None
    imported_at: datetime
    authorization: AuthorizationOut
    invocation: InvocationOut
    header: dict[str, Any]
    warnings: list[str]
    counts: dict[str, int]


class SectionOut(_Out):
    index: int
    name: str
    section_type: str | None
    file_offset: int
    raw_size: int
    virtual_address: int
    virtual_size: int
    flags: list[str]
    entropy: float | None
    entropy_note: str | None


class SectionsOut(BaseModel):
    entropy_method: str
    entropy_unit: Literal["bits_per_byte"] = "bits_per_byte"
    sections: list[SectionOut]


class ImportsOut(BaseModel):
    libraries: list[str]
    functions: list[str]


class ExportsOut(BaseModel):
    functions: list[str]


class ImportCreated(BaseModel):
    sample_version: SampleVersionOut


class ReportCreated(BaseModel):
    id: str
    sample_version_id: str
    format: Literal["json"]
    sha256: str
    generated_at: datetime
    download_url: str
