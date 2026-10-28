"""Request and response bodies of the API (blueprint 7.2): v0.1 and v0.2."""

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
    # v0.2: the pinned YARA-X package, and when a worker last checked in
    # (None: no worker has run for this data directory).
    yara_x_version: str
    worker_last_seen_seconds: float | None


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


# v0.2: rule set, analysis runs, findings (blueprint 7.2)


class RuleFileOut(BaseModel):
    name: str
    identifier: str
    # Exactly the text used (rule files are newline-terminated in the snapshot).
    text: str


class RuleSetOut(BaseModel):
    id: str | None  # None until a run has used this exact rule set
    tool: Literal["yara-x"]
    name: str
    version: str
    label: str
    sha256: str
    source: str
    current: bool  # the rule set on disk now has this hash
    rule_count: int
    files: list[RuleFileOut]
    installed_yara_x_version: str


class DiagnosticOut(BaseModel):
    code: str
    title: str
    file: str | None
    line: int | None
    column: int | None


class RuleValidationOut(BaseModel):
    rule_set_sha256: str
    label: str
    yara_x_version: str
    compiled: bool
    rule_identifiers: list[str]
    # Files whose rule identifier is missing from the compiled rules.
    problems: list[str]
    errors: list[DiagnosticOut]
    warnings: list[DiagnosticOut]
    duration_ms: int


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: Literal["default-static"]


class RuleSetRef(BaseModel):
    id: str
    label: str
    sha256: str


class RunSampleOut(BaseModel):
    project_id: str
    project_name: str
    sample_id: str
    sample_name: str
    version_id: str
    version_label: str | None
    sha256: str
    size_bytes: int
    detected_format: str
    admitted_under: str


StepStatus = Literal[
    "queued", "running", "succeeded", "failed", "timed_out", "cancelled", "skipped"
]


class StringsSummaryOut(BaseModel):
    """Counts from a succeeded strings step (no values)."""

    total_found: int
    found_by_encoding: dict[str, int]
    stored: int
    truncated: bool


class RunStepOut(BaseModel):
    index: int
    tool: str
    adapter: str
    # `skipped`: the step was not run (no invocation); see `message`.
    status: StepStatus
    message: str | None
    invocation_id: str | None
    tool_version: str | None
    adapter_version: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    timeout_seconds: float
    failure_reason: str | None
    raw_output_sha256: str | None
    strings: StringsSummaryOut | None
    warnings: list[str]


class RunCounts(BaseModel):
    findings: int
    evidence: int
    strings: int


class RunOut(BaseModel):
    id: str
    status: Literal["queued", "running", "succeeded", "partial", "failed", "cancelled"]
    failure_reason: str | None
    # Plain-language summary for partial, failed and cancelled runs (fixed text).
    failure_message: str | None
    cancel_requested: bool
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    bytasm_version: str
    profile_id: str
    profile_name: str
    rule_set: RuleSetRef
    sample: RunSampleOut
    steps: list[RunStepOut]
    counts: RunCounts


class RunsOut(BaseModel):
    runs: list[RunOut]


class EvidenceOut(BaseModel):
    id: int
    kind: Literal["byte_range"]
    pattern_id: str
    file_offset: int
    length: int
    xor_key: int | None
    # At most the first 32 matched bytes, hex-encoded; `excerpt_truncated`
    # when the match is longer than the excerpt.
    excerpt_hex: str
    excerpt_truncated: bool
    raw_json_pointer: str


class FindingOut(BaseModel):
    id: str
    kind: Literal["yara_match"]
    title: str
    rule_id: str
    rule_namespace: str
    rule_set_id: str
    tags: list[str]
    metadata: list[tuple[str, str | int | float | bool]]
    fingerprint: str
    match_count: int
    evidence_truncated: bool
    evidence: list[EvidenceOut]


class FindingsFilterOut(BaseModel):
    tool: str | None
    kind: str | None
    q: str | None


class FindingsOut(BaseModel):
    run_id: str
    run_status: str
    # The run's partial/cancelled/failed banner text, if any.
    run_message: str | None
    # Findings of the run before filtering, and the filter applied.
    total: int
    filters: FindingsFilterOut
    available_tools: list[str]
    available_kinds: list[str]
    findings: list[FindingOut]
    notices: list[str]


class StringOut(BaseModel):
    offset: int
    encoding: Literal["ascii", "utf-16le"]
    length_chars: int
    byte_length: int
    # Untrusted text from the sample: the first 256 characters of the run.
    value: str
    value_truncated: bool


class StringsOut(BaseModel):
    version_id: str
    # The run whose strings step produced these rows; null if none has yet.
    run_id: str | None
    run_status: str | None
    invocation_id: str | None
    tool_version: str | None
    min_length: int
    encodings: list[str]
    summary: StringsSummaryOut | None
    query: str | None
    encoding: str | None
    # Rows matching query/encoding, before offset/limit.
    matched: int
    offset: int
    limit: int
    items: list[StringOut]
    notices: list[str]


class RunLogEntryOut(BaseModel):
    seq: int
    at: datetime | None
    step_index: int | None
    message: str


class RunLogOut(BaseModel):
    run_id: str
    entries: list[RunLogEntryOut]
    # Pass as `after` to get only newer entries.
    next_cursor: int
    complete: bool
