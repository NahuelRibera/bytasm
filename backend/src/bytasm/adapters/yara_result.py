"""Schema of the YARA-X adapter's `result.json`, validated by the parent.

Same rules as the metadata adapter's schema (`bytasm.adapters.result`): the
parent size-caps the file before reading it and validates it against these
models; unknown fields, wrong types, or anything over a cap make the whole
result invalid, and nothing from it is used.

The adapter reports only what the pinned YARA-X documents per match (offset
and length in bytes from the start of the scanned data, and the XOR key for
`xor` patterns), plus a capped hex excerpt that the adapter itself reads from
the admitted bytes at that offset.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr

from bytasm.adapters.result import InputResult, ResourceLimitsResult

ADAPTER_NAME = "yara_x_scan"
# Hard caps, enforced by the adapter and again by this schema.
MAX_RULES = 32
MAX_DIAGNOSTICS = 20
MAX_PATTERNS_PER_RULE = 32
MAX_EVIDENCE_PER_PATTERN = 20
MAX_EXCERPT_BYTES = 32
MAX_MATCHES_PER_PATTERN = 1000

Short = Annotated[StrictStr, Field(max_length=128)]
Text = Annotated[StrictStr, Field(max_length=512)]
Count = Annotated[StrictInt, Field(ge=0)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Diagnostic(_Strict):
    """One compiler error or warning: YARA-X's code and title, and where."""

    code: Annotated[StrictStr, Field(max_length=32)]
    title: Text
    file: Short | None
    line: Count | None
    column: Count | None


class RulesResult(_Strict):
    sha256: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    compiled: StrictBool
    rule_identifiers: Annotated[list[Short], Field(max_length=MAX_RULES)]
    errors: Annotated[list[Diagnostic], Field(max_length=MAX_DIAGNOSTICS)]
    warnings: Annotated[list[Diagnostic], Field(max_length=MAX_DIAGNOSTICS)]


class MatchResult(_Strict):
    offset: Count
    length: Annotated[StrictInt, Field(ge=0, le=1 << 32)]
    xor_key: Annotated[StrictInt, Field(ge=0, le=255)] | None
    excerpt_hex: Annotated[
        StrictStr, Field(max_length=2 * MAX_EXCERPT_BYTES, pattern=r"^([0-9a-f]{2})*$")
    ]


class PatternResult(_Strict):
    identifier: Short
    # Matches YARA-X reported for this pattern (it stops at the per-pattern cap).
    match_count: Annotated[StrictInt, Field(ge=0, le=MAX_MATCHES_PER_PATTERN)]
    matches: Annotated[list[MatchResult], Field(max_length=MAX_EVIDENCE_PER_PATTERN)]


MetaValue = Annotated[StrictStr, Field(max_length=512)] | StrictInt | StrictFloat | StrictBool


class RuleMatchResult(_Strict):
    identifier: Short
    namespace: Short
    tags: Annotated[list[Short], Field(max_length=16)]
    metadata: Annotated[list[tuple[Short, MetaValue]], Field(max_length=32)]
    patterns: Annotated[list[PatternResult], Field(max_length=MAX_PATTERNS_PER_RULE)]


class ScanResult(_Strict):
    status: Literal["completed", "timed_out"]
    max_matches_per_pattern: Count
    matching_rules: Annotated[list[RuleMatchResult], Field(max_length=MAX_RULES)]


class YaraAdapterResult(_Strict):
    schema_version: Literal[1]
    adapter: Literal["yara_x_scan"]
    adapter_version: Annotated[StrictStr, Field(max_length=32)]
    tool: Literal["yara-x"]
    tool_version: Annotated[StrictStr, Field(max_length=32)]
    mode: Literal["scan", "compile"]
    input: InputResult | None
    rules: RulesResult
    scan: ScanResult | None
    resource_limits: ResourceLimitsResult
