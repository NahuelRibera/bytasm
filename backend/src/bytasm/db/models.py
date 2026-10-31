"""SQLAlchemy models: the v0.1 subset of the data model plus the v0.2
pattern-matching tables (blueprint section 6).

v0.1: every row below `sample_version` is written by one successful import,
in one transaction. A failed or rejected import writes no rows at all.

v0.2: an analysis run (`kind = "analysis"`) is created `queued` by the API and
moved through its states by the worker (`bytasm.jobs.runs` lists the allowed
transitions). Its tool invocation, findings and evidence are written in the
same transaction that marks it `succeeded`; a failed or cancelled run has no
findings. Findings are observations ("rule X matched"), never verdicts: there
is no severity, score, or malicious/safe field.

Values derived from the file (section and symbol names, the declared file
name) are untrusted text. They are stored as-is and only ever rendered as
escaped text.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    text,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

_U64_OFFSET = 1 << 64
_I64_MAX = (1 << 63) - 1


class U64(TypeDecorator[int]):
    """An unsigned 64-bit integer stored in a signed 64-bit column.

    Addresses and offsets can use all 64 bits, but SQLite integers are signed.
    Values above 2**63 - 1 are stored as their two's-complement negative.
    """

    impl = Integer
    cache_ok = True

    def process_bind_param(self, value: int | None, dialect: Dialect) -> int | None:
        if value is None:
            return None
        if not 0 <= value < _U64_OFFSET:
            raise ValueError("value out of unsigned 64-bit range")
        return value - _U64_OFFSET if value > _I64_MAX else value

    def process_result_value(self, value: int | None, dialect: Dialect) -> int | None:
        if value is None:
            return None
        return value + _U64_OFFSET if value < 0 else value


def new_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes stored as ISO 8601 text."""

    impl = String(32)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    def process_result_value(self, value: str | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Base(DeclarativeBase):
    pass


class ActivityEvent(Base):
    """Append-only project audit record; local actors have no account or OS identity.

    Payloads contain only minimal references, never user text or file contents.
    Application code never updates or deletes events. This is an audit trail,
    not protection against someone who can write the database directly.
    """

    __tablename__ = "activity_event"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    actor_id: Mapped[str] = mapped_column(String(32))
    type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    at: Mapped[datetime] = mapped_column(UtcDateTime)


class Project(Base):
    __tablename__ = "project"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    samples: Mapped[list["Sample"]] = relationship(back_populates="project", order_by="Sample.name")


class Sample(Base):
    __tablename__ = "sample"
    __table_args__ = (UniqueConstraint("project_id", "name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    project: Mapped[Project] = relationship(back_populates="samples")
    versions: Mapped[list["SampleVersion"]] = relationship(
        back_populates="sample", order_by="SampleVersion.imported_at"
    )


class SampleVersion(Base):
    __tablename__ = "sample_version"
    __table_args__ = (UniqueConstraint("sample_id", "sha256"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    sample_id: Mapped[str] = mapped_column(ForeignKey("sample.id"), index=True)
    version_label: Mapped[str | None] = mapped_column(String(100))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    declared_filename: Mapped[str | None] = mapped_column(String(255))  # untrusted
    detected_format: Mapped[str] = mapped_column(String(8))  # "PE" or "ELF"
    blob_path: Mapped[str] = mapped_column(String(128))  # relative to the blob store
    admitted_under: Mapped[str] = mapped_column(String(32))  # fixture_manifest|self_built_optin
    manifest_entry: Mapped[str | None] = mapped_column(String(255))
    imported_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    sample: Mapped[Sample] = relationship(back_populates="versions")
    authorization: Mapped["AuthorizationRecord"] = relationship(back_populates="sample_version")
    runs: Mapped[list["AnalysisRun"]] = relationship(
        back_populates="sample_version", order_by="AnalysisRun.id"
    )


class AuthorizationRecord(Base):
    """A self-attestation for record-keeping. Not proof of permission."""

    __tablename__ = "authorization_record"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    sample_version_id: Mapped[str] = mapped_column(ForeignKey("sample_version.id"), unique=True)
    basis: Mapped[str] = mapped_column(String(32))  # only "owned_or_built" in v0.1
    statement: Mapped[str] = mapped_column(Text)
    terms_reference: Mapped[str | None] = mapped_column(Text)  # unused in v0.1
    recorded_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    sample_version: Mapped[SampleVersion] = relationship(back_populates="authorization")


class AnalysisRun(Base):
    __tablename__ = "analysis_run"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    sample_version_id: Mapped[str] = mapped_column(ForeignKey("sample_version.id"), index=True)
    # "import": the v0.1 metadata run written by an import (always succeeded).
    # "analysis": a v0.2 pattern-matching run, processed by the worker.
    kind: Mapped[str] = mapped_column(String(16), server_default=text("'import'"))
    profile_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    # queued | running | succeeded | partial | failed | cancelled (import runs: succeeded)
    status: Mapped[str] = mapped_column(String(16))
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    queued_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, server_default=false())
    cancel_requested_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    bytasm_version: Mapped[str] = mapped_column(String(32))
    image_digest: Mapped[str | None] = mapped_column(String(128))

    sample_version: Mapped[SampleVersion] = relationship(back_populates="runs")
    invocations: Mapped[list["ToolInvocation"]] = relationship(
        back_populates="run", order_by="ToolInvocation.step_index"
    )


class RuleSet(Base):
    """One exact version of Bytasm's bundled rule set, identified by its SHA-256.

    The snapshot (all rule files, see bytasm.rules) is kept in the outputs
    store under that hash, so a run can always show the rule text it used.
    """

    __tablename__ = "rule_set"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    tool: Mapped[str] = mapped_column(String(16))  # "yara-x"
    name: Mapped[str] = mapped_column(String(64))
    version: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    source: Mapped[str] = mapped_column(String(32))  # "bytasm-repo"
    snapshot_path: Mapped[str] = mapped_column(String(128))  # relative to the outputs store
    rule_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class ToolInvocation(Base):
    """The provenance anchor: which tool, which version, which output."""

    __tablename__ = "tool_invocation"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_run.id"), index=True)
    step_index: Mapped[int] = mapped_column(Integer)
    tool_name: Mapped[str] = mapped_column(String(32))
    tool_version: Mapped[str] = mapped_column(String(32))
    adapter_name: Mapped[str] = mapped_column(String(32))
    adapter_version: Mapped[str] = mapped_column(String(32))
    args: Mapped[dict[str, Any]] = mapped_column(JSON)
    # succeeded | failed | timed_out | cancelled. A step with no row was not run.
    status: Mapped[str] = mapped_column(String(16))
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int] = mapped_column(Integer)
    # v0.2 analysis steps only (import invocations have the run's times).
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # Strings step only: counts from the validated result (no string values).
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    # Only a succeeded step has a stored raw output.
    raw_output_path: Mapped[str | None] = mapped_column(String(128))
    raw_output_sha256: Mapped[str | None] = mapped_column(String(64))
    rule_set_id: Mapped[str | None] = mapped_column(ForeignKey("rule_set.id"), index=True)
    # LIEF metadata step only.
    entropy_method: Mapped[str | None] = mapped_column(String(32))
    # File-level values as declared in the header: architecture, bitness,
    # endianness, entry point, declared_header, imported libraries.
    header: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    warnings: Mapped[list[str]] = mapped_column(JSON)

    run: Mapped[AnalysisRun] = relationship(back_populates="invocations")
    rule_set: Mapped[RuleSet | None] = relationship()
    sections: Mapped[list["Section"]] = relationship(order_by="Section.index")
    symbols: Mapped[list["Symbol"]] = relationship(order_by="Symbol.id")


class Finding(Base):
    """One machine-generated observation: a rule matched. Not a verdict."""

    __tablename__ = "finding"
    __table_args__ = (UniqueConstraint("invocation_id", "rule_namespace", "rule_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("analysis_run.id"), index=True)
    invocation_id: Mapped[str] = mapped_column(ForeignKey("tool_invocation.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # "yara_match"
    title: Mapped[str] = mapped_column(String(200))
    rule_id: Mapped[str] = mapped_column(String(128))  # the rule's identifier
    rule_namespace: Mapped[str] = mapped_column(String(128))
    rule_set_id: Mapped[str] = mapped_column(ForeignKey("rule_set.id"), index=True)
    # Rule tags and metadata exactly as YARA-X reported them (untrusted text).
    tool_reported_attributes: Mapped[dict[str, Any]] = mapped_column(JSON)
    # Stable key for comparing runs: SHA-256 of "yara-x:<namespace>:<rule>".
    fingerprint: Mapped[str] = mapped_column(String(64))
    # Matches YARA-X reported, summed over patterns (each capped per pattern).
    match_count: Mapped[int] = mapped_column(Integer)
    # True when YARA-X's per-pattern cap or Bytasm's evidence cap was reached.
    evidence_truncated: Mapped[bool] = mapped_column(Boolean)

    evidence: Mapped[list["Evidence"]] = relationship(
        order_by="Evidence.id", back_populates="finding"
    )


class Evidence(Base):
    """A byte range in the sample that a rule pattern matched."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # byte_range or virtual_address
    pattern_id: Mapped[str] = mapped_column(String(128))  # e.g. "$https"
    file_offset: Mapped[int | None] = mapped_column(U64)
    length: Mapped[int | None] = mapped_column(Integer)
    virtual_address: Mapped[int | None] = mapped_column(U64)
    xor_key: Mapped[int | None] = mapped_column(Integer)
    # At most the first 32 matched bytes, hex-encoded.
    excerpt_hex: Mapped[str] = mapped_column(String(64))
    # RFC 6901 pointer into the invocation's raw output.
    raw_json_pointer: Mapped[str] = mapped_column(String(256))

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class StringOccurrence(Base):
    """A printable ASCII or UTF-16LE run found by the strings step. An observation.

    The value is untrusted text from the sample, cut to its first 256
    characters (`value_truncated`); `length_chars` and `byte_length` describe
    the whole run.
    """

    __tablename__ = "string_occurrence"
    __table_args__ = (UniqueConstraint("invocation_id", "file_offset", "encoding"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    invocation_id: Mapped[str] = mapped_column(ForeignKey("tool_invocation.id"), index=True)
    file_offset: Mapped[int] = mapped_column(U64)
    encoding: Mapped[str] = mapped_column(String(16))  # "ascii" | "utf-16le"
    length_chars: Mapped[int] = mapped_column(U64)
    byte_length: Mapped[int] = mapped_column(U64)
    value: Mapped[str] = mapped_column(String(256))  # untrusted
    value_truncated: Mapped[bool] = mapped_column(Boolean)


class Section(Base):
    __tablename__ = "section"
    __table_args__ = (UniqueConstraint("invocation_id", "index"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    invocation_id: Mapped[str] = mapped_column(ForeignKey("tool_invocation.id"), index=True)
    index: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(Text)  # untrusted
    section_type: Mapped[str | None] = mapped_column(String(64))
    file_offset: Mapped[int] = mapped_column(U64)
    raw_size: Mapped[int] = mapped_column(U64)
    virtual_address: Mapped[int] = mapped_column(U64)
    virtual_size: Mapped[int] = mapped_column(U64)
    flags: Mapped[list[str]] = mapped_column(JSON)
    entropy: Mapped[float | None] = mapped_column()  # bits per byte; a measurement
    entropy_note: Mapped[str | None] = mapped_column(String(64))


class Symbol(Base):
    __tablename__ = "symbol"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    invocation_id: Mapped[str] = mapped_column(ForeignKey("tool_invocation.id"), index=True)
    direction: Mapped[str] = mapped_column(String(8))  # "import" or "export"
    # The v0.1 adapter reports imported functions without their library.
    library: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)  # untrusted
    ordinal: Mapped[int | None] = mapped_column(Integer)
    address: Mapped[int | None] = mapped_column(U64)


class Report(Base):
    __tablename__ = "report"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    sample_version_id: Mapped[str] = mapped_column(ForeignKey("sample_version.id"), index=True)
    format: Mapped[str] = mapped_column(String(8))  # "json"
    scope: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    generated_at: Mapped[datetime] = mapped_column(UtcDateTime)
    generator_version: Mapped[str] = mapped_column(String(32))
    path: Mapped[str] = mapped_column(String(128))  # relative to the report store


class Analyst(Base):
    __tablename__ = "analyst"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Annotation(Base):
    """One immutable revision; root_id identifies the annotation across edits."""

    __tablename__ = "annotation"
    __table_args__ = (UniqueConstraint("root_id", "revision"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    root_id: Mapped[str] = mapped_column(ForeignKey("annotation.id"), index=True)
    supersedes_id: Mapped[str | None] = mapped_column(ForeignKey("annotation.id"), unique=True)
    revision: Mapped[int] = mapped_column(Integer)
    version_id: Mapped[str] = mapped_column(ForeignKey("sample_version.id"), index=True)
    target_type: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[str] = mapped_column(String(32))
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("finding.id"))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"))
    kind: Mapped[str] = mapped_column(String(16))
    body: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(String(16))
    author_id: Mapped[str] = mapped_column(ForeignKey("analyst.id"))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class AnnotationCitation(Base):
    __tablename__ = "annotation_citation"
    __table_args__ = (UniqueConstraint("annotation_id", "target_type", "target_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    annotation_id: Mapped[str] = mapped_column(ForeignKey("annotation.id"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    target_type: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[str] = mapped_column(String(32))
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("finding.id"))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"))


class ReviewSnapshot(Base):
    """Immutable canonical review; never an alias for a live run selection."""

    __tablename__ = "review_snapshot"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    version_id: Mapped[str] = mapped_column(ForeignKey("sample_version.id"), index=True)
    supersedes_id: Mapped[str | None] = mapped_column(ForeignKey("review_snapshot.id"))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)
    sha256: Mapped[str] = mapped_column(String(64))
    canonical: Mapped[str] = mapped_column(Text)


class FunctionReviewRevision(Base):
    """Immutable analyst overlay, identified by an exact function/output scope."""

    __tablename__ = "function_review_revision"
    __table_args__ = (UniqueConstraint("scope_sha256", "revision"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    version_id: Mapped[str] = mapped_column(ForeignKey("sample_version.id"), index=True)
    invocation_id: Mapped[str] = mapped_column(ForeignKey("tool_invocation.id"), index=True)
    scope_sha256: Mapped[str] = mapped_column(String(64), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    document_sha256: Mapped[str] = mapped_column(String(64))
