"""SQLAlchemy models: the v0.1 subset of the data model (blueprint section 6).

Every row below `sample_version` is written by one successful import, in one
transaction. A failed or rejected import writes no rows at all.

Values derived from the file (section and symbol names, the declared file
name) are untrusted text. They are stored as-is and only ever rendered as
escaped text.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String, Text, UniqueConstraint
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
    runs: Mapped[list["AnalysisRun"]] = relationship(back_populates="sample_version")


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
    profile_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16))  # only "succeeded" in v0.1
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime] = mapped_column(UtcDateTime)
    bytasm_version: Mapped[str] = mapped_column(String(32))
    image_digest: Mapped[str | None] = mapped_column(String(128))

    sample_version: Mapped[SampleVersion] = relationship(back_populates="runs")
    invocations: Mapped[list["ToolInvocation"]] = relationship(
        back_populates="run", order_by="ToolInvocation.step_index"
    )


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
    status: Mapped[str] = mapped_column(String(16))
    exit_code: Mapped[int] = mapped_column(Integer)
    duration_ms: Mapped[int] = mapped_column(Integer)
    raw_output_path: Mapped[str] = mapped_column(String(128))
    raw_output_sha256: Mapped[str] = mapped_column(String(64))
    entropy_method: Mapped[str] = mapped_column(String(32))
    # File-level values as declared in the header: architecture, bitness,
    # endianness, entry point, declared_header, imported libraries.
    header: Mapped[dict[str, Any]] = mapped_column(JSON)
    warnings: Mapped[list[str]] = mapped_column(JSON)

    run: Mapped[AnalysisRun] = relationship(back_populates="invocations")
    sections: Mapped[list["Section"]] = relationship(order_by="Section.index")
    symbols: Mapped[list["Symbol"]] = relationship(order_by="Symbol.id")


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
    sha256: Mapped[str] = mapped_column(String(64))
    generated_at: Mapped[datetime] = mapped_column(UtcDateTime)
    generator_version: Mapped[str] = mapped_column(String(32))
    path: Mapped[str] = mapped_column(String(128))  # relative to the report store
