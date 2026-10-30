"""Turn database rows into API response models."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from bytasm.api.schemas import (
    AuthorizationOut,
    InvocationOut,
    ProjectOut,
    SampleOut,
    SampleVersionOut,
    VersionSummary,
)
from bytasm.db.imported import import_record
from bytasm.db.models import Project, Sample, SampleVersion, Section, ToolInvocation
from bytasm.notices import AUTHORIZATION_NOTICE


def project_out(session: Session, project: Project) -> ProjectOut:
    count = session.scalar(
        select(func.count()).select_from(Sample).where(Sample.project_id == project.id)
    )
    return ProjectOut(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at,
        sample_count=count or 0,
    )


def invocation_of(version: SampleVersion) -> ToolInvocation:
    """The v0.1 metadata invocation of the version's import run."""
    return import_record(version).invocation


def version_summary(version: SampleVersion) -> VersionSummary:
    record = import_record(version)
    return VersionSummary(
        id=version.id,
        version_label=version.version_label,
        sha256=version.sha256,
        size_bytes=version.size_bytes,
        detected_format=version.detected_format,
        architecture=str(record.header["architecture"]),
        admitted_under=version.admitted_under,
        imported_at=version.imported_at,
    )


def sample_out(sample: Sample) -> SampleOut:
    return SampleOut(
        id=sample.id,
        name=sample.name,
        versions=[version_summary(version) for version in sample.versions],
    )


def sample_version_out(version: SampleVersion) -> SampleVersionOut:
    record = import_record(version)
    invocation = record.invocation
    authorization = version.authorization
    sample = version.sample
    imports = sum(1 for s in invocation.symbols if s.direction == "import")
    return SampleVersionOut(
        id=version.id,
        project_id=sample.project_id,
        project_name=sample.project.name,
        sample_id=sample.id,
        sample_name=sample.name,
        version_label=version.version_label,
        sha256=version.sha256,
        size_bytes=version.size_bytes,
        declared_filename=version.declared_filename,
        detected_format=version.detected_format,
        admitted_under=version.admitted_under,
        manifest_entry=version.manifest_entry,
        imported_at=version.imported_at,
        authorization=AuthorizationOut(
            basis=authorization.basis,
            statement=authorization.statement,
            terms_reference=authorization.terms_reference,
            recorded_at=authorization.recorded_at,
            notice=AUTHORIZATION_NOTICE,
        ),
        invocation=InvocationOut(
            tool=invocation.tool_name,
            tool_version=invocation.tool_version,
            adapter=invocation.adapter_name,
            adapter_version=invocation.adapter_version,
            status=invocation.status,
            exit_code=record.exit_code,
            duration_ms=invocation.duration_ms,
            result_sha256=record.raw_output_sha256,
            entropy_method=record.entropy_method,
        ),
        header={
            **record.header,
            "entry_point_hex": f"{record.header['entry_point']:#x}"
            if record.header.get("entry_point") is not None
            else None,
            "declared_header_exact": {
                key: f"{value:#x}"
                for key, value in record.header.get("declared_header", {}).items()
                if type(value) is int and key != "pe_timestamp"
            },
        },
        warnings=list(invocation.warnings),
        counts={
            "sections": len(invocation.sections),
            "imported_libraries": len(record.header.get("imported_libraries", [])),
            "imported_functions": imports,
            "exports": len(invocation.symbols) - imports,
        },
    )


def sections_of(invocation: ToolInvocation) -> list[Section]:
    return list(invocation.sections)


def symbols_of(invocation: ToolInvocation, direction: str) -> list[str]:
    return sorted(s.name for s in invocation.symbols if s.direction == direction)
