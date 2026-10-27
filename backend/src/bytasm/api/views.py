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
    """The v0.1 metadata invocation: first step of the version's (only) run."""
    return version.runs[0].invocations[0]


def version_summary(version: SampleVersion) -> VersionSummary:
    invocation = invocation_of(version)
    return VersionSummary(
        id=version.id,
        version_label=version.version_label,
        sha256=version.sha256,
        size_bytes=version.size_bytes,
        detected_format=version.detected_format,
        architecture=str(invocation.header["architecture"]),
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
    invocation = invocation_of(version)
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
            exit_code=invocation.exit_code,
            duration_ms=invocation.duration_ms,
            result_sha256=invocation.raw_output_sha256,
            entropy_method=invocation.entropy_method,
        ),
        header=dict(invocation.header),
        warnings=list(invocation.warnings),
        counts={
            "sections": len(invocation.sections),
            "imported_libraries": len(invocation.header.get("imported_libraries", [])),
            "imported_functions": imports,
            "exports": len(invocation.symbols) - imports,
        },
    )


def sections_of(invocation: ToolInvocation) -> list[Section]:
    return list(invocation.sections)


def symbols_of(invocation: ToolInvocation, direction: str) -> list[str]:
    return sorted(s.name for s in invocation.symbols if s.direction == direction)
