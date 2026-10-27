"""Read and create endpoints for projects, samples and sample versions (blueprint 7.2)."""

import sys

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from bytasm import __version__
from bytasm.api.context import AppContext
from bytasm.api.problems import problem
from bytasm.api.schemas import (
    ExportsOut,
    HealthOut,
    ImportsOut,
    InputPolicyOut,
    ProjectIn,
    ProjectOut,
    SampleOut,
    SampleVersionOut,
    SectionOut,
    SectionsOut,
)
from bytasm.api.views import (
    invocation_of,
    project_out,
    sample_out,
    sample_version_out,
    sections_of,
    symbols_of,
)
from bytasm.db.models import Project, Sample, SampleVersion

router = APIRouter()


def _ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def _not_found(request: Request, what: str) -> JSONResponse:
    return problem(
        "not_found", detail=f"No {what} with this ID.", request_id=request.state.request_id
    )


@router.get("/health", response_model=HealthOut)
def health(request: Request) -> HealthOut:
    settings = _ctx(request).settings
    return HealthOut(
        status="ok",
        bytasm_version=__version__,
        input_policy=InputPolicyOut(
            mode=settings.input_policy,
            self_built_enabled=settings.input_policy == "self_built",
        ),
        max_upload_bytes=settings.max_upload_bytes,
        parser_timeout_seconds=settings.limits.timeout_seconds,
        platform=sys.platform,
        parser_memory_limit_enforced=sys.platform == "linux",
    )


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(request: Request) -> list[ProjectOut]:
    with _ctx(request).sessions() as session:
        projects = session.scalars(select(Project).order_by(Project.created_at, Project.id))
        return [project_out(session, project) for project in projects]


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(request: Request, body: ProjectIn) -> ProjectOut:
    with _ctx(request).sessions() as session:
        project = Project(name=body.name, description=body.description)
        session.add(project)
        session.commit()
        return project_out(session, project)


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(request: Request, project_id: str) -> ProjectOut | JSONResponse:
    with _ctx(request).sessions() as session:
        project = session.get(Project, project_id)
        if project is None:
            return _not_found(request, "project")
        return project_out(session, project)


@router.get("/projects/{project_id}/samples", response_model=list[SampleOut])
def list_samples(request: Request, project_id: str) -> list[SampleOut] | JSONResponse:
    with _ctx(request).sessions() as session:
        if session.get(Project, project_id) is None:
            return _not_found(request, "project")
        samples = session.scalars(
            select(Sample).where(Sample.project_id == project_id).order_by(Sample.name)
        )
        return [sample_out(sample) for sample in samples]


@router.get("/sample-versions/{version_id}", response_model=SampleVersionOut)
def get_sample_version(request: Request, version_id: str) -> SampleVersionOut | JSONResponse:
    with _ctx(request).sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            return _not_found(request, "sample version")
        return sample_version_out(version)


@router.get("/sample-versions/{version_id}/sections", response_model=SectionsOut)
def get_sections(request: Request, version_id: str) -> SectionsOut | JSONResponse:
    with _ctx(request).sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            return _not_found(request, "sample version")
        invocation = invocation_of(version)
        return SectionsOut(
            entropy_method=invocation.entropy_method,
            sections=[SectionOut.model_validate(s) for s in sections_of(invocation)],
        )


@router.get("/sample-versions/{version_id}/imports", response_model=ImportsOut)
def get_imports(request: Request, version_id: str) -> ImportsOut | JSONResponse:
    with _ctx(request).sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            return _not_found(request, "sample version")
        invocation = invocation_of(version)
        return ImportsOut(
            libraries=list(invocation.header.get("imported_libraries", [])),
            functions=symbols_of(invocation, "import"),
        )


@router.get("/sample-versions/{version_id}/exports", response_model=ExportsOut)
def get_exports(request: Request, version_id: str) -> ExportsOut | JSONResponse:
    with _ctx(request).sessions() as session:
        version = session.get(SampleVersion, version_id)
        if version is None:
            return _not_found(request, "sample version")
        return ExportsOut(functions=symbols_of(invocation_of(version), "export"))
