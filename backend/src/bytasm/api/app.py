"""Build the FastAPI application. Run it with `bytasm serve` (one process, loopback only)."""

import json
import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.body_limit import RequestBodyLimitMiddleware

from bytasm import __version__
from bytasm.api import imports, reports, routes
from bytasm.api.context import AppContext
from bytasm.api.guards import LocalOnlyGuard
from bytasm.api.maintenance import startup_sweep
from bytasm.api.problems import problem
from bytasm.api.web import add_web_routes
from bytasm.config import Settings
from bytasm.db.session import create_sqlite_engine, session_factory, upgrade_to_head
from bytasm.intake.manifest import Manifest, default_manifest_path
from bytasm.intake.policy import InputPolicy
from bytasm.provenance import current_generator
from bytasm.runner.supervisor import metadata_adapter_command
from bytasm.storage import ContentStore

log = logging.getLogger("bytasm.api")


def build_context(settings: Settings, adapter_command: Sequence[str] | None = None) -> AppContext:
    settings.validate()
    for directory in (
        settings.data_dir,
        settings.tmp_dir,
        settings.blobs_dir,
        settings.outputs_dir,
        settings.reports_dir,
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    engine = create_sqlite_engine(settings.database_path)
    upgrade_to_head(engine)
    return AppContext(
        settings=settings,
        policy=InputPolicy(settings.input_policy, Manifest.load(default_manifest_path())),
        engine=engine,
        sessions=session_factory(engine),
        blobs=ContentStore(settings.blobs_dir),
        outputs=ContentStore(settings.outputs_dir),
        reports=ContentStore(settings.reports_dir),
        adapter_command=list(adapter_command or metadata_adapter_command()),
        generator=current_generator(),
    )


def create_app(settings: Settings, adapter_command: Sequence[str] | None = None) -> FastAPI:
    """`adapter_command` replaces the LIEF adapter in tests (fake adapters)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        ctx = build_context(settings, adapter_command)
        swept = startup_sweep(ctx)
        log.info(
            json.dumps(
                {
                    "event": "startup",
                    "input_policy": settings.input_policy,
                    "sweep": swept.__dict__,
                },
                sort_keys=True,
            )
        )
        if settings.input_policy == "self_built":
            log.warning(
                "self_built input mode is ENABLED (local configuration). Only import "
                "binaries you compiled from source you wrote. It is not a sandbox."
            )
        app.state.ctx = ctx
        yield
        ctx.engine.dispose()

    app = FastAPI(
        title="Bytasm local API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.include_router(routes.router, prefix="/api/v1")
    app.include_router(imports.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    add_web_routes(app, settings.web_dist)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, _exc: RequestValidationError) -> JSONResponse:
        return problem("invalid_request", request_id=request.state.request_id)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code in (404, 405) else "internal_error"
        return problem(code, request_id=request.state.request_id)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.error(
            json.dumps(
                {
                    "event": "unhandled_error",
                    "request_id": request.state.request_id,
                    "error_type": type(exc).__name__,
                }
            )
        )
        return problem("internal_error", request_id=request.state.request_id)

    # Defence in depth for the JSON endpoints, whose bodies FastAPI reads into
    # memory. The import endpoint enforces its own, lower limit while streaming,
    # so it always refuses before this one would.
    app.add_middleware(
        RequestBodyLimitMiddleware, max_body_size=settings.max_upload_bytes + 1024 * 1024
    )
    app.add_middleware(
        LocalOnlyGuard,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=settings.allowed_origins,
        require_loopback_listener=not settings.container,
    )
    return app
