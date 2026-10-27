"""Helpers for API tests: settings, clients, imports, and live uvicorn servers.

API tests use a fresh data directory per test. Inputs are committed fixtures
or bytes generated in memory; nothing is executed. Tests that need generated
(non-manifest) inputs to reach the parser use `self_built` mode, which is
allowed because those bytes are test-authored (blueprint 9.2).
"""

import socket
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from bytasm.api.app import create_app
from bytasm.api.context import AppContext
from bytasm.config import Settings
from bytasm.db.models import Base
from bytasm.intake.import_metadata import encode_import_header

FAKE_ADAPTER = Path(__file__).resolve().parent / "fake_adapters" / "fake_adapter.py"
STATEMENT = "I built this fixture from source written for Bytasm."


def fake_adapter(behaviour: str) -> list[str]:
    return [sys.executable, "-I", str(FAKE_ADAPTER), behaviour]


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    settings = Settings(data_dir=tmp_path / "data", port=8000, web_dist=None)
    return replace(settings, **overrides)


@contextmanager
def api_client(
    settings: Settings,
    adapter_command: list[str] | None = None,
    *,
    raise_server_exceptions: bool = True,
) -> Iterator[TestClient]:
    """An in-process client. Note: it reads a streamed request body completely on
    the first `receive()`, so tests about where reading *stops* use live_server."""
    app = create_app(settings, adapter_command)
    with TestClient(
        app,
        base_url=f"http://127.0.0.1:{settings.port}",
        headers={"X-Bytasm-Request": "1"},
        raise_server_exceptions=raise_server_exceptions,
    ) as client:
        yield client


def ctx_of(client: TestClient) -> AppContext:
    app: FastAPI = client.app  # type: ignore[assignment]
    ctx: AppContext = app.state.ctx
    return ctx


def create_project(client: TestClient, name: str = "Demo") -> str:
    response = client.post("/api/v1/projects", json={"name": name})
    assert response.status_code == 201, response.text
    project_id: str = response.json()["id"]
    return project_id


def import_metadata(**fields: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "authorization": {"basis": "owned_or_built", "statement": STATEMENT},
    }
    if "sample_id" not in fields:
        document["sample_name"] = "my-sample"
    document.update(fields)
    return document


def import_headers(**fields: Any) -> dict[str, str]:
    return {
        "X-Bytasm-Import": encode_import_header(import_metadata(**fields)),
        "Content-Type": "application/octet-stream",
    }


def do_import(client: TestClient, project_id: str, data: bytes, **fields: Any) -> httpx.Response:
    response: httpx.Response = client.post(
        f"/api/v1/projects/{project_id}/imports", content=data, headers=import_headers(**fields)
    )
    return response


def row_counts(ctx: AppContext) -> dict[str, int]:
    with ctx.engine.connect() as connection:
        return {
            table.name: len(connection.execute(table.select()).fetchall())
            for table in Base.metadata.sorted_tables
        }


def stored_files(ctx: AppContext) -> list[Path]:
    return sorted(
        path
        for root in (ctx.blobs.root, ctx.outputs.root, ctx.reports.root)
        for path in root.rglob("*")
        if path.is_file()
    )


def temp_entries(ctx: AppContext) -> list[Path]:
    return sorted(ctx.tmp_dir.iterdir()) if ctx.tmp_dir.exists() else []


def assert_nothing_imported(ctx: AppContext) -> None:
    counts = row_counts(ctx)
    for table in (
        "sample_version",
        "authorization_record",
        "analysis_run",
        "tool_invocation",
        "section",
        "symbol",
    ):
        assert counts[table] == 0, f"{table} has rows"
    assert stored_files(ctx) == []
    assert temp_entries(ctx) == []


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@contextmanager
def live_server(
    tmp_path: Path, adapter_command: list[str] | None = None, **overrides: Any
) -> Iterator[tuple[Settings, AppContext]]:
    """Run the app under a real uvicorn server (h11) on a free loopback port."""
    settings = make_settings(tmp_path, port=free_port(), **overrides)
    app = create_app(settings, adapter_command)
    config = uvicorn.Config(app, host="127.0.0.1", port=settings.port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    try:
        yield settings, app.state.ctx
    finally:
        server.should_exit = True
        thread.join(timeout=15)


def wait_until(predicate: Any, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return bool(predicate())
