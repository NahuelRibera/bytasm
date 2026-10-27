"""Serve the built UI (frontend/dist) from the API's own origin.

Same origin means the UI needs no CORS permission, and Bytasm grants none.
Unknown paths outside /api/ return index.html so client-side routes work.
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response

from bytasm.api.problems import problem


def add_web_routes(app: FastAPI, dist: Path | None) -> None:
    root = dist.resolve() if dist is not None else None

    @app.get("/{path:path}", include_in_schema=False)
    def spa(request: Request, path: str) -> Response:
        if path == "api" or path.startswith("api/"):
            return problem("not_found", request_id=request.state.request_id)
        if root is None or not (root / "index.html").is_file():
            return PlainTextResponse(
                "The Bytasm UI is not built. Run `make web-build` and reload this page.",
                status_code=503,
            )
        try:
            candidate = (root / path).resolve()
            servable = bool(path) and candidate.is_file() and candidate.is_relative_to(root)
        except (OSError, ValueError):  # e.g. an encoded NUL byte in the path
            servable = False
        if servable:
            return FileResponse(candidate)
        return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})
