"""Command-line entry points: `bytasm inspect <fixture-path>`, `bytasm serve`, `bytasm worker`.

Output is deterministic JSON on stdout (sorted keys, no timestamps, no
absolute paths), so inspecting the same fixture twice gives identical bytes.

`inspect` exit codes:
  0  success, report on stdout
  1  operational problem (file missing, manifest unreadable), JSON error on stdout
  2  input refused (unknown hash, unsupported or malformed file, parse failure),
     JSON error on stdout; also used by argparse for usage errors (text on stderr)

`serve` reads its configuration from the environment only (see bytasm.config)
and refuses to start on a non-loopback address. It exits 1 on a configuration
error.

`worker` (v0.2) reads the same configuration, processes queued analysis runs
from the same data directory, and listens on no port. Run exactly one next to
`bytasm serve`; a second one exits 1.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from bytasm import __version__
from bytasm.errors import InspectError
from bytasm.inspection import inspect_file
from bytasm.intake.manifest import Manifest, default_manifest_path


def to_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bytasm",
        description=(
            "Bytasm static inspection (development build). Only files listed in "
            "fixtures/MANIFEST.sha256 are accepted. Files are never executed."
        ),
    )
    parser.add_argument("--version", action="version", version=f"bytasm {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="print metadata for a committed fixture")
    inspect.add_argument("path", type=Path, help="path to a fixture listed in the manifest")
    commands.add_parser(
        "serve",
        help="run the local web app on 127.0.0.1 (configuration: BYTASM_* environment variables)",
    )
    commands.add_parser(
        "worker",
        help="process queued analysis runs (YARA-X) for the same data directory as `serve`",
    )
    return parser


def worker() -> int:
    import logging

    from bytasm.config import ConfigError, Settings
    from bytasm.jobs.worker import WorkerError, run_worker
    from bytasm.runner.hardening import make_non_dumpable

    try:
        settings = Settings.from_env()
    except ConfigError as error:
        sys.stderr.write(f"bytasm worker: {error}\n")
        return 1
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    make_non_dumpable()
    sys.stderr.write(f"Bytasm {__version__} worker (input policy: {settings.input_policy})\n")
    try:
        run_worker(settings)
    except WorkerError as error:
        sys.stderr.write(f"bytasm worker: {error}\n")
        return 1
    return 0


def serve() -> int:
    import logging

    import uvicorn

    from bytasm.api.app import create_app
    from bytasm.config import ConfigError, Settings
    from bytasm.runner.hardening import make_non_dumpable

    try:
        settings = Settings.from_env()
    except ConfigError as error:
        sys.stderr.write(f"bytasm serve: {error}\n")
        return 1
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    make_non_dumpable()
    where = (
        f"container mode, published by Compose on http://127.0.0.1:{settings.port}/"
        if settings.container
        else f"http://{settings.host}:{settings.port}/"
    )
    sys.stderr.write(f"Bytasm {__version__} on {where} (input policy: {settings.input_policy})\n")
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        workers=1,  # the parser slot is in-process: exactly one server process
        proxy_headers=False,
        server_header=False,
        log_level="info",
        access_log=False,  # URLs may contain local strings-explorer queries.
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "serve":
        return serve()
    if args.command == "worker":
        return worker()

    try:
        manifest = Manifest.load(default_manifest_path())
        report = inspect_file(args.path, manifest)
    except InspectError as error:
        sys.stdout.write(to_json({"error": {"code": error.code, "message": error.message}}))
        return error.exit_code

    sys.stdout.write(to_json(report))
    return 0
