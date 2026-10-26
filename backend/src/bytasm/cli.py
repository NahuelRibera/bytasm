"""Command-line entry point: `bytasm inspect <fixture-path>`.

Output is deterministic JSON on stdout (sorted keys, no timestamps, no
absolute paths), so inspecting the same fixture twice gives identical bytes.

Exit codes:
  0  success, report on stdout
  1  operational problem (file missing, manifest unreadable), JSON error on stdout
  2  input refused (unknown hash, unsupported or malformed file, parse failure),
     JSON error on stdout; also used by argparse for usage errors (text on stderr)
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        manifest = Manifest.load(default_manifest_path())
        report = inspect_file(args.path, manifest)
    except InspectError as error:
        sys.stdout.write(to_json({"error": {"code": error.code, "message": error.message}}))
        return error.exit_code

    sys.stdout.write(to_json(report))
    return 0
