"""YARA-X adapter: match Bytasm's rule set against admitted bytes, in a child process.

Run as `python -I -m bytasm.adapters.yara_x_scan ...` by the worker (scan
mode) or the API (compile mode, to validate the rule set). Never imported for
use inside the API or worker process: like the LIEF adapter, `main` lowers its
own resource limits *before* `yara_x` is imported. The child is not a
security sandbox; the input policy keeps untrusted files away from it.

Steps (the order is part of the contract):

1. Lower RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE / RLIMIT_CORE.
2. Read the rule snapshot and confirm its SHA-256; in scan mode also read the
   sample and confirm it is exactly the bytes the worker verified against the
   stored SHA-256 and admission record.
3. Compile each rule file with includes disabled. Compiler errors and
   warnings are reported as YARA-X's code, title, and position only (never
   its full text, which quotes source lines).
4. In scan mode, scan once with YARA-X's own timeout and per-pattern match
   cap, and report each match's offset and length, plus a hex excerpt of at
   most 32 bytes read from the admitted data.

The result goes to `result.json`; exit 0 means the document is complete. Any
other exit code is a failure and the parent reads nothing.
"""

from __future__ import annotations

import argparse
import contextlib
import json
from collections.abc import Sequence
from importlib.metadata import version
from typing import Any

from bytasm.adapters.yara_result import (
    ADAPTER_NAME,
    MAX_DIAGNOSTICS,
    MAX_EVIDENCE_PER_PATTERN,
    MAX_EXCERPT_BYTES,
    MAX_PATTERNS_PER_RULE,
    MAX_RULES,
)
from bytasm.runner import child

ADAPTER_VERSION = "0.1.0"
MAX_RULES_BYTES = 256 * 1024
_TEXT_CAP = 512


def yara_x_version() -> str:
    return version("yara-x")


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--mode", choices=("scan", "compile"), required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--expected-rules-sha256", required=True)
    parser.add_argument("--input")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-input-bytes", type=int, required=True)
    parser.add_argument("--scan-timeout", type=int, required=True)
    parser.add_argument("--max-matches-per-pattern", type=int, required=True)
    parser.add_argument("--rlimit-as", type=int, required=True)
    parser.add_argument("--rlimit-cpu", type=int, required=True)
    parser.add_argument("--rlimit-fsize", type=int, required=True)
    ns = parser.parse_args(argv)
    if ns.mode == "scan" and (ns.input is None or ns.expected_sha256 is None):
        parser.error("scan mode needs --input and --expected-sha256")
    return ns


def _cap(text: object, limit: int = _TEXT_CAP) -> str:
    value = text if isinstance(text, str) else str(text)
    return value[:limit]


def _diagnostics(items: Any, file_name: str) -> list[dict[str, Any]]:
    """Keep YARA-X's code, title and position; drop the full report text."""
    result = []
    for item in list(items)[:MAX_DIAGNOSTICS]:
        line, column = item.get("line"), item.get("column")
        result.append(
            {
                "code": _cap(item.get("code", "unknown"), 32),
                "title": _cap(item.get("title", "")),
                "file": file_name,
                "line": line if isinstance(line, int) and line >= 0 else None,
                "column": column if isinstance(column, int) and column >= 0 else None,
            }
        )
    return result


def _meta_value(value: Any) -> Any:
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, bytes):
        return _cap(value.decode("utf-8", errors="replace"))
    return _cap(value)


def compile_rules(snapshot: bytes) -> tuple[Any, dict[str, Any]]:
    """Compile every file of the snapshot. Returns (Rules or None, rules report)."""
    import yara_x

    from bytasm.rules import split_snapshot

    compiler = yara_x.Compiler(includes_enabled=False)
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for file_name, text in split_snapshot(snapshot).items():
        before_errors, before_warnings = len(compiler.errors()), len(compiler.warnings())
        # A CompileError is also recorded in compiler.errors(), read below.
        with contextlib.suppress(yara_x.CompileError):
            compiler.add_source(text, origin=file_name)
        errors += _diagnostics(compiler.errors()[before_errors:], file_name)
        warnings += _diagnostics(compiler.warnings()[before_warnings:], file_name)
    rules = None if errors else compiler.build()
    identifiers = [] if rules is None else [_cap(rule.identifier, 128) for rule in rules]
    return rules, {
        "compiled": rules is not None,
        "rule_identifiers": identifiers[:MAX_RULES],
        "errors": errors[:MAX_DIAGNOSTICS],
        "warnings": warnings[:MAX_DIAGNOSTICS],
    }


def scan(
    rules: Any, data: bytes, timeout_seconds: int, max_matches_per_pattern: int
) -> dict[str, Any]:
    import yara_x

    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout_seconds)
    scanner.max_matches_per_pattern(max_matches_per_pattern)
    try:
        results = scanner.scan(data)
    except yara_x.TimeoutError:
        return {
            "status": "timed_out",
            "max_matches_per_pattern": max_matches_per_pattern,
            "matching_rules": [],
        }
    matching = []
    for rule in list(results.matching_rules)[:MAX_RULES]:
        patterns = []
        for pattern in list(rule.patterns)[:MAX_PATTERNS_PER_RULE]:
            matches = list(pattern.matches)
            patterns.append(
                {
                    "identifier": _cap(pattern.identifier, 128),
                    "match_count": min(len(matches), max_matches_per_pattern),
                    "matches": [
                        {
                            "offset": match.offset,
                            "length": match.length,
                            "xor_key": match.xor_key,
                            "excerpt_hex": data[
                                match.offset : match.offset + min(match.length, MAX_EXCERPT_BYTES)
                            ].hex(),
                        }
                        for match in matches[:MAX_EVIDENCE_PER_PATTERN]
                    ],
                }
            )
        matching.append(
            {
                "identifier": _cap(rule.identifier, 128),
                "namespace": _cap(rule.namespace, 128),
                "tags": [_cap(tag, 128) for tag in list(rule.tags)[:16]],
                "metadata": [
                    [_cap(key, 128), _meta_value(value)] for key, value in list(rule.metadata)[:32]
                ],
                "patterns": patterns,
            }
        )
    matching.sort(key=lambda item: (item["namespace"], item["identifier"]))
    return {
        "status": "completed",
        "max_matches_per_pattern": max_matches_per_pattern,
        "matching_rules": matching,
    }


def main(argv: Sequence[str] | None = None) -> int:
    ns = _parse(argv)
    limit_args = child.ChildArgs(
        input=ns.input or "",
        out=ns.out,
        expected_sha256=ns.expected_sha256 or "",
        max_input_bytes=ns.max_input_bytes,
        address_space_bytes=ns.rlimit_as,
        cpu_seconds=ns.rlimit_cpu,
        file_size_bytes=ns.rlimit_fsize,
    )
    try:
        limits = child.apply_resource_limits(limit_args)
    except child.LimitsNotApplied:
        return child.EXIT_LIMITS_NOT_APPLIED
    try:
        snapshot = child.read_verified_file(ns.rules, MAX_RULES_BYTES, ns.expected_rules_sha256)
        data = (
            child.read_verified_file(ns.input, ns.max_input_bytes, ns.expected_sha256)
            if ns.mode == "scan"
            else None
        )
    except (OSError, ValueError):
        return child.EXIT_INPUT_MISMATCH

    rules, rules_report = compile_rules(snapshot)
    scan_report = None
    if ns.mode == "scan" and rules is not None and data is not None:
        scan_report = scan(rules, data, ns.scan_timeout, ns.max_matches_per_pattern)

    document = {
        "schema_version": 1,
        "adapter": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "tool": "yara-x",
        "tool_version": yara_x_version(),
        "mode": ns.mode,
        "input": (
            {"sha256": ns.expected_sha256, "size_bytes": len(data)} if data is not None else None
        ),
        "rules": {"sha256": ns.expected_rules_sha256, **rules_report},
        "scan": scan_report,
        "resource_limits": limits,
    }
    payload = json.dumps(document, sort_keys=True, ensure_ascii=True).encode("ascii")
    child.write_result(ns.out, payload)
    return child.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
