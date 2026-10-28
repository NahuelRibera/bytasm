"""Built-in strings extractor: printable ASCII and UTF-16LE runs, in a child process.

Run as `python -I -m bytasm.adapters.strings_extract ...` by the worker, like
the other adapters: `main` lowers its own resource limits first, then reads
the input and confirms it is exactly the bytes the worker verified against
the stored SHA-256 and admission record. Nothing is executed or decoded
beyond matching byte patterns, and nothing leaves the machine.

What a string is, the minimum length, and the caps are defined in
bytasm.adapters.strings_result. The output is deterministic: strings sorted
by (offset, encoding), the first `max_strings` kept, each value cut to
`max_chars` characters with its full length reported.

The result goes to `result.json`; exit 0 means the document is complete.
"""

from __future__ import annotations

import argparse
import heapq
import itertools
import json
import re
from collections.abc import Iterator, Sequence
from typing import Any

from bytasm import __version__
from bytasm.adapters.strings_result import (
    ADAPTER_NAME,
    ENCODINGS,
    MAX_CHARS,
    MAX_STRINGS,
    MIN_LENGTH,
)
from bytasm.runner import child

ADAPTER_VERSION = "0.1.0"
TOOL_VERSION = f"bytasm {__version__}"

_PRINTABLE = rb"[\t\x20-\x7e]"


def patterns(min_length: int) -> dict[str, re.Pattern[bytes]]:
    """The byte patterns of each encoding, for runs of at least `min_length` characters."""
    return {
        "ascii": re.compile(_PRINTABLE + rb"{%d,}" % min_length),
        "utf-16le": re.compile(rb"(?:" + _PRINTABLE + rb"\x00){%d,}" % min_length),
    }


def _width(encoding: str) -> int:
    return 1 if encoding == "ascii" else 2


def decode(raw: bytes, encoding: str) -> str:
    return raw.decode("ascii") if encoding == "ascii" else raw[0::2].decode("ascii")


def extract(
    data: bytes,
    min_length: int = MIN_LENGTH,
    max_strings: int = MAX_STRINGS,
    max_chars: int = MAX_CHARS,
) -> dict[str, Any]:
    """Find every run, keep the first `max_strings` by (offset, encoding)."""
    compiled = patterns(min_length)
    found = dict.fromkeys(ENCODINGS, 0)

    # One iterator per encoding, each in offset order; merged by (offset, encoding).
    merged = heapq.merge(
        *(
            _counting(data, index, encoding, compiled[encoding], found)
            for index, encoding in enumerate(ENCODINGS)
        )
    )
    items = []
    for offset, enc_index, byte_length in itertools.islice(merged, max_strings):
        encoding = ENCODINGS[enc_index]
        width = _width(encoding)
        length_chars = byte_length // width
        kept = min(length_chars, max_chars)
        items.append(
            {
                "offset": offset,
                "encoding": encoding,
                "length_chars": length_chars,
                "byte_length": byte_length,
                "value": decode(data[offset : offset + kept * width], encoding),
                "value_truncated": kept < length_chars,
            }
        )
    # Count the runs beyond the cap too (the iterators above stopped early).
    for _ in merged:
        pass
    total = sum(found.values())
    return {
        "params": {
            "encodings": list(ENCODINGS),
            "min_length": min_length,
            "max_strings": max_strings,
            "max_chars": max_chars,
        },
        "total_found": total,
        "found_by_encoding": found,
        "truncated": total > len(items),
        "strings": items,
    }


def _counting(
    data: bytes, index: int, encoding: str, pattern: re.Pattern[bytes], found: dict[str, int]
) -> Iterator[tuple[int, int, int]]:
    """(offset, encoding index, byte_length) of each run, counting them in `found`."""
    for match in pattern.finditer(data):
        found[encoding] += 1
        yield match.start(), index, match.end() - match.start()


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--input", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-input-bytes", type=int, required=True)
    parser.add_argument("--min-length", type=int, required=True)
    parser.add_argument("--max-strings", type=int, required=True)
    parser.add_argument("--max-chars", type=int, required=True)
    parser.add_argument("--rlimit-as", type=int, required=True)
    parser.add_argument("--rlimit-cpu", type=int, required=True)
    parser.add_argument("--rlimit-fsize", type=int, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    ns = _parse(argv)
    args = child.ChildArgs(
        input=ns.input,
        out=ns.out,
        expected_sha256=ns.expected_sha256,
        max_input_bytes=ns.max_input_bytes,
        address_space_bytes=ns.rlimit_as,
        cpu_seconds=ns.rlimit_cpu,
        file_size_bytes=ns.rlimit_fsize,
    )
    try:
        limits = child.apply_resource_limits(args)
    except child.LimitsNotApplied:
        return child.EXIT_LIMITS_NOT_APPLIED
    try:
        data = child.read_admitted_input(args)
    except (OSError, ValueError):
        return child.EXIT_INPUT_MISMATCH

    extracted = extract(
        data,
        min_length=ns.min_length,
        max_strings=min(ns.max_strings, MAX_STRINGS),
        max_chars=min(ns.max_chars, MAX_CHARS),
    )
    document = {
        "schema_version": 1,
        "adapter": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "tool": "strings",
        "tool_version": TOOL_VERSION,
        "input": {"sha256": ns.expected_sha256, "size_bytes": len(data)},
        **extracted,
        "resource_limits": limits,
    }
    payload = json.dumps(document, sort_keys=True, ensure_ascii=True).encode("ascii")
    child.write_result(ns.out, payload)
    return child.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
