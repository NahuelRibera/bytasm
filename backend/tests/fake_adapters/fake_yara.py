"""A stand-in for the YARA-X adapter child, used by the analysis-run tests.

Usage (built by the tests): python -I fake_yara.py <behaviour> <adapter args...>

Behaviours that need a real result run the real adapter first
(bytasm.adapters.yara_x_scan.main) and then alter its result.json, so the
tests exercise the parent's validation of untrusted output. Nothing here
executes a fixture.
"""

import json
import os
import sys
import time

from bytasm.adapters import yara_x_scan


def _rewrite(change: str) -> None:
    with open("result.json", encoding="ascii") as handle:
        document = json.load(handle)
    match = next(
        pattern["matches"][0]
        for pattern in document["scan"]["matching_rules"][0]["patterns"]
        if pattern["matches"]
    )
    if change == "bad_excerpt":
        match["excerpt_hex"] = "00" * (len(match["excerpt_hex"]) // 2)
    elif change == "offset_past_end":
        match["offset"] = document["input"]["size_bytes"]
    elif change == "drop_rule":
        document["rules"]["rule_identifiers"] = document["rules"]["rule_identifiers"][1:]
    os.chmod("result.json", 0o600)
    with open("result.json", "w", encoding="ascii") as handle:
        json.dump(document, handle)


def main() -> int:
    behaviour, args = sys.argv[1], sys.argv[2:]
    if behaviour.startswith("spy:"):
        # Records that the child was started at all; never reads the input.
        with open(behaviour.removeprefix("spy:"), "w", encoding="ascii") as handle:
            handle.write("started\n")
        return 1
    if behaviour == "hang":
        with open("pids.txt", "a", encoding="ascii") as handle:
            handle.write(f"{os.getpid()}\n")
        while True:
            time.sleep(0.1)
    if behaviour == "exit1":
        return 1
    if behaviour == "invalid_json":
        with open("result.json", "w", encoding="ascii") as handle:
            handle.write("{not json")
        return 0
    if behaviour == "huge_stdout":
        sys.stdout.write("x" * (1024 * 1024))
        return 0
    code = yara_x_scan.main(args)
    if behaviour != "real" and code == 0:
        _rewrite(behaviour)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
