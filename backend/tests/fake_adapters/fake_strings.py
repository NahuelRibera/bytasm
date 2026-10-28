"""A stand-in for the strings adapter child, used by the analysis-run tests.

Usage (built by the tests): python -I fake_strings.py <behaviour> <adapter args...>

Behaviours that need a real result run the real adapter first
(bytasm.adapters.strings_extract.main) and then alter its result.json, so the
tests exercise the parent's validation of untrusted output. Nothing here
executes a fixture.
"""

import json
import os
import sys
import time

from bytasm.adapters import strings_extract


def _rewrite(change: str) -> None:
    with open("result.json", encoding="ascii") as handle:
        document = json.load(handle)
    items = document["strings"]
    if change == "tamper_value":
        first = items[0]
        first["value"] = "X" + first["value"][1:]
    elif change == "offset_past_end":
        items[-1]["offset"] = document["input"]["size_bytes"]
    elif change == "unsorted":
        items[0], items[1] = items[1], items[0]
    elif change == "wrong_count":
        document["total_found"] += 1
    elif change == "markup_value":
        items[0]["value"] = "<script>alert(1)</script>"
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
    code = strings_extract.main(args)
    if behaviour != "real" and code == 0:
        _rewrite(behaviour)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
