"""Fixed disposable-worker entry point. Receives inert bytes, never runs them."""

import hashlib
import json
import sys

from bytasm.runner.child import ChildArgs, apply_resource_limits
from bytasm.runner.limits import MAX_INPUT_BYTES


def main() -> int:
    if len(sys.argv) != 2:
        return 4
    expected = sys.argv[1]
    limits = apply_resource_limits(
        ChildArgs(
            input="",
            out="",
            expected_sha256=expected,
            max_input_bytes=MAX_INPUT_BYTES,
            address_space_bytes=512 * 1024 * 1024,
            cpu_seconds=20,
            file_size_bytes=4 * 1024 * 1024,
        )
    )
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES or hashlib.sha256(data).hexdigest() != expected:
        return 4
    # Parser is imported only after limits and exact-input verification.
    from bytasm.adapters.metadata_lief import build_result

    document = build_result(data, expected, limits)
    raw = json.dumps(document, sort_keys=True, ensure_ascii=True).encode()
    if len(raw) > 4 * 1024 * 1024:
        return 5
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
