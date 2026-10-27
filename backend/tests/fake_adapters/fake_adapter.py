"""A misbehaving stand-in for an adapter child, used by the runner tests.

Usage (built by the tests): python -I fake_adapter.py <behaviour> <runner args...>

It accepts the same arguments as a real adapter. Some behaviours apply the
real child-side resource limits first (bytasm.runner.child), exactly like
bytasm.adapters.metadata_lief does. `template.json`, when a test puts it in
the work directory, is a valid result produced by the real adapter.

Nothing here parses or executes fixtures.
"""

import json
import os
import shutil
import signal
import sys
import time

from bytasm.runner import child


def _record_pid(name: str = "pids.txt") -> None:
    with open(name, "a", encoding="ascii") as handle:
        handle.write(f"{os.getpid()}\n")


def _sleep_forever() -> None:
    while True:
        time.sleep(0.1)


def _copy_template() -> None:
    shutil.copyfile("template.json", "result.json")


def main() -> int:
    behaviour = sys.argv[1]
    args = child.parse_child_args(sys.argv[2:])

    if behaviour == "hang":
        _record_pid()
        _sleep_forever()
    if behaviour == "ignore_sigterm":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        _record_pid()
        _sleep_forever()
    if behaviour == "fork_orphan":
        if os.fork() == 0:
            _record_pid()
            _sleep_forever()
        time.sleep(0.2)  # let the grandchild record its pid
        _copy_template()
        return 0
    if behaviour == "setsid_escape":
        if os.fork() == 0:
            os.setsid()  # leaves the process group; keeps stdout open
            _record_pid()
            time.sleep(30)
            os._exit(0)
        time.sleep(0.2)
        _copy_template()
        return 0
    if behaviour == "env_dump":
        with open("env.json", "w", encoding="utf-8") as handle:
            json.dump(dict(os.environ), handle)
        return 1
    if behaviour == "exit1":
        return 1
    if behaviour == "reject_known":
        sys.stdout.write("parse_failed\n")
        return 2
    if behaviour == "reject_unknown":
        sys.stdout.write("<b>not a known code</b>\n")
        return 2
    if behaviour == "reject_extra":
        sys.stdout.write("parse_failed\nand some adapter text\n")
        return 2
    if behaviour == "invalid_json":
        with open("result.json", "w", encoding="utf-8") as handle:
            handle.write("{not json")
        return 0
    if behaviour == "wrong_schema":
        with open("result.json", "w", encoding="utf-8") as handle:
            json.dump({"schema_version": 1, "unexpected": True}, handle)
        return 0
    if behaviour == "wrong_sha":
        with open("template.json", encoding="utf-8") as handle:
            document = json.load(handle)
        document["input"]["sha256"] = "0" * 64
        with open("result.json", "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        return 0
    if behaviour == "symlink_result":
        os.symlink("template.json", "result.json")
        return 0
    if behaviour == "no_result":
        return 0
    if behaviour == "slow_real":
        # The real LIEF adapter, after a pause: lets a test disconnect mid-parse.
        from bytasm.adapters import metadata_lief

        time.sleep(1.5)
        return metadata_lief.main(sys.argv[2:])
    if behaviour == "valid":
        _copy_template()
        return 0
    if behaviour == "huge_stdout":
        _copy_template()
        sys.stdout.write("x" * (1024 * 1024))
        return 0
    if behaviour == "huge_stderr":
        _copy_template()
        sys.stderr.write("\x1b[31m" + "y" * (1024 * 1024))
        return 0
    if behaviour == "exceed_as":
        child.apply_resource_limits(args)
        hog = bytearray(2 * 1024 * 1024 * 1024)
        return len(hog) and 0
    if behaviour == "exceed_cpu":
        child.apply_resource_limits(args)
        while True:
            pass
    if behaviour == "exceed_fsize":
        child.apply_resource_limits(args)
        with open("big.bin", "wb") as handle:
            handle.write(b"\x00" * (args.file_size_bytes * 2))
        return 0
    raise SystemExit(f"unknown behaviour {behaviour}")


if __name__ == "__main__":
    raise SystemExit(main())
