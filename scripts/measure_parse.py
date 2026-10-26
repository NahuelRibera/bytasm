"""Measure LIEF parse time and peak memory for the fixtures (blueprint M1, ADR-0001 D4).

Run from the repository root with the backend environment:

    uv --directory backend run --no-sync python ../scripts/measure_parse.py [--rlimit-as MIB]

Cases:
  - every fixture listed in fixtures/MANIFEST.sha256;
  - three synthetic files of exactly the 64 MiB size limit, generated in memory
    from fixture bytes (test-authored, never written to disk, never listed in
    the manifest). As blueprint 9.2 allows for M1, they are passed straight to
    the adapter, like the generated inputs in the tests. The CLI refuses them.

Each case runs in a fresh child interpreter so its peak memory is its own.
Timed region: identify_format + extract_metadata (LIEF parse + entropy), and
LIEF's parse alone. The bytes are already in memory, as in `bytasm inspect`.
Memory: ru_maxrss of the child (peak resident set). On Linux also VmPeak from
/proc/self/status: the peak *virtual* size, which is what RLIMIT_AS limits.
With --rlimit-as, the child sets RLIMIT_AS before importing LIEF (Linux only;
macOS does not enforce it) to check that each case completes under that limit.

Nothing is executed: fixtures are only read and parsed as data.
"""

import argparse
import json
import os
import random
import resource
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
SIZE_LIMIT = 64 * 1024 * 1024  # bytasm.inspection.MAX_FILE_SIZE
SEED = 0xB17A5


def _fixture(name: str) -> bytes:
    return (FIXTURES / "bin" / name).read_bytes()


def _random(size: int) -> bytes:
    return random.Random(SEED).randbytes(size)  # noqa: S311 (test data, not crypto)


def synthetic_elf_overlay() -> bytes:
    """x86-64 ELF fixture + zero padding to the limit (data no section covers)."""
    data = _fixture("hello_v1-x86_64.elf")
    return data + bytes(SIZE_LIMIT - len(data))


def synthetic_elf_big_section() -> bytes:
    """x86-64 ELF fixture whose .comment section is redirected to cover random
    bytes appended up to the limit: one ~64 MiB section to measure entropy on."""
    data = bytearray(_fixture("hello_v1-x86_64.elf"))
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    (shentsize,) = struct.unpack_from("<H", data, 0x3A)
    (shnum,) = struct.unpack_from("<H", data, 0x3C)
    (shstrndx,) = struct.unpack_from("<H", data, 0x3E)
    (strtab_offset,) = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 0x18)
    for index in range(shnum):
        header = shoff + index * shentsize
        (name_offset,) = struct.unpack_from("<I", data, header)
        start = strtab_offset + name_offset
        if bytes(data[start : start + 9]) == b".comment\x00":
            original_size = len(data)
            padding = SIZE_LIMIT - original_size
            struct.pack_into("<QQ", data, header + 0x18, original_size, padding)
            return bytes(data) + _random(padding)
    raise RuntimeError(".comment section not found")


def synthetic_pe_big_section() -> bytes:
    """Hand-assembled PE32+ with one .text section of random bytes filling the limit."""
    alignment = 0x200
    raw_size = SIZE_LIMIT - alignment
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 0, 0, raw_size, 0, 0, 0x1000, 0x1000, 0x1_4000_0000,
        0x1000, alignment, 6, 0, 0, 0, 6, 0, 0, 0x1000 + raw_size, alignment,
        0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + bytes(16 * 8)  # fmt: skip
    text = struct.pack(
        "<8sIIIIIIHHI", b".text", raw_size, 0x1000, raw_size, alignment, 0, 0, 0, 0, 0x60000020
    )
    headers = (bytes(dos) + b"PE\x00\x00" + coff + optional + text).ljust(alignment, b"\x00")
    return headers + _random(raw_size)


SYNTHETIC = {
    "synthetic: ELF + 64 MiB overlay": synthetic_elf_overlay,
    "synthetic: ELF, one 64 MiB section": synthetic_elf_big_section,
    "synthetic: PE, one 64 MiB section": synthetic_pe_big_section,
}


def _proc_status(field: str) -> int | None:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(field + ":"):
                return int(line.split()[1]) * 1024
    except OSError:
        return None
    return None


def child(case: str, repeats: int, rlimit_as: int | None) -> dict[str, object]:
    if rlimit_as is not None:
        resource.setrlimit(resource.RLIMIT_AS, (rlimit_as, rlimit_as))
    data = SYNTHETIC[case]() if case in SYNTHETIC else (FIXTURES / case).read_bytes()

    import lief

    from bytasm.adapters.metadata_lief import extract_metadata
    from bytasm.intake.identify import identify_format

    lief.logging.disable()
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    full, parse_only = [], []
    for _ in range(repeats):
        start = time.perf_counter()
        metadata = extract_metadata(data, identify_format(data))
        full.append(time.perf_counter() - start)
        start = time.perf_counter()
        lief.parse(data)
        parse_only.append(time.perf_counter() - start)
    # ru_maxrss is bytes on macOS and KiB on Linux.
    scale = 1 if sys.platform == "darwin" else 1024
    return {
        "case": case,
        "size_bytes": len(data),
        "sections": len(metadata["sections"]),
        "repeats": repeats,
        "total_s_median": statistics.median(full),
        "total_s_max": max(full),
        "parse_s_median": statistics.median(parse_only),
        "maxrss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale,
        "maxrss_before_parse_bytes": rss_before * scale,
        "vmpeak_bytes": _proc_status("VmPeak"),
        "rlimit_as_bytes": rlimit_as,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rlimit-as", type=int, metavar="MIB", help="RLIMIT_AS for each child")
    parser.add_argument("--child", help=argparse.SUPPRESS)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    rlimit = args.rlimit_as * 1024 * 1024 if args.rlimit_as else None

    if args.child:
        print(json.dumps(child(args.child, args.repeats, rlimit)))
        return

    manifest = (FIXTURES / "MANIFEST.sha256").read_text().splitlines()
    cases = [(line.split("  ", 1)[1], args.repeats) for line in manifest if line.strip()]
    cases += [(name, 3) for name in SYNTHETIC]
    print(f"# host: {sys.platform} {os.uname().machine}, Python {sys.version.split()[0]}")
    for case, repeats in cases:
        command = [sys.executable, __file__, "--child", case, "--repeats", str(repeats)]
        if args.rlimit_as:
            command += ["--rlimit-as", str(args.rlimit_as)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
        if result.returncode != 0:
            tail = result.stderr.strip().splitlines()[-1:] or ["(no stderr)"]
            print(json.dumps({"case": case, "failed": result.returncode, "error": tail[0]}))
        else:
            print(result.stdout.strip())


if __name__ == "__main__":
    main()
