"""Resource-limited capa CLI bridge. Reads admitted bytes, never executes them."""

import argparse
import contextlib
import json
import os
import resource
import subprocess
import sys
from pathlib import Path

from bytasm.adapters.capa_result import classifications
from bytasm.runner import child

ADAPTER_VERSION = "0.1.0"


def normalize(raw: str, sample_sha: str, rules_sha: str) -> dict[str, object]:
    """Map only capa 10's static match-scope addresses; never invent byte ranges."""
    from capa.render.result_document import ResultDocument  # type: ignore[import-untyped]

    # The pinned tool's complete public result model checks its own JSON contract.
    document = ResultDocument.model_validate_json(raw)
    data = json.loads(document.model_dump_json())
    if data["meta"]["version"] != "10.0.0" or data["meta"]["sample"]["sha256"] != sample_sha:
        raise ValueError("Unexpected capa provenance")
    if data["meta"]["flavor"] != "static":
        raise ValueError("Only static results are supported")
    findings = []
    if len(data["rules"]) > 16:
        raise ValueError("Too many rules")
    for name, rule in sorted(data["rules"].items()):
        matches = rule["matches"]
        if len(matches) > 1_000_000:
            raise ValueError("Too many matches")
        escaped = name.replace("~", "~0").replace("/", "~1")
        locations = []
        for index, (address, _tree) in enumerate(matches[:32]):
            if address["type"] != "absolute" or type(address["value"]) is not int:
                raise ValueError("Unsupported capa address type")
            locations.append(
                {"address": address["value"], "pointer": f"/rules/{escaped}/matches/{index}/0"}
            )
        findings.append(
            {
                "name": name,
                "namespace": rule["meta"].get("namespace") or "",
                "source": rule["source"],
                "classifications": classifications(rule["meta"]),
                "matches": locations,
                "match_count": len(matches),
            }
        )
    return {
        "schema_version": 1,
        "tool_version": "10.0.0",
        "sample_sha256": sample_sha,
        "rules_sha256": rules_sha,
        "raw": raw,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--rules-sha256", required=True)
    args = parser.parse_args()
    limits = child.ChildArgs(
        "upload.bin", "result.json", args.expected_sha256, 64 * 1024**2, 1024**3, 100, 16 * 1024**2
    )
    try:
        child.apply_resource_limits(limits)
        # RLIMIT_NPROC counts same-UID threads across PID namespaces. Counting
        # container /proc alone underestimates that total and can prevent fork.
        # Prefer the actual bounded cgroup in supported Compose deployments.
        if sys.platform == "linux":
            try:
                cgroup_pids = int(Path("/sys/fs/cgroup/pids.max").read_text().strip())
            except (OSError, ValueError):
                cgroup_pids = 0
            if not 0 < cgroup_pids <= 128:
                count = 0
                for path in Path("/proc").glob("[0-9]*"):
                    try:
                        if path.stat().st_uid == os.getuid():
                            fields = (path / "status").read_text().splitlines()
                            count += int(
                                next(
                                    line.split()[1]
                                    for line in fields
                                    if line.startswith("Threads:")
                                )
                            )
                    except (OSError, StopIteration):
                        continue
                resource.setrlimit(resource.RLIMIT_NPROC, (count + 8, count + 8))
        child.read_admitted_input(limits)
        snapshot = child.read_verified_file("capa-rules.json", 256 * 1024, args.rules_sha256)
        rules = json.loads(snapshot)
        Path("rules").mkdir()
        Path("signatures").mkdir()
        # capa uses a pickled rule cache: never reuse the user's/global cache.
        # This fresh per-step directory also works with a read-only rootfs.
        Path("cache").mkdir(mode=0o700)
        for name, text in rules.items():
            if Path(name).name != name or not name.endswith(".yml"):
                return 4
            Path("rules", name).write_text(text, encoding="utf-8")
        # stdout/stderr go to size-limited private files, never routine logs.
        with Path("capa.raw").open("wb") as out, Path("capa.err").open("wb") as err:
            result = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "bytasm.adapters.capa_cli",
                    "-q",
                    "-j",
                    "--color",
                    "never",
                    "-b",
                    "vivisect",
                    "-f",
                    "pe",
                    "-s",
                    "signatures",
                    "-r",
                    "rules",
                    "upload.bin",
                ],
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                env={**os.environ, "XDG_CACHE_HOME": str(Path.cwd() / "cache")},
                timeout=110,
                check=False,
            )
        if result.returncode:
            return 1
        if (
            Path("capa.raw").stat().st_size > 8 * 1024**2
            or Path("capa.err").stat().st_size > 64 * 1024
        ):
            return 5
        raw = Path("capa.raw").read_text(encoding="utf-8")
        document = normalize(raw, args.expected_sha256, args.rules_sha256)
        from bytasm.adapters.capa_result import CapaResult

        CapaResult.model_validate(document)
        Path("result.json").write_text(json.dumps(document, ensure_ascii=True), encoding="ascii")
        os.chmod("result.json", 0o400)
        return 0
    except (OSError, ValueError, child.LimitsNotApplied, subprocess.TimeoutExpired):
        return 1


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        raise SystemExit(main())
