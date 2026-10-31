"""Optional real Headless execution with fixed scripts and bounded documents.

Only the trusted configured installation is executable. The sample is supplied
as an import argument to Ghidra, never an executable, plugin or library.
"""

import asyncio
import hashlib
import json
import os
import re
import resource
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from bytasm.ghidra import GhidraConfiguration, diagnose
from bytasm.ghidra_protocol import Address, GhidraResult
from bytasm.runner import workspace
from bytasm.runner.child import read_verified_file
from bytasm.runner.limits import MAX_INPUT_BYTES, MIB, ParserLimits
from bytasm.runner.supervisor import AdapterOutcome, run_child

SCRIPTS = Path(__file__).parent / "ghidra_scripts"
LIMITS = ParserLimits(
    timeout_seconds=180,
    cpu_seconds=120,
    file_size_bytes=16 * MIB,
    result_bytes=2 * MIB,
    captured_stream_bytes=64 * 1024,
)
OPTIONS: dict[str, Any] = {
    "id": "ghidra-static",
    "version": 2,
    "name": "Bounded Ghidra static review",
    "ghidra_version": "12.2",
    "analyzers": "Ghidra 12.2 loader defaults, single CPU, fresh project",
    "analysis_timeout_seconds": 60,
    "wall_timeout_seconds": 180,
    "heap_mib": 768,
    "max_functions": 1024,
    "max_function_details": 16,
    "max_instructions_per_function": 64,
    "max_calls_per_function": 64,
    "max_pseudocode_characters": 4096,
    "max_decompiler_payload_mib": 1,
    "max_json_bytes": 2 * MIB,
}


def script_digest() -> str:
    return hashlib.sha256((SCRIPTS / "BytasmExtract.java").read_bytes()).hexdigest()


def profile_digest(selected: list[Address] | None = None) -> str:
    return hashlib.sha256(
        json.dumps(profile_options(selected), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def profile_options(selected: list[Address] | None = None) -> dict[str, Any]:
    if selected is None:
        return dict(OPTIONS)
    if not 1 <= len(selected) <= 8 or len({(a.space, a.address) for a in selected}) != len(
        selected
    ):
        raise ValueError("Invalid selected function set")
    entries = sorted((a.model_dump() for a in selected), key=lambda a: (a["space"], a["address"]))
    return {**OPTIONS, "selected_entries": entries}


def profile_snapshot(selected: list[Address] | None = None) -> dict[str, Any]:
    return {
        "id": OPTIONS["id"],
        "version": 2,
        "name": OPTIONS["name"] if selected is None else "Selected Ghidra function review",
        "steps": [
            {
                "tool": "ghidra",
                "adapter": "ghidra_headless",
                "adapter_version": "1",
                "tool_version": "12.2",
                "profile_sha256": profile_digest(selected),
                "script_sha256": script_digest(),
                "options": profile_options(selected),
            }
        ],
    }


def isolation_status() -> str | None:
    """Require an offline Linux namespace and finite container resource controls.

    No environment variable can assert that these boundaries exist. This is
    defence in depth, not a sandbox: the worker still shares its writable data.
    """
    if sys.platform != "linux":
        return "isolation_unavailable"
    try:
        interfaces = {
            line.split(":", 1)[0].strip()
            for line in Path("/proc/net/dev").read_text().splitlines()[2:]
        }
        if "lo" not in interfaces:
            return "isolation_unavailable"
        # Network namespaces may expose dormant kernel tunnel interfaces. Only
        # loopback may be UP; zero effective capabilities and no-new-privileges
        # prevent this process from enabling a dormant egress interface.
        for interface in interfaces:
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", interface) is None:
                return "isolation_unavailable"
            flags = int((Path("/sys/class/net") / interface / "flags").read_text().strip(), 16)
            if interface != "lo" and flags & 1:
                return "isolation_unavailable"
        process = dict(
            line.split(":", 1)
            for line in Path("/proc/self/status").read_text().splitlines()
            if ":" in line
        )
        if any(
            int(process.get(capability, "1").strip(), 16) != 0
            for capability in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")
        ):
            return "isolation_unavailable"
        if process.get("NoNewPrivs", "0").strip() != "1":
            return "isolation_unavailable"
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        if any(line.split()[0] != "lo" for line in routes if line.split()):
            return "isolation_unavailable"
        ipv6_routes = Path("/proc/net/ipv6_route").read_text().splitlines()
        if any(line.split()[-1] != "lo" for line in ipv6_routes if line.split()):
            return "isolation_unavailable"
        if os.geteuid() == 0:
            return "isolation_unavailable"
        cg = Path("/sys/fs/cgroup")
        memory = (cg / "memory.max").read_text().strip()
        pids = (cg / "pids.max").read_text().strip()
        cpu = (cg / "cpu.max").read_text().split()
        if memory == "max" or not 1024 * MIB <= int(memory) <= 4096 * MIB:
            return "resource_constraint"
        if pids == "max" or not 32 <= int(pids) <= 256:
            return "resource_constraint"
        if cpu[0] == "max" or int(cpu[0]) > 2 * int(cpu[1]):
            return "resource_constraint"
    except (OSError, ValueError, IndexError):
        return "resource_constraint"
    return None


def _temporary_filesystem_bounded(workdir: Path) -> bool:
    # Require a small dedicated tmpfs: the project, compilation cache, logs and
    # result all share its aggregate cap. Per-file rlimits alone do not cap disk.
    try:
        resolved = workdir.resolve()
        for line in Path("/proc/mounts").read_text().splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[2] != "tmpfs":
                continue
            mount = Path(fields[1])
            if resolved == mount or mount in resolved.parents:
                info = os.statvfs(workdir)
                return 32 * MIB <= info.f_blocks * info.f_frsize <= 512 * MIB
    except OSError:
        pass
    return False


def _parse(
    raw: bytes, expected_sha256: str, selected: list[Address] | None = None
) -> GhidraResult | None:
    try:
        result = GhidraResult.model_validate_json(raw)
    except ValidationError:
        return None
    if (
        result.schema_version != "ghidra-2"
        or result.input_sha256 != expected_sha256
        or result.script_sha256 != script_digest()
        or result.profile_sha256 != profile_digest(selected)
        or result.analysis_timed_out
        or result.language_id
        not in {
            "x86:LE:32:default",
            "x86:LE:64:default",
            "AARCH64:LE:64:v8A",
        }
    ):
        return None
    if (
        selected is None
        and sum(f.pseudocode_status != "not_selected" for f in result.functions) > 16
    ):
        return None
    if selected is not None:
        expected = {(a.space, a.address) for a in selected}
        actual = {
            (f.entry.space, f.entry.address)
            for f in result.functions
            if f.pseudocode_status != "not_selected"
        }
        if expected != actual:
            return None
    return result


def _command(config: GhidraConfiguration, mode: str, expected: str) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-m",
        "bytasm.ghidra_provider",
        "--bridge",
        mode,
        str(config.home),
        str(config.java_home),
        expected,
    ]


def _failure(reason: str) -> AdapterOutcome[GhidraResult]:
    return AdapterOutcome(status="failed", reason=reason, exit_code=None, duration_ms=0)


async def analyze(
    config: GhidraConfiguration,
    workdir: Path,
    expected_sha256: str,
    should_cancel: Callable[[], bool],
    selected: list[Address] | None = None,
) -> AdapterOutcome[GhidraResult]:
    preflight = diagnose(config)
    if preflight.status != "execution_unavailable":
        return _failure(preflight.status)
    boundary = isolation_status()
    if boundary is not None:
        return _failure(boundary)
    if not _temporary_filesystem_bounded(workdir):
        return _failure("resource_constraint")
    if should_cancel():
        return AdapterOutcome(
            status="cancelled", reason="cancel_requested", exit_code=None, duration_ms=0
        )
    try:
        if selected is not None:
            options = profile_options(selected)
            (workdir / "selection.json").write_text(
                json.dumps(options["selected_entries"]), encoding="utf-8"
            )
        return await run_child(
            _command(config, "analyze", expected_sha256),
            workdir,
            LIMITS,
            parse_result=lambda raw: _parse(raw, expected_sha256, selected),
            should_cancel=should_cancel,
        )
    except OSError:
        return _failure("startup_failed")


async def provider_health(config: GhidraConfiguration, tmp_dir: Path) -> dict[str, Any]:
    """A real no-sample Headless self-test; caller decides caching policy."""
    preflight = diagnose(config)
    result = preflight.model_dump()
    if preflight.status != "execution_unavailable":
        return result
    directory: Path | None = None
    try:
        directory = workspace.create_workdir(tmp_dir)
        outcome = await run_child(
            _command(config, "health", "none"),
            directory,
            ParserLimits(timeout_seconds=90, result_bytes=1024),
            parse_result=lambda raw: json.loads(raw) == {"healthy": True, "version": "12.2"},
        )
        if outcome.status != "succeeded" or outcome.result is not True:
            result.update(
                status="self_check_failed",
                message="The bounded no-sample Headless self-check failed.",
                verification="headless_self_check",
                health_check="failed",
            )
            return result
        boundary = isolation_status()
        enabled = boundary is None and _temporary_filesystem_bounded(directory)
        result.update(
            available=True,
            analysis_enabled=enabled,
            status="available" if enabled else boundary or "resource_constraint",
            message="Headless self-check passed. Static analysis is enabled."
            if enabled
            else (
                "Headless self-check passed. Analysis requires an offline non-root Linux "
                "worker with bounded cgroups and temporary filesystem."
            ),
            verification="headless_self_check",
            health_check="passed",
        )
        return result
    except (OSError, ValueError, json.JSONDecodeError):
        result.update(
            status="self_check_failed",
            message="The bounded no-sample Headless self-check failed.",
            verification="headless_self_check",
            health_check="failed",
        )
        return result
    finally:
        if directory is not None:
            # Retry transient cleanup once; never touch caller-owned projects.
            for _ in range(2):
                try:
                    shutil.rmtree(directory)
                    break
                except FileNotFoundError:
                    break
                except OSError:
                    await asyncio.sleep(0.05)


def _bridge() -> None:
    # This child runs before Ghidra or any parser. It execs the trusted launcher,
    # keeping the parent's process group and minimal inherited descriptors.
    if len(sys.argv) != 6 or sys.argv[1] != "--bridge":
        raise SystemExit(3)
    mode, home, java, expected = sys.argv[2:]
    if mode not in {"analyze", "health"}:
        raise SystemExit(3)
    config = GhidraConfiguration(home, java)
    if diagnose(config).status != "execution_unavailable":
        raise SystemExit(3)
    work = Path.cwd()
    os.umask(0o077)
    for name in ("home", "cache", "config", "tmp", "projects", "scripts"):
        (work / name).mkdir(mode=0o700)
    for name in ("BytasmHealth.java", "BytasmExtract.java"):
        shutil.copyfile(SCRIPTS / name, work / "scripts" / name)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 121))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * MIB, 16 * MIB))
    # JVM classloading needs more than the native parser's descriptor budget.
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    argv = [
        str(Path(home) / "support" / "analyzeHeadless"),
        str(work / "projects"),
        "review",
        "-scriptPath",
        str(work / "scripts"),
        "-deleteProject",
        "-log",
        str(work / "ghidra.log"),
        "-scriptlog",
        str(work / "script.log"),
    ]
    if mode == "health":
        argv += ["-preScript", "BytasmHealth.java", str(work / "result.json")]
    else:
        if isolation_status() is not None or not _temporary_filesystem_bounded(work):
            raise SystemExit(3)
        data = read_verified_file("upload.bin", MAX_INPUT_BYTES, expected)
        # Header admission is repeated before the real parser sees the file.
        from bytasm.intake.identify import identify_format

        identify_format(data)
        del data
        selected = None
        selection_path = work / "selection.json"
        if selection_path.exists():
            if selection_path.is_symlink() or selection_path.stat().st_size > 8192:
                raise SystemExit(3)
            selected = [Address.model_validate(a) for a in json.loads(selection_path.read_text())]
            profile_options(selected)
        else:
            selection_path.write_text("[]", encoding="utf-8")
        argv += [
            "-import",
            str(work / "upload.bin"),
            "-max-cpu",
            "1",
            "-analysisTimeoutPerFile",
            "60",
            "-postScript",
            "BytasmExtract.java",
            str(work / "result.json"),
            expected,
            profile_digest(selected),
            script_digest(),
            str(selection_path),
        ]
    env = {
        "PATH": f"{java}/bin:/usr/bin:/bin",
        "GHIDRA_HEADLESS_MAXMEM": "768M",
        "LC_ALL": "C",
        "JAVA_HOME": java,
        "HOME": str(work / "home"),
        "XDG_CONFIG_HOME": str(work / "config"),
        "XDG_CACHE_HOME": str(work / "cache"),
        "TMPDIR": str(work / "tmp"),
        "JAVA_TOOL_OPTIONS": (
            f'-Duser.home="{work / "home"}" -Djava.io.tmpdir="{work / "tmp"}" '
            f'-Dghidra.user.settings.dir="{work / "config"}" '
            f'-Dghidra.user.cache.dir="{work / "cache"}"'
        ),
    }
    # No shell command string is constructed; analyzeHeadless is an installation-owned
    # fixed launcher. The input path is only ever an -import argument.
    os.execve(argv[0], argv, env)  # noqa: S606 - fixed trusted launcher, argv only


if __name__ == "__main__":
    _bridge()
