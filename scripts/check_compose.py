"""Assert the security-relevant settings of compose.yaml (blueprint 12.1, 8.2).

Checks the configuration Docker Compose actually resolves (`docker compose
config --format json`), not the YAML text, so overrides and interpolation are
included. Standard library only.

Usage:
  python scripts/check_compose.py            # runs `docker compose config`
  python scripts/check_compose.py config.json

Exit status 0 if every check passes, 1 otherwise (each failure is printed).
"""

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA_TARGET = "/data"
MAX_MEMORY_BYTES = 4 * 1024**3
MAX_PIDS = 512


def _memory_bytes(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def check_service(name: str, service: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(f"{name}: {message}")

    if service.get("privileged"):
        fail("privileged must not be set")
    for key in ("network_mode", "pid", "ipc", "userns_mode", "uts", "cgroup"):
        if str(service.get(key, "")).startswith("host"):
            fail(f"{key}: host is not allowed")
    if service.get("devices"):
        fail("no devices may be mapped")
    if service.get("cap_add"):
        fail(f"cap_add must be empty, not {service['cap_add']}")
    if [str(cap).upper() for cap in service.get("cap_drop", [])] != ["ALL"]:
        fail("cap_drop must be exactly [ALL]")
    security_opt = [str(opt) for opt in service.get("security_opt", [])]
    if "no-new-privileges:true" not in security_opt:
        fail("security_opt must include no-new-privileges:true")
    if any("unconfined" in opt for opt in security_opt):
        fail("seccomp/apparmor must not be unconfined (keep Docker's default profile)")

    user = str(service.get("user", ""))
    uid = user.split(":", 1)[0]
    if not uid.isdigit() or int(uid) == 0:
        fail(f"user must be a numeric non-root UID, not {user!r}")
    if service.get("read_only") is not True:
        fail("read_only must be true")
    if service.get("init") is not True:
        fail("init must be true")

    memory = _memory_bytes(service.get("mem_limit"))
    if memory is None or not 0 < memory <= MAX_MEMORY_BYTES:
        fail(f"mem_limit must be set and at most 4 GiB, not {service.get('mem_limit')!r}")
    if _memory_bytes(service.get("memswap_limit")) != memory:
        fail("memswap_limit must equal mem_limit (no extra swap)")
    cpus = service.get("cpus")
    if not isinstance(cpus, int | float) or not 0 < cpus <= 8:
        fail(f"cpus must be set (0 < cpus <= 8), not {cpus!r}")
    pids = service.get("pids_limit")
    if not isinstance(pids, int) or not 0 < pids <= MAX_PIDS:
        fail(f"pids_limit must be set (1..{MAX_PIDS}), not {pids!r}")

    if name == "worker" and service.get("network_mode") != "none":
        fail("worker must use network_mode: none")
    if name != "api" and service.get("ports"):
        fail("only the api service may publish a port")
    for port in service.get("ports", []):
        if port.get("host_ip") != "127.0.0.1":
            fail(f"port {port.get('target')} must be published on 127.0.0.1 only")

    for volume in service.get("volumes", []):
        if volume.get("type") != "volume" or volume.get("target") != DATA_TARGET:
            fail(
                f"only the named data volume at {DATA_TARGET} may be mounted, "
                f"not {volume.get('type')} {volume.get('source')} -> {volume.get('target')}"
            )
        if "docker.sock" in str(volume.get("source", "")):
            fail("the Docker socket must never be mounted")
    for entry in service.get("tmpfs", []):
        options = str(entry).split(":", 1)[1].split(",") if ":" in str(entry) else []
        if not {"noexec", "nosuid", "nodev"} <= set(options) or not any(
            option.startswith("size=") for option in options
        ):
            fail(f"tmpfs {entry!r} must be noexec,nosuid,nodev with a size")

    environment = service.get("environment") or {}
    if environment.get("BYTASM_INPUT_POLICY", "fixtures") != "fixtures":
        fail("BYTASM_INPUT_POLICY must be fixtures")
    for key in environment:
        if key in ("BYTASM_HOST",) or any(word in key.upper() for word in ("SECRET", "TOKEN")):
            fail(f"environment variable {key} is not allowed")
    if service.get("env_file"):
        fail("env_file is not allowed (no secrets in the container)")
    if service.get("volumes_from"):
        fail("volumes_from is not allowed")
    return failures


def check_config(config: Mapping[str, Any]) -> list[str]:
    services = config.get("services") or {}
    if not services:
        return ["no services defined"]
    failures: list[str] = []
    for name, service in services.items():
        failures.extend(check_service(name, service))
    for name, network in (config.get("networks") or {}).items():
        if network.get("driver") == "host":
            failures.append(f"network {name}: host driver is not allowed")
    return failures


def main(argv: list[str]) -> int:
    if argv:
        config = json.loads(Path(argv[0]).read_text())
    else:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["docker", "compose", "config", "--format", "json"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        config = json.loads(completed.stdout)
    failures = check_config(config)
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print(f"compose settings OK ({', '.join(config['services'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
