"""compose.yaml keeps the v0.1 container settings (blueprint 12.1), and the
checker that asserts them refuses each weakening."""

import copy
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "check_compose.py"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_compose", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()

# The shape `docker compose config --format json` resolves compose.yaml to.
GOOD: dict[str, Any] = {
    "name": "bytasm",
    "services": {
        "api": {
            "cap_drop": ["ALL"],
            "cpus": 2,
            "environment": {"BYTASM_INPUT_POLICY": "fixtures"},
            "init": True,
            "mem_limit": "2147483648",
            "memswap_limit": "2147483648",
            "networks": {"default": None},
            "pids_limit": 128,
            "ports": [
                {"host_ip": "127.0.0.1", "mode": "ingress", "protocol": "tcp", "target": 8000}
            ],
            "read_only": True,
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"],  # noqa: S108
            "user": "10001:10001",
            "volumes": [{"source": "bytasm-data", "target": "/data", "type": "volume"}],
        }
    },
    "networks": {"default": {"name": "bytasm_default"}},
    "volumes": {"bytasm-data": {"name": "bytasm_bytasm-data"}},
}


def _mutated(**changes: Any) -> dict[str, Any]:
    config = copy.deepcopy(GOOD)
    service = config["services"]["api"]
    for key, value in changes.items():
        if value is None:
            service.pop(key, None)
        else:
            service[key] = value
    return config


def test_good_config_passes() -> None:
    assert checker.check_config(GOOD) == []


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"ports": [{"host_ip": "", "target": 8000}]}, "127.0.0.1 only"),
        ({"ports": [{"host_ip": "0.0.0.0", "target": 8000}]}, "127.0.0.1 only"),
        ({"user": None}, "non-root"),
        ({"user": "0:0"}, "non-root"),
        ({"user": "root"}, "non-root"),
        ({"cap_drop": None}, "cap_drop"),
        ({"cap_add": ["SYS_PTRACE"]}, "cap_add"),
        ({"security_opt": []}, "no-new-privileges"),
        ({"security_opt": ["no-new-privileges:true", "seccomp=unconfined"]}, "unconfined"),
        ({"privileged": True}, "privileged"),
        ({"read_only": None}, "read_only"),
        ({"init": None}, "init"),
        ({"mem_limit": None}, "mem_limit"),
        ({"memswap_limit": None}, "memswap_limit"),
        ({"cpus": None}, "cpus"),
        ({"pids_limit": None}, "pids_limit"),
        ({"pids_limit": -1}, "pids_limit"),
        ({"network_mode": "host"}, "network_mode"),
        ({"pid": "host"}, "pid"),
        ({"devices": ["/dev/kvm:/dev/kvm"]}, "devices"),
        (
            {
                "volumes": [
                    {"source": "bytasm-data", "target": "/data", "type": "volume"},
                    {
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                        "type": "bind",
                    },
                ]
            },
            "Docker socket",
        ),
        (
            {"volumes": [{"source": "/Users/someone", "target": "/data", "type": "bind"}]},
            "named data volume",
        ),
        ({"tmpfs": ["/tmp"]}, "noexec"),  # noqa: S108
        ({"environment": {"BYTASM_INPUT_POLICY": "self_built"}}, "fixtures"),
        ({"environment": {"BYTASM_HOST": "0.0.0.0"}}, "BYTASM_HOST"),
        ({"env_file": ["./.env"]}, "env_file"),
    ],
)
def test_each_weakening_is_refused(changes: dict[str, Any], expected: str) -> None:
    failures = checker.check_config(_mutated(**changes))
    assert failures, changes
    assert any(expected in failure for failure in failures), failures


def test_checker_reads_a_saved_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    saved = tmp_path / "config.json"
    saved.write_text(json.dumps(_mutated(init=None)))
    assert checker.main([str(saved)]) == 1
    assert "FAIL api: init must be true" in capsys.readouterr().out


@pytest.mark.skipif(
    shutil.which("docker") is None or not (ROOT / "compose.yaml").exists(),
    reason="needs the Docker CLI and the repository's compose.yaml",
)
def test_repository_compose_file_passes() -> None:
    resolved = subprocess.run(
        ["docker", "compose", "config", "--format", "json"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if resolved.returncode != 0:
        pytest.skip(f"docker compose is unavailable: {resolved.stderr.strip()[:200]}")
    config = json.loads(resolved.stdout)
    assert checker.check_config(config) == []
    service = config["services"]["api"]
    # Not covered by the generic checks: exactly one service, one port.
    assert list(config["services"]) == ["api"]
    assert [(port["host_ip"], port["target"]) for port in service["ports"]] == [("127.0.0.1", 8000)]
