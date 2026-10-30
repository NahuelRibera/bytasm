"""The production CLI must not turn local explorer queries into access logs."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx


def test_real_server_and_worker_do_not_log_personal_paths_or_query_values(tmp_path: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    data = tmp_path / "private-user-data"
    env = {
        **os.environ,
        "BYTASM_DATA_DIR": str(data),
        "BYTASM_PORT": str(port),
        "BYTASM_INPUT_POLICY": "fixtures",
    }
    env.pop("BYTASM_CONTAINER", None)
    env.pop("BYTASM_HOST", None)
    processes: list[subprocess.Popen[str]] = []
    captured = []
    try:
        processes.append(
            subprocess.Popen(
                [sys.executable, "-m", "bytasm", "serve"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        )
        deadline = time.monotonic() + 15
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
            while True:
                try:
                    if client.get("/api/v1/health", timeout=1).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert processes[0].poll() is None and time.monotonic() < deadline
                time.sleep(0.05)
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-m", "bytasm", "worker"],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            )
            assert client.get("/api/v1/health?query=PRIVATE_QUERY_SENTINEL").status_code == 200
            deadline = time.monotonic() + 10
            while not (data / "worker.heartbeat").exists():
                assert processes[-1].poll() is None and time.monotonic() < deadline
                time.sleep(0.05)
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                output, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            captured.append(output)
    logs = "\n".join(captured)
    assert len(logs) < 64 * 1024
    assert "PRIVATE_QUERY_SENTINEL" not in logs
    assert str(data) not in logs
    assert "Bytasm" in logs and "worker" in logs
