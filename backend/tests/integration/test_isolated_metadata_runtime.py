"""Opt-in REAL runtime tests. Self-authored harnesses only; never execute a sample."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from api_support import api_client, create_project, do_import, make_settings
from conftest import ELF_X86_64

from bytasm.intake.manifest import Manifest, default_manifest_path
from bytasm.intake.policy import InputPolicy
from bytasm.runner.isolated_metadata import (
    IsolationConfig,
    _control,
    container_argv,
    parse_isolated,
)

IMAGE = os.environ.get("BYTASM_TEST_ISOLATION_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="Opt-in disposable Docker metadata runtime")


def test_real_isolated_import_and_cleanup(tmp_path: Path) -> None:
    assert IMAGE
    with api_client(make_settings(tmp_path, metadata_isolation_image=IMAGE)) as client:
        response = do_import(client, create_project(client), ELF_X86_64.read_bytes())
        assert response.status_code == 201, response.text
        version = response.json()["sample_version"]
        assert version["sha256"]


def test_real_runtime_unavailable_never_falls_back(tmp_path: Path) -> None:
    # Nonexistent immutable image; native adapter would succeed on this fixture.
    with api_client(
        make_settings(tmp_path, metadata_isolation_image="sha256:" + "0" * 64)
    ) as client:
        result = do_import(client, create_project(client), ELF_X86_64.read_bytes())
        assert result.status_code != 201


@pytest.mark.parametrize(
    "case",
    [
        "filesystem",
        "network",
        "disk",
        "pids",
        "detach",
        "memory",
        "crash",
        "malformed",
        "output",
        "timeout",
    ],
)
def test_real_boundary_harness(case: str, tmp_path: Path) -> None:
    from uuid import uuid4

    from bytasm.runner.supervisor import _drain

    assert IMAGE

    async def probe() -> None:
        name = "bytasm-test-" + uuid4().hex
        args = container_argv(IsolationConfig(IMAGE), "a" * 64, name)
        args[-5:] = ["-I", "/opt/bytasm-boundary-probe.py", case]
        # Keep the immutable image while replacing only the fixed worker command.
        # Original tail: image, -I, -m, module, digest.
        args.insert(len(args) - 3, IMAGE)
        canary = tmp_path / "trusted-host-canary"
        canary.write_text("self-authored host canary")
        if case == "filesystem":
            args.append(str(canary))
        code, _ = await _control("docker", *args)
        assert code == 0
        _, inspected = await _control("docker", "inspect", "--format", "{{json .Mounts}}", name)
        assert json.loads(inspected) == []
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "start",
            "--attach",
            name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout = asyncio.create_task(_drain(proc.stdout, 4096))
        stderr = asyncio.create_task(_drain(proc.stderr, 4096))
        try:
            if case == "timeout":
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(2):
                        await proc.wait()
            else:
                async with asyncio.timeout(15):
                    code = await proc.wait()
                raw, overflow = await stdout
                await stderr
                assert overflow if case == "output" else not overflow
                if case == "filesystem":
                    record = json.loads(raw)
                    assert not any(record["reads"].values())
                    assert not any(record["writes"].values())
                    assert record["uid"] == 65532
                elif case in {"memory", "crash"}:
                    assert code != 0
                elif case == "malformed":
                    with pytest.raises(json.JSONDecodeError):
                        json.loads(raw)
                else:
                    assert code == 0, raw
        finally:
            code, _ = await _control("docker", "rm", "--force", name)
            assert code == 0
            if proc.returncode is None:
                await proc.wait()
            await asyncio.gather(stdout, stderr)
            code, _ = await _control("docker", "container", "inspect", name)
            assert code != 0
            assert canary.read_text() == "self-authored host canary"
        # A fresh real parse after every harness detects obvious cross-job contamination.
        policy = InputPolicy("fixtures", Manifest.load(default_manifest_path()))
        result = await parse_isolated(ELF_X86_64.read_bytes(), policy, IsolationConfig(IMAGE))
        assert result.status == "succeeded", result.reason

    asyncio.run(probe())
