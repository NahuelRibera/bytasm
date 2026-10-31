"""Broker admission, fixed runtime contract and fail-closed configuration."""

import asyncio
from pathlib import Path

import pytest

from bytasm.intake.manifest import Manifest, default_manifest_path
from bytasm.intake.policy import InputPolicy


def test_broker_refuses_before_runtime_and_requires_local_image_id(tmp_path: Path) -> None:
    from bytasm.runner.isolated_metadata import IsolationConfig, parse_isolated

    with pytest.raises(ValueError):
        IsolationConfig(image="untrusted:latest")
    policy = InputPolicy("fixtures", Manifest.load(default_manifest_path()))
    outcome = asyncio.run(
        parse_isolated(b"not a fixture", policy, IsolationConfig(image="sha256:" + "a" * 64))
    )
    assert outcome.status == "rejected" and outcome.reason == "input_policy"


def test_container_profile_has_no_host_mounts_or_network() -> None:
    from bytasm.runner.isolated_metadata import IsolationConfig, container_argv

    args = container_argv(IsolationConfig(image="sha256:" + "a" * 64), "b" * 64, "c" * 32)
    assert "--network=none" in args and "--read-only" in args
    assert "--cap-drop=ALL" in args and "--security-opt=no-new-privileges" in args
    assert not any(x in args for x in ("--volume", "-v", "--mount", "--privileged"))
    assert "--log-driver=none" in args
