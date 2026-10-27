"""Server configuration: loopback only, policy from local configuration only."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from bytasm.config import ConfigError, Settings, is_loopback


def test_defaults_are_fixtures_mode_on_loopback(tmp_path: Path) -> None:
    settings = Settings.from_env({"BYTASM_DATA_DIR": str(tmp_path)})
    assert settings.input_policy == "fixtures"
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert settings.allowed_hosts == {"127.0.0.1:8000", "localhost:8000", "[::1]:8000"}


@pytest.mark.skipif(sys.platform != "linux", reason="self_built requires Linux")
def test_self_built_is_enabled_only_by_explicit_local_setting(tmp_path: Path) -> None:
    env = {"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_INPUT_POLICY": "self_built"}
    assert Settings.from_env(env).input_policy == "self_built"


@pytest.mark.skipif(sys.platform == "linux", reason="checks the non-Linux refusal")
def test_self_built_is_refused_where_memory_limit_cannot_be_applied(tmp_path: Path) -> None:
    env = {"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_INPUT_POLICY": "self_built"}
    with pytest.raises(ConfigError, match="requires Linux"):
        Settings.from_env(env)


@pytest.mark.parametrize("value", ["SELF_BUILT", "any", "third_party", ""])
def test_unknown_policy_values_are_refused(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env({"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_INPUT_POLICY": value})


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "10.0.0.1", "example.com"])
@pytest.mark.parametrize("policy", ["fixtures", "self_built"])
def test_non_loopback_binding_is_refused(tmp_path: Path, host: str, policy: str) -> None:
    env = {"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_HOST": host, "BYTASM_INPUT_POLICY": policy}
    with pytest.raises(ConfigError, match="loopback"):
        Settings.from_env(env)


@pytest.mark.parametrize("port", ["0", "70000", "http", "-1"])
def test_invalid_port_is_refused(tmp_path: Path, port: str) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env({"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_PORT": port})


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.8.9.10", True),
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("::", False),
        ("8.8.8.8", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert is_loopback(host) is expected


@pytest.mark.parametrize("policy", ["fixtures", "self_built"])
def test_serve_refuses_to_start_on_a_public_address(tmp_path: Path, policy: str) -> None:
    env = {
        **os.environ,
        "BYTASM_DATA_DIR": str(tmp_path),
        "BYTASM_HOST": "0.0.0.0",
        "BYTASM_INPUT_POLICY": policy,
    }
    result = subprocess.run(
        [sys.executable, "-m", "bytasm", "serve"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1
    assert "Refusing to bind" in result.stderr
    assert not (tmp_path / "bytasm.sqlite3").exists()


@pytest.fixture
def container_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    marker = tmp_path / ".dockerenv"
    marker.touch()
    monkeypatch.setattr("bytasm.config.CONTAINER_MARKERS", (marker,))
    return marker


def test_container_mode_listens_on_the_container_interface_with_fixtures_only(
    tmp_path: Path, container_marker: Path
) -> None:
    settings = Settings.from_env({"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_CONTAINER": "1"})
    assert settings.container is True
    assert settings.host == "0.0.0.0"  # noqa: S104 - container mode
    assert settings.input_policy == "fixtures"
    # The browser still talks to the published host port on loopback.
    assert settings.allowed_hosts == {"127.0.0.1:8000", "localhost:8000", "[::1]:8000"}


def test_container_mode_is_refused_outside_a_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("bytasm.config.CONTAINER_MARKERS", (tmp_path / "missing",))
    with pytest.raises(ConfigError, match="container runtime marker"):
        Settings.from_env({"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_CONTAINER": "1"})


def test_container_mode_refuses_self_built(tmp_path: Path, container_marker: Path) -> None:
    env = {
        "BYTASM_DATA_DIR": str(tmp_path),
        "BYTASM_CONTAINER": "1",
        "BYTASM_INPUT_POLICY": "self_built",
    }
    with pytest.raises(ConfigError, match="self_built mode is refused in container mode"):
        Settings.from_env(env)


def test_container_mode_refuses_a_host_override(tmp_path: Path, container_marker: Path) -> None:
    env = {"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_CONTAINER": "1", "BYTASM_HOST": "127.0.0.1"}
    with pytest.raises(ConfigError, match="BYTASM_HOST cannot be set"):
        Settings.from_env(env)


@pytest.mark.parametrize("value", ["0", "true", "yes", ""])
def test_only_the_exact_container_flag_enables_container_mode(
    tmp_path: Path, container_marker: Path, value: str
) -> None:
    settings = Settings.from_env({"BYTASM_DATA_DIR": str(tmp_path), "BYTASM_CONTAINER": value})
    assert settings.container is False
    assert settings.host == "127.0.0.1"


def test_container_settings_cannot_be_built_with_self_built(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Settings(
            data_dir=tmp_path,
            host="0.0.0.0",  # noqa: S104 - container mode
            input_policy="self_built",
            container=True,
        ).validate()
