"""Metadata is untrusted and cannot establish a usable Ghidra installation."""

import os
from pathlib import Path

import pytest

from bytasm.ghidra import GhidraConfiguration, diagnose


def configured(tmp_path: Path) -> GhidraConfiguration:
    home = tmp_path / "private-installation"
    java = tmp_path / "private-jdk"
    (home / "Ghidra").mkdir(parents=True)
    (home / "support").mkdir()
    (java / "bin").mkdir(parents=True)
    (home / "Ghidra" / "application.properties").write_text(
        "application.name=Ghidra\napplication.version=12.2\n"
    )
    (java / "release").write_text('JAVA_VERSION="25.0.1"\nOS_ARCH="aarch64"\n')
    # Deliberately not a real tool. Invoking this would create an observable marker.
    for executable in (home / "support" / "analyzeHeadless", java / "bin" / "java"):
        executable.write_text(f"#!/bin/sh\ntouch '{tmp_path / 'EXECUTED'}'\n")
        executable.chmod(0o700)
    return GhidraConfiguration(str(home), str(java))


def test_metadata_ready_is_not_available_and_does_not_execute_tools(tmp_path: Path) -> None:
    result = diagnose(configured(tmp_path), host="darwin", machine="arm64")
    assert result.status == "execution_unavailable"
    assert result.declared_ghidra_version == "12.2" and result.declared_java_major == 25
    assert not result.available and not result.analysis_enabled and result.health_check == "not_run"
    assert not (tmp_path / "EXECUTED").exists()
    assert str(tmp_path) not in result.model_dump_json()


def test_unconfigured_does_not_search_path_or_inherit_global_java() -> None:
    configuration = GhidraConfiguration.from_env({"JAVA_HOME": "/private", "PATH": "/private"})
    assert diagnose(configuration).status == "not_configured"


@pytest.mark.parametrize("path", ["relative", "~/.local/ghidra", "x" * 4097, "/bad\x00path"])
def test_invalid_paths_are_a_diagnostic_not_an_exception(path: str) -> None:
    assert diagnose(GhidraConfiguration(path, None)).status == "installation_invalid"


def test_missing_java_and_incompatible_declared_java_are_distinct(tmp_path: Path) -> None:
    config = configured(tmp_path)
    assert diagnose(GhidraConfiguration(config.home, None)).status == "java_missing"
    assert config.java_home is not None
    release = Path(config.java_home) / "release"
    release.write_text('JAVA_VERSION="21.0.12"\nOS_ARCH="aarch64"\n')
    result = diagnose(config)
    assert result.status == "java_incompatible" and result.declared_java_major == 21


@pytest.mark.parametrize("value", ["12.1.4", "12.3", "<img src=x onerror=alert(1)>"])
def test_unreviewed_or_hostile_ghidra_version_is_not_echoed(tmp_path: Path, value: str) -> None:
    config = configured(tmp_path)
    assert config.home is not None
    (Path(config.home) / "Ghidra" / "application.properties").write_text(
        f"application.name=Ghidra\napplication.version={value}\n"
    )
    result = diagnose(config)
    assert not result.available and value not in result.model_dump_json()


@pytest.mark.parametrize("damage", ["large", "duplicate", "invalid", "symlink", "fifo"])
def test_bad_metadata_is_bounded_and_never_followed(tmp_path: Path, damage: str) -> None:
    config = configured(tmp_path)
    assert config.home is not None
    metadata = Path(config.home) / "Ghidra" / "application.properties"
    if damage == "large":
        metadata.write_bytes(b"a" * 16385)
    elif damage == "duplicate":
        metadata.write_text("application.version=12.2\napplication.version=12.1\n")
    elif damage == "invalid":
        metadata.write_bytes(b"\xff")
    else:
        metadata.unlink()
        if damage == "symlink":
            metadata.symlink_to(tmp_path / "unrelated-private-file")
        else:
            os.mkfifo(metadata)
    result = diagnose(config)
    assert result.status == "installation_invalid" and result.health_check == "not_run"


def test_unsupported_host_and_architecture_cannot_enable_analysis(tmp_path: Path) -> None:
    config = configured(tmp_path)
    assert diagnose(config, host="win32", machine="AMD64").status == "unsupported_host"
    assert diagnose(config, host="linux", machine="mips").status == "unsupported_host"


def test_missing_launcher_and_java_binary_are_not_usable(tmp_path: Path) -> None:
    config = configured(tmp_path)
    assert config.home is not None and config.java_home is not None
    launcher = Path(config.home) / "support" / "analyzeHeadless"
    launcher.chmod(0o600)
    assert diagnose(config).status == "installation_invalid"
    launcher.chmod(0o700)
    (Path(config.java_home) / "bin" / "java").unlink()
    assert diagnose(config).status == "java_missing"
