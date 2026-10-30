"""Optional metadata checks must not create sample work or enable analysis."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from api_support import api_client, ctx_of, make_settings

from bytasm.config import Settings
from bytasm.ghidra import GhidraConfiguration


def test_tools_reports_unconfigured_optional_provider_without_changing_profiles(
    tmp_path: Path,
) -> None:
    with api_client(make_settings(tmp_path)) as client:
        result = client.get("/api/v1/tools").json()
        assert [row["tool"] for row in result["tools"]] == ["lief", "strings", "yara-x", "capa"]
        assert [row["id"] for row in result["profiles"]] == ["default-static", "full-static"]
        diagnostic = result["optional_providers"][0]
        assert diagnostic["provider"] == "ghidra"
        assert diagnostic["status"] == "not_configured"
        assert diagnostic["available"] is False and diagnostic["analysis_enabled"] is False
        assert diagnostic["health_check"] == "not_run"
        assert client.get("/api/v1/projects").json() == []
        assert list(ctx_of(client).tmp_dir.iterdir()) == []


def test_optional_configuration_is_local_fixed_at_startup_and_nonfatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = str(tmp_path / "PRIVATE_DIRECTORY_SENTINEL")
    settings = Settings.from_env(
        {
            "BYTASM_DATA_DIR": str(tmp_path / "data"),
            "BYTASM_GHIDRA_HOME": private,
            "BYTASM_GHIDRA_JAVA_HOME": private,
            "BYTASM_GHIDRA_AVAILABLE": "1",
        }
    )
    assert settings.ghidra == GhidraConfiguration(private, private)
    assert private not in repr(settings)
    with api_client(settings) as client:
        monkeypatch.delenv("BYTASM_GHIDRA_HOME", raising=False)
        response = client.get("/api/v1/tools")
        assert response.status_code == 200
        assert response.json()["optional_providers"][0]["status"] == "installation_invalid"
        assert private not in response.text and "PRIVATE_DIRECTORY_SENTINEL" not in response.text
        assert client.get("/api/v1/health").status_code == 200


def test_doctor_does_not_create_data_or_launch_java(tmp_path: Path) -> None:
    data = tmp_path / "must-not-be-created"
    env = {key: value for key, value in os.environ.items() if not key.startswith("BYTASM_")}
    env["BYTASM_DATA_DIR"] = str(data)
    result = subprocess.run(
        [sys.executable, "-m", "bytasm", "doctor"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    diagnostic = json.loads(result.stdout)
    assert diagnostic["status"] == "not_configured"
    assert diagnostic["available"] is False and diagnostic["health_check"] == "not_run"
    assert result.stderr == "" and str(tmp_path) not in result.stdout
    assert not data.exists()
