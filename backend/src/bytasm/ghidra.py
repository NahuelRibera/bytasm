"""Read-only optional-provider preflight. Never launches Ghidra, Java or samples.

Metadata is a declaration, not proof that an executable is usable. Until a
real offline runner and bounded health check are verified, availability is
always false. No environment variable can override that release boundary.
"""

import os
import platform
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

MAX_METADATA_BYTES = 16 * 1024
Status = Literal[
    "not_configured",
    "installation_invalid",
    "unsupported_version",
    "java_missing",
    "java_incompatible",
    "unsupported_host",
    "execution_unavailable",
]


@dataclass(frozen=True)
class GhidraConfiguration:
    # Avoid leaking local paths if a containing Settings object is inspected.
    home: str | None = field(default=None, repr=False)
    java_home: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "GhidraConfiguration":
        source = os.environ if env is None else env
        return cls(source.get("BYTASM_GHIDRA_HOME"), source.get("BYTASM_GHIDRA_JAVA_HOME"))


class GhidraDiagnostic(BaseModel):
    provider: Literal["ghidra"] = "ghidra"
    available: Literal[False] = False
    analysis_enabled: Literal[False] = False
    status: Status
    message: str
    declared_ghidra_version: Literal["12.2"] | None = None
    declared_java_major: int | None = None
    verification: Literal["metadata_only"] = "metadata_only"
    health_check: Literal["not_run"] = "not_run"


def _directory(value: str) -> Path:
    if len(value) > 4096 or "\x00" in value or not Path(value).is_absolute():
        raise ValueError("Invalid local directory")
    path = Path(value)
    if not path.is_dir():
        raise ValueError("Missing local directory")
    return path


def _properties(path: Path) -> dict[str, str]:
    # Nonblocking open means a FIFO cannot hang the API before fstat refuses it.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA_BYTES:
            raise ValueError("Invalid metadata file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(MAX_METADATA_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("Oversized metadata file")
    result = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not re.fullmatch(r"[A-Za-z0-9_.]+", key) or key in result:
            raise ValueError("Invalid metadata declaration")
        result[key] = value.strip().strip('"')
    return result


def _executable(path: Path) -> bool:
    return stat.S_ISREG(path.lstat().st_mode) and os.access(path, os.X_OK)


def diagnose(
    config: GhidraConfiguration, *, host: str | None = None, machine: str | None = None
) -> GhidraDiagnostic:
    """Fixed messages only: no raw filesystem errors, paths or tool text escape."""
    if not config.home:
        return GhidraDiagnostic(
            status="not_configured",
            message="Ghidra is not configured. Nothing is downloaded or installed automatically.",
        )
    try:
        home = _directory(config.home)
    except (OSError, ValueError):
        return GhidraDiagnostic(
            status="installation_invalid",
            message="The configured Ghidra directory is missing, unreadable or invalid.",
        )
    host = sys.platform if host is None else host
    machine = platform.machine() if machine is None else machine
    aliases = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}
    architecture = aliases.get(machine.lower())
    if host not in ("linux", "darwin") or architecture is None:
        return GhidraDiagnostic(
            status="unsupported_host",
            message="Only Linux/macOS x64 or ARM64 metadata is checked; analysis is disabled.",
        )
    try:
        properties = _properties(home / "Ghidra" / "application.properties")
        if properties.get("application.name") != "Ghidra" or not _executable(
            home / "support" / "analyzeHeadless"
        ):
            raise ValueError("Invalid installation")
        version = properties.get("application.version")
    except (OSError, ValueError):
        return GhidraDiagnostic(
            status="installation_invalid",
            message="Ghidra metadata or its fixed Headless launcher is invalid or unavailable.",
        )
    if version != "12.2":
        return GhidraDiagnostic(
            status="unsupported_version",
            message="Only Ghidra 12.2 metadata is reviewed; provider usability is unverified.",
        )
    if not config.java_home:
        return GhidraDiagnostic(
            status="java_missing",
            declared_ghidra_version="12.2",
            message="Configure a separate caller-installed 64-bit JDK 25; global Java is not used.",
        )
    try:
        java_home = _directory(config.java_home)
        java = _properties(java_home / "release")
        if not _executable(java_home / "bin" / "java"):
            raise ValueError("Missing Java executable")
    except (OSError, ValueError):
        return GhidraDiagnostic(
            status="java_missing",
            declared_ghidra_version="12.2",
            message="Configured JDK metadata or its fixed Java executable is missing or invalid.",
        )
    match = re.fullmatch(
        r"([1-9][0-9]{0,2})(?:\.[0-9]+)*(?:\+[A-Za-z0-9.-]+)?", java.get("JAVA_VERSION", "")
    )
    major = int(match[1]) if match else None
    if major != 25 or aliases.get(java.get("OS_ARCH", "").lower()) != architecture:
        return GhidraDiagnostic(
            status="java_incompatible",
            declared_ghidra_version="12.2",
            declared_java_major=major,
            message="JDK metadata must declare version 25 and a matching 64-bit host architecture.",
        )
    return GhidraDiagnostic(
        status="execution_unavailable",
        declared_ghidra_version="12.2",
        declared_java_major=25,
        message=(
            "Installation metadata matches. No verified offline Ghidra runner or real health "
            "check is implemented. Analysis remains disabled; no tool was launched."
        ),
    )
