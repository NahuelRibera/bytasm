"""Server configuration, read once from the local environment at start-up.

The input policy is part of this configuration and nothing else: no API
endpoint, request header, or UI control can read a different value or change
it while the server runs (blueprint 3.4).

Environment variables (all optional):

  BYTASM_DATA_DIR      where the database, blobs, reports and temp files live
                       (default: <repository>/data; never served over HTTP)
  BYTASM_HOST          bind address; must be loopback (default 127.0.0.1)
  BYTASM_PORT          TCP port (default 8000)
  BYTASM_INPUT_POLICY  "fixtures" (default) or "self_built" (Linux only)
  BYTASM_CONTAINER     "1" only in the Compose image (see `container` below)
  BYTASM_SOURCE_REVISION  source revision baked into the image (no .git there)
"""

import ipaddress
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

from bytasm.runner.limits import DEFAULT_LIMITS, MAX_INPUT_BYTES, ParserLimits

PolicyMode = Literal["fixtures", "self_built"]

REPO_ROOT: Final = Path(__file__).resolve().parents[3]
LOOPBACK_NAMES: Final = frozenset({"127.0.0.1", "::1", "localhost"})
# Files that container runtimes create; container mode refuses to start without one.
CONTAINER_MARKERS: Final = (Path("/.dockerenv"), Path("/run/.containerenv"))
CONTAINER_BIND: Final = "0.0.0.0"  # noqa: S104 - container mode only, see Settings.container


class ConfigError(Exception):
    """The configuration is unsafe or invalid; the server must not start."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8000
    input_policy: PolicyMode = "fixtures"
    max_upload_bytes: int = MAX_INPUT_BYTES
    limits: ParserLimits = DEFAULT_LIMITS
    web_dist: Path | None = field(default_factory=lambda: REPO_ROOT / "frontend" / "dist")
    # Temp directories and unreferenced stored files older than this are
    # removed by the start-up sweep.
    sweep_age_seconds: float = 3600.0
    # Container mode (compose.yaml only). Inside the container's own network
    # namespace the server must listen on its interface (0.0.0.0) for Docker
    # to forward the published port, so the "loopback only" binding control
    # moves to Compose: the port is published on host 127.0.0.1 only, which
    # `scripts/check_compose.py` asserts. Host, Origin and request-header
    # guards still apply. self_built is refused in this mode, because the
    # listener is not loopback (blueprint 5.7, 8.2). See ADR-0002.
    container: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        policy = env.get("BYTASM_INPUT_POLICY", "fixtures")
        if policy not in ("fixtures", "self_built"):
            raise ConfigError(
                f"BYTASM_INPUT_POLICY must be 'fixtures' or 'self_built', not {policy!r}."
            )
        container = env.get("BYTASM_CONTAINER", "") == "1"
        if container:
            if not any(marker.exists() for marker in CONTAINER_MARKERS):
                raise ConfigError(
                    "BYTASM_CONTAINER=1 is only for the Bytasm container image; "
                    "no container runtime marker was found."
                )
            if "BYTASM_HOST" in env:
                raise ConfigError("BYTASM_HOST cannot be set in container mode.")
        port_text = env.get("BYTASM_PORT", "8000")
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise ConfigError(f"BYTASM_PORT must be a TCP port number, not {port_text!r}.")
        settings = cls(
            data_dir=Path(env.get("BYTASM_DATA_DIR", str(REPO_ROOT / "data"))).resolve(),
            host=CONTAINER_BIND if container else env.get("BYTASM_HOST", "127.0.0.1"),
            port=int(port_text),
            input_policy="self_built" if policy == "self_built" else "fixtures",
            container=container,
        )
        settings.validate()
        if settings.input_policy == "self_built" and sys.platform != "linux":
            # Blueprint 5.4.1 Q5: outside Linux the parser's memory limit
            # (RLIMIT_AS) cannot be applied, so native runs are fixtures-only.
            raise ConfigError(
                "self_built mode requires Linux, where the parser's memory limit is enforced. "
                f"On {sys.platform} Bytasm runs in fixtures-only mode."
            )
        return settings

    def validate(self) -> None:
        """Refuse configurations the v0.1 design does not allow."""
        if self.container:
            if self.host != CONTAINER_BIND:
                raise ConfigError(f"Container mode listens on {CONTAINER_BIND} only.")
            if self.input_policy != "fixtures":
                raise ConfigError(
                    "self_built mode is refused in container mode: the listener there is "
                    "not loopback. Container runs are fixtures-only in v0.1."
                )
            return
        if not is_loopback(self.host):
            # There is no authentication, so the API must never be reachable
            # from other machines (blueprint 8.2 "Network exposure").
            raise ConfigError(
                f"Refusing to bind to {self.host!r}: Bytasm v0.1 has no authentication and "
                "only listens on loopback (127.0.0.1, ::1 or localhost)."
            )
        if self.input_policy == "self_built" and not is_loopback(self.host):
            raise ConfigError("self_built mode is only allowed on a loopback binding.")

    @property
    def allowed_hosts(self) -> frozenset[str]:
        """Accepted `Host` header values (DNS-rebinding and cross-site guard)."""
        return frozenset({f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"})

    @property
    def allowed_origins(self) -> frozenset[str]:
        return frozenset(f"http://{host}" for host in self.allowed_hosts)

    @property
    def database_path(self) -> Path:
        return self.data_dir / "bytasm.sqlite3"

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    @property
    def blobs_dir(self) -> Path:
        return self.data_dir / "blobs"

    @property
    def outputs_dir(self) -> Path:
        return self.data_dir / "outputs"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"
