"""Who generated a result: Bytasm version and source revision (blueprint 2 J9)."""

import os
import shutil
import subprocess
from dataclasses import dataclass

from bytasm import __version__
from bytasm.config import REPO_ROOT


@dataclass(frozen=True)
class Generator:
    name: str
    version: str
    # `git describe --always --dirty --abbrev=40` of the checkout, or None.
    # "-dirty" means the code had uncommitted changes when the server started.
    source_revision: str | None
    # Container image ID. Not known inside the container either, so None.
    image_id: str | None = None


def source_revision() -> str | None:
    git = shutil.which("git")
    if git is None or not (REPO_ROOT / ".git").exists():
        # The container image has no .git; `make compose-build` bakes the
        # revision in as a build argument instead.
        return os.environ.get("BYTASM_SOURCE_REVISION") or None
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            [git, "-C", str(REPO_ROOT), "describe", "--always", "--dirty", "--abbrev=40"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def current_generator() -> Generator:
    return Generator(name="bytasm", version=__version__, source_revision=source_revision())
