"""Private per-run work directories for adapter children.

Each run gets `<root>/<random hex>/` with mode 0700, holding `upload.bin`
(mode 0400) and, on success, the child's `result.json`. The directory is never
served over HTTP, and the caller deletes it on every exit path.
"""

import os
import shutil
import uuid
from pathlib import Path

from bytasm.runner.supervisor import INPUT_NAME


def create_workdir(root: Path) -> Path:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / uuid.uuid4().hex
    path.mkdir(mode=0o700)
    return path


def input_path(workdir: Path) -> Path:
    return workdir / INPUT_NAME


def write_input(workdir: Path, data: bytes) -> Path:
    path = input_path(workdir)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    seal_input(path)
    return path


def seal_input(path: Path) -> None:
    """Make the admitted input read-only before any child sees it."""
    os.chmod(path, 0o400)


def remove_workdir(workdir: Path) -> None:
    shutil.rmtree(workdir, ignore_errors=True)
