#!/usr/bin/env python3
"""Build from a pre-existing trusted local image and run real disposable-worker tests."""

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "bytasm-local:v0.4"
TAG = "bytasm-metadata-boundary:local"
DOCKER = shutil.which("docker")
UV = shutil.which("uv")
if DOCKER is None or UV is None:
    raise SystemExit("Local Docker and uv executables are required")

# Refuse a missing base instead of allowing a build to implicitly download one.
subprocess.run(  # noqa: S603 - fixed trusted local verification commands
    [DOCKER, "image", "inspect", BASE], check=True, stdout=subprocess.DEVNULL
)
subprocess.run(  # noqa: S603 - fixed trusted local verification commands
    [
        DOCKER,
        "build",
        "--pull=false",
        "--network=none",
        "-f",
        "isolation/Dockerfile",
        "-t",
        TAG,
        ".",
    ],
    cwd=ROOT,
    check=True,
)
image = subprocess.check_output(  # noqa: S603 - local image inspection only
    [DOCKER, "image", "inspect", TAG, "--format", "{{.Id}}"], text=True
).strip()
print("Testing immutable metadata worker", image, flush=True)
subprocess.run(  # noqa: S603 - fixed trusted local verification commands
    [
        UV,
        "--directory",
        "backend",
        "run",
        "--no-sync",
        "pytest",
        "tests/integration/test_isolated_metadata_runtime.py",
        "-q",
    ],
    cwd=ROOT,
    env={**os.environ, "BYTASM_TEST_ISOLATION_IMAGE": image},
    check=True,
)
