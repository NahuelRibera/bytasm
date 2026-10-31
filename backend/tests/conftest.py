"""Shared test helpers.

Tests only READ fixture files. No test executes a fixture binary; the CLI is
run as `python -m bytasm`, which parses the fixture as data.
"""

import hashlib
import math
import subprocess
import sys
from pathlib import Path

import pytest

from bytasm.intake.manifest import Manifest, default_manifest_path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "fixtures"
MANIFEST_PATH = FIXTURES_DIR / "MANIFEST.sha256"

ELF_AARCH64 = FIXTURES_DIR / "bin" / "hello_v1-aarch64.elf"
ELF_AARCH64_STRIPPED = FIXTURES_DIR / "bin" / "hello_v1-aarch64-stripped.elf"
ELF_ENTROPY = FIXTURES_DIR / "bin" / "entropy_blob-aarch64.elf"
ELF_X86_64_OBJECT = FIXTURES_DIR / "bin" / "hello_v1-x86_64.o"
ELF_X86_64 = FIXTURES_DIR / "bin" / "hello_v1-x86_64.elf"
ELF_X86_64_V2 = FIXTURES_DIR / "bin" / "hello_v2-x86_64.elf"
ELF_X86_64_STRIPPED = FIXTURES_DIR / "bin" / "hello_v1-x86_64-stripped.elf"
PE_X86_64_EXE = FIXTURES_DIR / "bin" / "hello_v1-x86_64.exe"
PE_X86_64_DLL = FIXTURES_DIR / "bin" / "exports_v1-x86_64.dll"
ELF_FIXTURES = (
    ELF_AARCH64,
    ELF_AARCH64_STRIPPED,
    ELF_ENTROPY,
    ELF_X86_64_OBJECT,
    ELF_X86_64,
    ELF_X86_64_STRIPPED,
    ELF_X86_64_V2,
    FIXTURES_DIR / "bin" / "inventory_many-x86_64.elf",
)
CAPA_PE = FIXTURES_DIR / "bin" / "capa_environment-x86_64.exe"
V09_PE_FIXTURES = tuple(
    FIXTURES_DIR / "bin" / f"{name}-x86_64.exe"
    for name in (
        "capa_create_process",
        "capa_http_request",
        "capa_read_file",
        "capa_read_configuration",
        "capa_load_library",
        "capa_control_unrelated",
        "capa_control_reference",
        "pe_version_resource",
        "pe_resource_noversion",
    )
)
PE_FIXTURES = (PE_X86_64_EXE, PE_X86_64_DLL, CAPA_PE, *V09_PE_FIXTURES)
ALL_FIXTURES = ELF_FIXTURES + PE_FIXTURES


@pytest.fixture
def manifest() -> Manifest:
    assert default_manifest_path() == MANIFEST_PATH
    return Manifest.load(MANIFEST_PATH)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_test_manifest(directory: Path, *files: Path) -> Manifest:
    """A test-only manifest listing generated, test-authored files.

    The CLI cannot use this: it always loads fixtures/MANIFEST.sha256. Tests use
    it with `inspect_file` to drive malformed or generated inputs through the
    whole pipeline (blueprint 9.2).
    """
    lines = [f"{sha256_of(f.read_bytes())}  {f.name}" for f in files]
    path = directory / "TEST_MANIFEST.sha256"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return Manifest.load(path)


def independent_entropy(data: bytes) -> float:
    """A second, deliberately different Shannon entropy implementation.

    Bytasm's own uses collections.Counter; this one uses bytes.count per value.
    """
    total = len(data)
    result = 0.0
    for value in range(256):
        count = data.count(bytes([value]))
        if count:
            result += (count / total) * math.log2(total / count)
    return result


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run `python -m bytasm <args>` and capture raw stdout bytes."""
    return subprocess.run(
        [sys.executable, "-m", "bytasm", *args],
        cwd=cwd,
        capture_output=True,
        check=False,
        timeout=60,
    )
