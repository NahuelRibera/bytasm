"""Pinned, read-only upstream and Bytasm-authored capa subset.

No rule upload/configuration surface."""

import hashlib
import json
from pathlib import Path

from bytasm.config import REPO_ROOT

RULES_DIR = REPO_ROOT / "rules" / "capa"
VERSION = "10.0.0"
MAX_RAW = 8 * 1024 * 1024


def snapshot() -> tuple[bytes, str]:
    manifest_path = RULES_DIR / "ruleset.json"
    if manifest_path.is_symlink():
        raise ValueError("Invalid packaged capa manifest")
    with manifest_path.open("rb") as stream:
        manifest_data = stream.read(65_537)
    if len(manifest_data) > 65_536:
        raise ValueError("Oversized packaged capa manifest")
    manifest = json.loads(manifest_data)
    if not 1 <= len(manifest["files"]) <= 16:
        raise ValueError("Invalid packaged capa rule count")
    files = {}
    for item in manifest["files"]:
        name = item["file"]
        if Path(name).name != name or not name.endswith(".yml"):
            raise ValueError("Invalid packaged capa rule name")
        path = RULES_DIR / name
        if path.is_symlink():
            raise ValueError("Invalid packaged capa rule")
        with path.open("rb") as stream:
            data = stream.read(32_769)
        if len(data) > 32_768 or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("Packaged capa rules changed")
        files[name] = data.decode("utf-8")
    if not 1 <= len(files) <= 16:
        raise ValueError("Invalid packaged capa rule count")
    raw = (
        json.dumps(files, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != manifest["sha256"]:
        raise ValueError("Packaged capa snapshot changed")
    return raw, sha
