"""Bytasm's bundled YARA-X rule set (blueprint 3.1, 5.6; ADR-0003).

The rules are self-written, committed under `rules/yara/`, and baked into the
container image. There is no API or UI to add or edit rules, and no
environment variable or request field selects another directory: the rule set
is part of the code, like the fixture manifest (blueprint 8.2 "Tool rules are
baked into the image at build time").

Each `<identifier>.yar` file holds exactly one rule whose identifier equals
the file name (checked when the rules are compiled). The files are joined
into one canonical *snapshot*:

    // bytasm-rule-file: <name>.yar\n<file text, newline-terminated>

in file-name order. The rule set's SHA-256 is the SHA-256 of that snapshot,
and the snapshot itself is stored by that hash with every run that used it.
Editing a rule therefore produces a new rule set hash; earlier runs keep
pointing at the exact text they were matched with.

The text is read as trusted repository content, but it is still bounded and
validated here, and only YARA-X (in a child process) ever compiles it.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from bytasm.config import REPO_ROOT

DEFAULT_RULES_DIR: Final = REPO_ROOT / "rules" / "yara"
RULESET_FILE: Final = "ruleset.json"

MAX_RULE_FILES: Final = 32
MAX_RULE_FILE_BYTES: Final = 64 * 1024
MAX_SNAPSHOT_BYTES: Final = 256 * 1024
FILE_MARKER: Final = "// bytasm-rule-file: "
_FILE_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,62}\.yar$")
_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_VERSION: Final = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class RuleSetError(Exception):
    """The rule directory is missing, malformed, or over a limit."""


@dataclass(frozen=True)
class RuleFile:
    name: str  # "<identifier>.yar"
    text: str

    @property
    def identifier(self) -> str:
        return self.name.removesuffix(".yar")


@dataclass(frozen=True)
class RuleSet:
    name: str
    version: str
    files: tuple[RuleFile, ...]
    snapshot: bytes
    sha256: str

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"


def build_snapshot(files: tuple[RuleFile, ...]) -> bytes:
    parts = []
    for rule in files:
        text = rule.text if rule.text.endswith("\n") else rule.text + "\n"
        parts.append(f"{FILE_MARKER}{rule.name}\n{text}")
    return "".join(parts).encode("utf-8")


def split_snapshot(snapshot: bytes) -> dict[str, str]:
    """Map file name -> exact rule text, from a stored snapshot."""
    text = snapshot.decode("utf-8")
    result: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith(FILE_MARKER):
            if current is not None:
                result[current] = "".join(lines)
            current = line[len(FILE_MARKER) :].rstrip("\n")
            lines = []
        elif current is not None:
            lines.append(line)
    if current is not None:
        result[current] = "".join(lines)
    return result


def file_at_line(snapshot: bytes, line: int) -> tuple[str, int] | None:
    """Translate a 1-based line in the snapshot into (file name, line in file)."""
    current: str | None = None
    start = 0
    for number, text in enumerate(snapshot.decode("utf-8").splitlines(), start=1):
        if text.startswith(FILE_MARKER):
            current = text[len(FILE_MARKER) :]
            start = number
        elif number == line:
            return (current, number - start) if current is not None else None
    return None


def load_rule_set(directory: Path = DEFAULT_RULES_DIR) -> RuleSet:
    try:
        meta = json.loads((directory / RULESET_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuleSetError("ruleset.json is missing or not valid JSON") from exc
    if not isinstance(meta, dict):
        raise RuleSetError("ruleset.json must be an object")
    name, version = meta.get("name"), meta.get("version")
    if not isinstance(name, str) or not _NAME.match(name):
        raise RuleSetError("ruleset.json: invalid name")
    if not isinstance(version, str) or not _VERSION.match(version):
        raise RuleSetError("ruleset.json: invalid version")

    files: list[RuleFile] = []
    for path in sorted(directory.iterdir(), key=lambda p: p.name):
        if path.suffix != ".yar":
            continue
        if not _FILE_NAME.match(path.name) or path.is_symlink() or not path.is_file():
            raise RuleSetError(f"unexpected rule file name or type: {path.name!r}")
        data = path.read_bytes()
        if not data.strip() or len(data) > MAX_RULE_FILE_BYTES:
            raise RuleSetError(f"{path.name}: empty or larger than {MAX_RULE_FILE_BYTES} bytes")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuleSetError(f"{path.name}: not UTF-8") from exc
        if FILE_MARKER in text:
            raise RuleSetError(f"{path.name}: contains the reserved snapshot marker")
        files.append(RuleFile(path.name, text))
    if not files:
        raise RuleSetError("no .yar files")
    if len(files) > MAX_RULE_FILES:
        raise RuleSetError(f"more than {MAX_RULE_FILES} rule files")
    frozen = tuple(files)
    snapshot = build_snapshot(frozen)
    if len(snapshot) > MAX_SNAPSHOT_BYTES:
        raise RuleSetError(f"rule set larger than {MAX_SNAPSHOT_BYTES} bytes")
    return RuleSet(name, version, frozen, snapshot, hashlib.sha256(snapshot).hexdigest())
