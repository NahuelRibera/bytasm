"""Bytasm's bundled YARA-X rule set: loading, snapshots, and expected matches.

The expected-match table is the rule set's test corpus (blueprint 10.5): it
says which committed fixtures each rule should and should not match. The
scans run in the real adapter child, never in the test process.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest
from conftest import ALL_FIXTURES, FIXTURES_DIR

from bytasm.jobs.scan import parse_yara_result, write_rules, yara_argv
from bytasm.rules import (
    DEFAULT_RULES_DIR,
    FILE_MARKER,
    MAX_RULE_FILE_BYTES,
    RuleSetError,
    build_snapshot,
    file_at_line,
    load_rule_set,
    split_snapshot,
)
from bytasm.runner import workspace
from bytasm.runner.limits import DEFAULT_LIMITS
from bytasm.runner.supervisor import run_child, yara_adapter_command

EXPECTED_MATCHES = {
    "capa_environment-x86_64.exe": ["pe_dos_stub_message", "pe_kernel32_import_name"],
    "entropy_blob-aarch64.elf": ["elf_dynamic_loader_path"],
    "exports_v1-x86_64.dll": ["pe_dos_stub_message", "pe_kernel32_import_name"],
    "hello_v1-aarch64-stripped.elf": ["elf_dynamic_loader_path", "url_reference"],
    "hello_v1-aarch64.elf": ["elf_dynamic_loader_path", "url_reference"],
    "hello_v1-x86_64-stripped.elf": ["elf_dynamic_loader_path", "url_reference"],
    "hello_v1-x86_64.elf": ["elf_dynamic_loader_path", "url_reference"],
    "hello_v2-x86_64.elf": ["elf_dynamic_loader_path", "url_reference"],
    "hello_v1-x86_64.exe": ["pe_dos_stub_message", "pe_kernel32_import_name", "url_reference"],
    "hello_v1-x86_64.o": ["url_reference"],
    "inventory_many-x86_64.elf": ["elf_dynamic_loader_path"],
}


def _valid_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "ruleset.json").write_text(json.dumps({"name": "t", "version": "1.0.0"}))
    (directory / "a_rule.yar").write_text("rule a_rule { condition: true }\n")
    return directory


def test_bundled_rule_set_loads_and_has_one_rule_per_file() -> None:
    rule_set = load_rule_set()
    assert rule_set.label == "bytasm-rules@0.2.0"
    assert [f.name for f in rule_set.files] == sorted(f.name for f in rule_set.files)
    for rule_file in rule_set.files:
        assert rule_file.text.count("\nrule ") + rule_file.text.startswith("rule ") == 1
        assert f"rule {rule_file.identifier} " in rule_file.text
        # Descriptive wording only.
        lowered = rule_file.text.lower()
        for word in ("malicious", "malware", "severity", "score"):
            assert word not in lowered


def test_snapshot_is_deterministic_and_round_trips() -> None:
    first, second = load_rule_set(), load_rule_set()
    assert first.snapshot == second.snapshot and first.sha256 == second.sha256
    assert hashlib.sha256(first.snapshot).hexdigest() == first.sha256
    assert split_snapshot(first.snapshot) == {f.name: f.text for f in first.files}
    located = file_at_line(first.snapshot, 2)
    assert located == (first.files[0].name, 1)


def test_editing_a_rule_changes_the_hash(tmp_path: Path) -> None:
    directory = _valid_dir(tmp_path)
    before = load_rule_set(directory).sha256
    (directory / "a_rule.yar").write_text("rule a_rule { condition: false }\n")
    assert load_rule_set(directory).sha256 != before


def test_snapshot_adds_only_a_final_newline() -> None:
    from bytasm.rules import RuleFile

    snapshot = build_snapshot((RuleFile("x.yar", "rule x { condition: true }"),))
    assert split_snapshot(snapshot) == {"x.yar": "rule x { condition: true }\n"}


@pytest.mark.parametrize(
    "damage",
    [
        "no_meta",
        "bad_meta",
        "bad_version",
        "bad_name",
        "empty",
        "too_big",
        "not_utf8",
        "marker",
        "symlink",
        "no_rules",
    ],
)
def test_loader_refuses_malformed_rule_directories(tmp_path: Path, damage: str) -> None:
    directory = _valid_dir(tmp_path)
    rule = directory / "a_rule.yar"
    if damage == "no_meta":
        (directory / "ruleset.json").unlink()
    elif damage == "bad_meta":
        (directory / "ruleset.json").write_text("[]")
    elif damage == "bad_version":
        (directory / "ruleset.json").write_text(json.dumps({"name": "t", "version": "x"}))
    elif damage == "bad_name":
        (directory / "../evil.yar").write_text("")
        (directory / "Bad-Name.yar").write_text("rule x { condition: true }")
    elif damage == "empty":
        rule.write_text("  \n")
    elif damage == "too_big":
        rule.write_text("//" + "x" * MAX_RULE_FILE_BYTES)
    elif damage == "not_utf8":
        rule.write_bytes(b"rule a_rule { condition: true } // \xff\n")
    elif damage == "marker":
        rule.write_text(f"{FILE_MARKER}other.yar\nrule a_rule {{ condition: true }}\n")
    elif damage == "symlink":
        target = tmp_path / "outside.yar"
        target.write_text("rule b { condition: true }\n")
        os.symlink(target, directory / "b_rule.yar")
    elif damage == "no_rules":
        rule.unlink()
    with pytest.raises(RuleSetError):
        load_rule_set(directory)


def _scan(fixture: Path, root: Path) -> list[str]:
    rule_set = load_rule_set()
    data = fixture.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    workdir = workspace.create_workdir(root)
    try:
        workspace.write_input(workdir, data)
        write_rules(workdir, rule_set.snapshot)
        outcome = asyncio.run(
            run_child(
                yara_argv(yara_adapter_command(), DEFAULT_LIMITS, rule_set.sha256, sha),
                workdir,
                DEFAULT_LIMITS,
                parse_result=lambda raw: parse_yara_result(raw, rule_set.sha256, sha),
            )
        )
    finally:
        workspace.remove_workdir(workdir)
    assert outcome.status == "succeeded", outcome.reason
    assert outcome.result is not None and outcome.result.scan is not None
    return [rule.identifier for rule in outcome.result.scan.matching_rules]


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_bundled_rules_match_exactly_the_expected_fixtures(fixture: Path, tmp_path: Path) -> None:
    assert fixture.parent == FIXTURES_DIR / "bin"
    assert _scan(fixture, tmp_path) == EXPECTED_MATCHES[fixture.name]


def test_every_bundled_rule_is_exercised_by_the_corpus() -> None:
    matched = {rule for rules in EXPECTED_MATCHES.values() for rule in rules}
    defined = {f.identifier for f in load_rule_set().files}
    # upx_style_section_name has no positive fixture yet; it documents the
    # "section name, not proof of packing" wording and must never match ours.
    assert defined - matched == {"upx_style_section_name"}
    assert DEFAULT_RULES_DIR.is_dir()
