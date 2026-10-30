"""Fail closed on oversized, malformed or type-coerced capa envelopes."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from bytasm.adapters.capa_result import CapaResult


@pytest.mark.parametrize("mutation", ["version", "sha", "extra", "rules", "raw"])
def test_envelope_rejects_bad_provenance_or_bounds(mutation: str) -> None:
    document = {
        "schema_version": 1,
        "tool_version": "10.0.0",
        "sample_sha256": "a" * 64,
        "rules_sha256": "b" * 64,
        "raw": "{}",
        "findings": [],
    }
    if mutation == "version":
        document["tool_version"] = "other"
    elif mutation == "sha":
        document["sample_sha256"] = "not-a-hash"
    elif mutation == "extra":
        document["unknown"] = True
    elif mutation == "raw":
        document["raw"] = "x" * (8 * 1024 * 1024 + 1)
    else:
        document["findings"] = [{}] * 17
    with pytest.raises(ValidationError):
        CapaResult.model_validate(document)


def test_cli_shim_never_uses_a_global_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import capa.main  # type: ignore[import-untyped]
    import capa.rules.cache  # type: ignore[import-untyped]

    from bytasm.adapters import capa_cli

    monkeypatch.chdir(tmp_path)
    (tmp_path / "cache").mkdir(mode=0o700)
    original = capa.rules.cache.get_default_cache_directory

    def actual_entry() -> int:
        assert capa.rules.cache.get_default_cache_directory() == tmp_path / "cache"
        return 0

    monkeypatch.setattr(capa.main, "main", actual_entry)
    assert capa_cli.main() == 0
    assert capa.rules.cache.get_default_cache_directory is original


def test_virtual_addresses_keep_exact_u64_display() -> None:
    from bytasm.api.analysis import _finding_out
    from bytasm.db.models import Evidence, Finding

    address = 0xFFFFF80000001234
    finding = Finding(
        id="f",
        kind="capability",
        title="observation",
        rule_id="rule",
        rule_namespace="namespace",
        rule_set_id="rules",
        fingerprint="f" * 64,
        tool_reported_attributes={},
        match_count=1,
        evidence_truncated=False,
        evidence=[
            Evidence(
                id=1,
                kind="virtual_address",
                pattern_id="function",
                virtual_address=address,
                file_offset=None,
                length=None,
                excerpt_hex="",
                raw_json_pointer="/rules/rule/matches/0/0",
            )
        ],
    )
    output = _finding_out(finding)
    assert output.evidence[0].virtual_address == address
    assert output.evidence[0].virtual_address_hex == "0xfffff80000001234"
