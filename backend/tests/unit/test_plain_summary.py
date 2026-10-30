"""Summaries state execution/coverage truthfully without invented scores."""

import pytest

from bytasm.plain_summary import describe, report_summary


@pytest.mark.parametrize("status", ["succeeded", "partial", "failed", "cancelled"])
def test_status_and_incomplete_steps_are_explicit(status: str) -> None:
    steps = [{"tool": "strings", "status": "succeeded"}, {"tool": "capa", "status": "unsupported"}]
    paragraphs = describe(
        {"sha256": "a" * 64, "format": "ELF", "architecture": "x86_64"},
        status,
        steps,
        [],
        {"stored": 5, "truncated": True},
    )
    text = " ".join(paragraphs)
    assert f"Analysis status: {status}" in text
    assert "1 of 2 selected steps succeeded" in text and "capa: unsupported" in text
    assert "Extraction was capped" in text
    assert "capa reported 0" not in text and "%" not in text
    assert "did not run the file" in text
    assert len(paragraphs) <= 4


@pytest.mark.parametrize(
    "missing", ["failed", "cancelled", "timed_out", "unsupported", "unavailable", "skipped"]
)
def test_zero_results_only_describe_successful_steps(missing: str) -> None:
    text = " ".join(
        describe(
            {"sha256": "a" * 64},
            "partial",
            [{"tool": "yara-x", "status": "succeeded"}, {"tool": "capa", "status": missing}],
            [],
            None,
        )
    )
    assert "yara-x reported 0 rule matches in its completed step" in text
    assert f"capa: {missing.replace('_', ' ')}" in text
    assert "capa reported" not in text


def test_comparison_warnings_do_not_invent_zero_counts() -> None:
    document = {
        "sample": {"sha256": "a" * 64},
        "metadata": {"declared_in_header": {"architecture": "x86_64"}},
        "pattern_analysis": None,
        "comparison": {
            "categories": {
                "imports": {"status": "comparable", "added": 2, "removed": 1, "changed": 3},
                "capabilities": {"status": "incompatible"},
            }
        },
    }
    text = " ".join(report_summary(document))
    assert "+2 added, −1 removed, ~3 changed" in text
    assert "capabilities: incompatible (no change count inferred)" in text
