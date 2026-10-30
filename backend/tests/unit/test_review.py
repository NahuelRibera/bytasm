"""Reviewed interpretation never outlives its exact rule/tool provenance."""

from bytasm.review import YARA_SHA, build_review, explanation, safe_filename


def test_known_rule_has_a_cautious_explanation_but_unknown_provenance_does_not() -> None:
    known = explanation("yara-x", "1.22.1", "url_reference", YARA_SHA)
    assert "prefix" in known[0] and "may" in known[1].lower()
    for tool, version, sha in [
        ("other", "1.22.1", YARA_SHA),
        ("yara-x", "other", YARA_SHA),
        ("yara-x", "1.22.1", "0" * 64),
    ]:
        assert "no reviewed interpretation" in explanation(tool, version, "url_reference", sha)[1]


def test_review_is_bounded_links_to_source_and_marks_capped_evidence() -> None:
    findings = [
        {
            "tool": "yara-x",
            "tool_version": "1.22.1",
            "rule_id": "url_reference",
            "rule_set_sha256": YARA_SHA,
            "fingerprint": str(i),
            "id": str(i),
            "evidence": [
                {"file_offset": j, "length": 7, "raw_json_pointer": f"/matches/{j}"}
                for j in range(5)
            ],
            "match_count": 5,
        }
        for i in range(15)
    ]
    review = build_review(findings, "a" * 32, "b" * 32)
    assert review.total == 15 and len(review.observations) == 12 and review.capped
    item = review.observations[0]
    assert item.source_href.startswith("/runs/") and "#finding-" in item.source_href
    assert len(item.locations) == 3 and item.evidence_capped
    assert item.rule_sha256 == YARA_SHA and "byte" in item.locations[0]


def test_filename_hides_directory_components_without_interpreting_contents() -> None:
    assert safe_filename(r"C:\Users\private\sample.exe") == "sample.exe"
    assert safe_filename("/private/home/name/sample.elf") == "sample.elf"
    assert safe_filename(None) == "Unnamed file"


def test_failed_step_does_not_generate_a_hypothesis_from_stray_findings() -> None:
    from bytasm.plain_summary import describe

    text = " ".join(
        describe(
            {"sha256": "a" * 64},
            "failed",
            [{"tool": "yara-x", "status": "failed"}],
            [
                {
                    "tool": "yara-x",
                    "tool_version": "1.22.1",
                    "rule_id": "url_reference",
                    "rule_set_sha256": YARA_SHA,
                }
            ],
            None,
        )
    )
    assert "URL prefix" not in text and "may indicate" not in text


def test_metadata_addresses_have_exact_display_strings_above_javascript_precision() -> None:
    from bytasm.api.schemas import SectionOut

    section = SectionOut(
        index=1,
        name=".text",
        section_type=None,
        file_offset=0,
        raw_size=8,
        virtual_address=0xFFFFF80000001234,
        virtual_size=2**63 + 1,
        flags=[],
        entropy=None,
        entropy_note="not measured",
    )
    assert section.model_dump()["virtual_address_hex"] == "0xfffff80000001234"
    assert section.model_dump()["virtual_size_decimal"] == "9223372036854775809"
