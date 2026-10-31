"""Human answers use exact reviewed identifiers and survive privacy derivation."""

from types import SimpleNamespace

from bytasm.investigation_answers import build_answers


def test_authored_rule_identifiers_are_grouped_without_matching_display_names() -> None:
    def observation(name: str, reviewed: bool = True) -> SimpleNamespace:
        return SimpleNamespace(
            rule_id=name,
            reviewed=reviewed,
            statement="Exact static API feature",
            why_it_matters="Context",
            alternatives=["Ordinary client"],
            run_id="r",
            finding_id="f",
            invocation_id="i",
            output_sha256="d",
            evidence=[],
            limitations=["No execution"],
            next_step="Inspect code",
        )

    answers = build_answers(
        [
            observation("send HTTP request via Windows API"),
            observation("create process via Windows API"),
            observation("read INI configuration via Windows API"),
            observation("network process file", reviewed=False),
        ],
        [],
        [],
        [],
    )
    assert [len(a["observations"]) for a in answers] == [1, 1, 1, 0]
    assert answers[0]["observations"][0]["level"] == "static_rule_match"
    assert answers[0]["observations"][0]["evidence"]["finding_id"] == "f"
