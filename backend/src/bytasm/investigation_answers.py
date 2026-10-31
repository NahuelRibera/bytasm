"""Pinned, deterministic answers from exact reviewed records; no text similarity joins."""

from typing import Any

QUESTIONS: tuple[tuple[str, str, set[str], set[str]], ...] = (
    (
        "network",
        "Does it contain network references?",
        {"http", "sockets"},
        {"url_reference", "send HTTP request via Windows API"},
    ),
    (
        "process",
        "Does it contain references to starting processes?",
        {"process", "shell", "services"},
        {"create process via Windows API"},
    ),
    (
        "files",
        "Does it refer to files or configuration?",
        {"files", "directories", "environment", "configuration"},
        {
            "read file via Windows API",
            "read INI configuration via Windows API",
            "query environment variable",
            "set environment variable",
        },
    ),
    ("analysis", "What makes analysis harder?", set(), {"upx_style_section_name"}),
)


def build_answers(
    observations: list[Any],
    imports: list[Any],
    functions: list[dict[str, Any]],
    unknowns: list[str],
) -> list[dict[str, Any]]:
    answers = []
    for key, title, categories, rules in QUESTIONS:
        records = []
        for item in imports:
            if item.category not in categories:
                continue
            records.append(
                {
                    "level": "import_present",
                    "observation": item.observation,
                    "why_it_matters": (
                        "The declared import inventory raises a concrete question "
                        "about interfaces available to the program."
                    ),
                    "alternative": item.alternative,
                    "evidence": {
                        "run_id": item.run_id,
                        "invocation_id": item.invocation_id,
                        "output_sha256": item.output_sha256,
                        "pointers": item.pointers,
                        "names": item.supporting_names,
                    },
                    "missing": item.limitation,
                    "next_action": item.next_step,
                }
            )
        for item in observations:
            if item.rule_id not in rules or not item.reviewed:
                continue
            records.append(
                {
                    "level": "static_rule_match",
                    "observation": item.statement,
                    "why_it_matters": item.why_it_matters,
                    "alternative": " ".join(item.alternatives),
                    "evidence": {
                        "run_id": item.run_id,
                        "finding_id": item.finding_id,
                        "invocation_id": item.invocation_id,
                        "output_sha256": item.output_sha256,
                        "locations": item.evidence,
                    },
                    "missing": " ".join(item.limitations),
                    "next_action": item.next_step,
                }
            )
        # A reference is evidence about the tool's exact target. It is never
        # joined to the LIEF import inventory by target-name resemblance.
        if key == "analysis":
            capped = sum(
                bool(
                    f["references_truncated"]
                    or f["instructions_truncated"]
                    or f["body_ranges_truncated"]
                )
                for f in functions
            )
            if capped:
                records.append(
                    {
                        "level": "static_reference",
                        "observation": (
                            f"{capped} retained functions have capped reference, "
                            "instruction or body windows."
                        ),
                        "why_it_matters": (
                            "Relevant code or references may lie outside the retained window."
                        ),
                        "alternative": (
                            "Large ordinary functions can exceed a bounded analysis budget."
                        ),
                        "evidence": {
                            "function_pointers": [
                                f["pointer"]
                                for f in functions
                                if f["references_truncated"]
                                or f["instructions_truncated"]
                                or f["body_ranges_truncated"]
                            ][:64]
                        },
                        "missing": "References outside retained windows were not evaluated.",
                        "next_action": (
                            "Select relevant functions for another bounded reconstruction."
                        ),
                    }
                )
        answers.append(
            {
                "id": key,
                "title": title,
                "observations": records,
                "missing": (
                    "No runtime behavior was observed; absent results do not "
                    "establish absence of this capability."
                ),
                "next_action": (
                    "Inspect exact source records and retained function "
                    "references; review tool coverage and limits."
                ),
                **({"limits": unknowns} if key == "analysis" else {}),
            }
        )
    return answers
