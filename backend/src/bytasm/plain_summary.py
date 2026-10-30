"""Reviewed deterministic English templates; no model calls or safety classifications."""

from collections import Counter
from typing import Any


def describe(
    identity: dict[str, Any],
    status: str | None,
    steps: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    strings: dict[str, Any] | None,
) -> list[str]:
    sha = str(identity.get("sha256", ""))[:16]
    file_format = identity.get("format", identity.get("detected_format", "unknown format"))
    arch = identity.get("architecture", "architecture declared in the file")
    paragraphs = [f"Bytasm read file {sha}… ({file_format}, {arch}). It did not run the file."]
    if not steps:
        paragraphs.append(
            "Header metadata is available. No completed analysis run was selected; "
            "this does not mean that the tools reported no matches."
        )
    else:
        complete = sum(step["status"] == "succeeded" for step in steps)
        paragraphs.append(
            f"Analysis status: {status}. {complete} of {len(steps)} selected steps succeeded. "
            + "; ".join(f"{step['tool']}: {step['status'].replace('_', ' ')}" for step in steps)
            + "."
        )
        counts = Counter(finding.get("tool", "yara-x") for finding in findings)
        observations = [
            f"{step['tool']} reported {counts[step['tool']]} rule matches in its completed step."
            for step in steps
            if step["status"] == "succeeded" and step["tool"] != "strings"
        ]
        if strings is not None:
            observations.append(
                f"The strings step recorded {strings['stored']} printable text sequences "
                "of at least six characters; individual values may be shortened to 256 characters."
                + (
                    " Extraction was capped; additional strings may exist."
                    if strings.get("truncated")
                    else ""
                )
            )
        if observations:
            paragraphs.append(" ".join(observations))
    paragraphs.append(
        "What this tells you: which static patterns the completed tools reported. "
        "What it does not tell you: whether the file is safe, malicious, or what it will do "
        "when run. Missing steps and no matches cannot establish absence of behavior."
    )
    return paragraphs


def report_summary(document: dict[str, Any]) -> list[str]:
    pattern = document.get("pattern_analysis") or {}
    identity = {
        **document["sample"],
        "architecture": document["metadata"]["declared_in_header"]["architecture"],
    }
    paragraphs = describe(
        identity,
        pattern.get("run", {}).get("status"),
        pattern.get("steps", []),
        pattern.get("findings", []),
        pattern.get("strings"),
    )
    context = document.get("analysis_context")
    if context and context["latest_run_id"] != context["selected_run_id"]:
        paragraphs[1] += (
            f" The most recent run is {context['latest_status']}; "
            "its results were not selected for this report."
        )
    comparison = document.get("comparison")
    if comparison:
        changes = []
        for name, category in comparison["categories"].items():
            if category["status"] != "comparable":
                changes.append(f"{name}: {category['status']} (no change count inferred)")
            else:
                changes.append(
                    f"{name}: +{category['added']} added, −{category['removed']} removed, "
                    f"~{category['changed']} changed"
                )
        paragraphs.insert(-1, "Comparison of the selected versions — " + "; ".join(changes) + ".")
    return paragraphs
