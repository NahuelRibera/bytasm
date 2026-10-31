"""Bounded, reviewed explanations of exact static rule observations; never AI."""

import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, Field

YARA_SHA = "cca6936c3b56167d7d2c403171149b70b42cecfef3228a9090599b8948b3946a"
CAPA_SHA = "c78c7ff8ad97ba7e6f2b74060e425bbcc830ea30c5fb5b2594acc9365d78d3a6"
CATALOG = {
    "url_reference": (
        "The rule matched an HTTP or HTTPS URL prefix in the stored bytes.",
        (
            "This may indicate embedded link text or configuration; it does not prove "
            "a network request."
        ),
    ),
    "pe_dos_stub_message": (
        "The rule matched the conventional DOS-stub message in a PE file.",
        (
            "This may reflect a standard executable header stub; it does not "
            "characterize the program's purpose."
        ),
    ),
    "pe_kernel32_import_name": (
        "The rule matched KERNEL32.dll as text in a PE file, not by reading its import table.",
        (
            "This may be a Windows library reference; inspect the import records "
            "before interpreting it."
        ),
    ),
    "elf_dynamic_loader_path": (
        (
            "The rule matched Linux loader-path text in an ELF file, not a verified "
            "interpreter record."
        ),
        (
            "This may be a loader reference or embedded text; it does not establish "
            "how the file will run."
        ),
    ),
    "upx_style_section_name": (
        "The rule matched a PE section declared as UPX0 or UPX1 and the corresponding text.",
        "This may warrant reviewing section declarations; a name alone does not establish packing.",
    ),
    "query environment variable": (
        "The static rule matched an environment-query API feature in analyzed code.",
        (
            "This may indicate code that reads environment settings; it does not "
            "prove that the query executes."
        ),
    ),
    "set environment variable": (
        "The static rule matched an environment-setting API feature in analyzed code.",
        (
            "This may indicate code that changes environment settings; it does not "
            "prove that a setting changes."
        ),
    ),
}
GLOSSARY = {
    "Static observation": "Information read from a file without launching the executable.",
    "File offset": "A byte position measured from the beginning of the stored file.",
    "Virtual address": (
        "An address reported by a tool, not a verified file offset or execution event."
    ),
    "Hypothesis": (
        "A cautious possible interpretation, not an analyst conclusion or established behavior."
    ),
}


def safe_filename(value: str | None) -> str:
    return re.split(r"[/\\]", value or "")[-1][:256] or "Unnamed file"


def explanation(tool: str, version: str, rule: str, sha: str) -> tuple[str, str]:
    reviewed = (tool == "yara-x" and version == "1.22.1" and sha == YARA_SHA) or (
        tool == "capa" and version == "10.0.0" and sha == CAPA_SHA
    )
    rule_belongs = (tool == "capa") == (
        rule in {"query environment variable", "set environment variable"}
    )
    if reviewed and rule_belongs and rule in CATALOG:
        return CATALOG[rule]
    return (
        "The tool reported a static rule match; inspect its exact rule and evidence.",
        "There is no reviewed interpretation for this rule/tool/ruleset combination.",
    )


Text = Annotated[str, Field(max_length=256)]


class ReviewObservation(BaseModel):
    title: Text | None = None
    key: Text
    tool: Text
    tool_version: Text
    adapter_version: Text
    rule_id: Text
    rule_version: Text
    rule_sha256: Text
    statement: Text
    hypothesis: Text
    source_href: Text
    locations: list[Text] = Field(max_length=3)
    pointers: list[Annotated[str, Field(max_length=512)]] = Field(max_length=3)
    evidence_capped: bool


class ReviewOut(BaseModel):
    selection_policy: Literal["source-order-v1", "relevance-v1"] = "source-order-v1"
    selection_explanation: Annotated[str, Field(max_length=512)] | None = None
    template_version: Literal["1"] = "1"
    run_id: str | None
    version_id: Text
    total: int = Field(ge=0)
    capped: bool
    observations: list[ReviewObservation] = Field(max_length=12)
    glossary: dict[str, str] = GLOSSARY


def build_review(
    findings: list[dict[str, Any]], run_id: str | None, version_id: str, *, snapshot: bool = False
) -> ReviewOut:
    observations = []
    ordered = sorted(
        findings,
        key=lambda row: (
            str(row.get("tool", "yara-x")),
            str(row.get("rule_id", "")),
            str(row.get("fingerprint", "")),
        ),
    )
    for finding in ordered[:12]:
        tool = str(finding.get("tool", "yara-x"))
        version = str(finding.get("tool_version", "Not recorded"))
        sha = str(finding.get("rule_set_sha256", "Not recorded"))
        rule = str(finding.get("rule_id", "Not recorded"))
        statement, hypothesis = explanation(tool, version, rule, sha)
        key = str(finding.get("fingerprint", finding.get("id", "unknown")))
        evidence = finding.get("evidence", [])
        locations = []
        for item in evidence[:3]:
            if item.get("virtual_address") is not None:
                locations.append(
                    f"Tool-reported virtual address {int(item['virtual_address']):#x}; "
                    "file offset not supplied"
                )
            elif item.get("file_offset") is not None and item.get("length") is not None:
                locations.append(
                    f"File byte offset {item['file_offset']} ({int(item['file_offset']):#x}), "
                    f"length {item['length']} bytes"
                )
            else:
                locations.append("Exact location unavailable")
        observations.append(
            ReviewObservation(
                key=key,
                tool=tool,
                tool_version=version,
                adapter_version=str(finding.get("adapter_version", "Not recorded")),
                rule_id=rule,
                rule_version=str(finding.get("rule_version", "Not recorded")),
                rule_sha256=sha,
                statement=statement,
                hypothesis=hypothesis,
                source_href=f"#review-{quote(key, safe='')}"
                if snapshot
                else (
                    f"/runs/{quote(run_id or '', safe='')}#finding-"
                    f"{quote(str(finding.get('id', '')), safe='')}"
                ),
                locations=locations,
                pointers=[
                    str(item.get("raw_json_pointer", "Not recorded")) for item in evidence[:3]
                ],
                evidence_capped=bool(finding.get("evidence_truncated")) or len(evidence) > 3,
            )
        )
    return ReviewOut(
        run_id=run_id,
        version_id=version_id,
        total=len(findings),
        capped=len(findings) > 12,
        observations=observations,
    )


def report_review(document: dict[str, Any]) -> ReviewOut:
    pattern = document.get("pattern_analysis") or {}
    steps = {step["tool"]: step for step in pattern.get("steps", [])}
    profile = {
        step["tool"]: step for step in pattern.get("run", {}).get("profile", {}).get("steps", [])
    }
    findings = []
    for finding in pattern.get("findings", []):
        step = steps.get(finding["tool"], {})
        if step.get("status") != "succeeded":
            continue
        label = profile.get(finding["tool"], {}).get("rule_set", {}).get("label", "")
        findings.append(
            {
                **finding,
                "adapter_version": step.get("adapter_version") or "Not recorded",
                "rule_version": label.rsplit("@", 1)[1] if "@" in label else "Not recorded",
            }
        )
    return build_review(
        findings,
        pattern.get("run", {}).get("id"),
        (document.get("scope") or {}).get("version_ids", [""])[-1],
        snapshot=True,
    )
