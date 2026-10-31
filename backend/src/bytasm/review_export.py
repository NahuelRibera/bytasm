"""Privacy derivatives of a pinned review. JSON is canonical; HTML is inert."""

import hashlib
import html
import re
from typing import Any, Literal

from pydantic import Field

from bytasm.reports.generate import canonical_json
from bytasm.review_snapshot import Identity, Snapshot, Strict, TextRecord


class ExportPolicy(Strict):
    analyst_notes: bool = False
    overview: bool = True
    observations: bool = True
    technical_details: bool = True
    string_values: bool = False
    original_names: bool = False
    mask_sensitive_values: bool = True


class ExportDocument(Strict):
    schema_version: Literal["bytasm-review-export-1"]
    review_id: str
    review_sha256: str
    created_at: str
    sample: Identity
    scope: Literal["combined", "exact_run"]
    exact_run_id: str | None
    catalog_version: str
    source_selection_policy: str
    sources: list[dict[str, Any]] = Field(max_length=5)
    privacy_policy: ExportPolicy
    observations: list[dict[str, Any]] = Field(max_length=48)
    import_observations: list[dict[str, Any]] = Field(max_length=16)
    function_reviews: list[dict[str, Any]] = Field(max_length=128)
    observations_total: int
    observations_capped: bool
    strings: list[TextRecord] = Field(max_length=5000)
    unknowns: list[str]
    excluded_content: list[str]
    privacy_notice: str
    overview: dict[str, str] | None = None
    declared_filename: str | None = None


# Deliberately narrow deterministic heuristics: false positives/negatives are
# possible. No reputation lookup and no claim that all secrets are detected.
SECRET = re.compile(
    r"(?i)(?:\b(?:password|passwd|token|api[_-]?key|secret)\s*[:=]\s*[^\s;,]+"
    r"|\bAKIA[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b)"
)
PRIVATE_PATH = re.compile(r"(?:/(?:Users|home)/[^\s\"'<>]+|[A-Za-z]:\\Users\\[^\s\"'<>]+)")


def mask_text(value: str) -> str:
    return PRIVATE_PATH.sub("[private path masked]", SECRET.sub("[plausible secret masked]", value))


def mask_tree(value: Any) -> Any:
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, list):
        return [mask_tree(item) for item in value]
    if isinstance(value, dict):
        return {key: mask_tree(item) for key, item in value.items()}
    return value


def derivative(review: Snapshot, source_digest: str, policy: ExportPolicy) -> dict[str, Any]:
    observations = (
        [o.model_dump(mode="json") for o in review.observations] if policy.observations else []
    )
    sources = []
    for source in review.sources:
        item = source.model_dump(mode="json")
        if not policy.technical_details and item["selected"]:
            item["selected"] = {
                key: item["selected"][key]
                for key in (
                    "run_id",
                    "invocation_id",
                    "status",
                    "run_status",
                    "output_sha256",
                    "completeness",
                )
            }
        sources.append(item)
    if not policy.technical_details:
        observations = [
            {
                key: value
                for key, value in obs.items()
                if key
                not in {
                    "evidence",
                    "rule_id",
                    "rule_sha256",
                    "relevance",
                }
            }
            for obs in observations
        ]
    import_observations = (
        [item.model_dump(mode="json") for item in review.import_observations]
        if policy.observations
        else []
    )
    function_reviews = (
        [dict(item) for item in review.function_reviews] if policy.analyst_notes else []
    )
    if not policy.technical_details:
        import_observations = [
            {
                key: value
                for key, value in item.items()
                if key
                not in {
                    "pointers",
                    "supporting_names",
                }
            }
            for item in import_observations
        ]
        for item in function_reviews:
            item["identity"] = {
                key: value
                for key, value in item["identity"].items()
                if key not in {"entry", "record_pointer"}
            }
            if item.get("citation"):
                item["citation"] = {"text_sha256": item["citation"]["text_sha256"]}
    document: dict[str, Any] = {
        "schema_version": "bytasm-review-export-1",
        "review_id": review.id,
        "review_sha256": source_digest,
        "created_at": review.created_at.isoformat(),
        "sample": review.sample.model_dump(),
        "scope": review.scope,
        "exact_run_id": review.exact_run_id,
        "catalog_version": review.catalog_version,
        "source_selection_policy": review.source_selection_policy,
        "sources": sources,
        "function_reviews": function_reviews,
        "privacy_policy": policy.model_dump(),
        "observations": observations,
        "import_observations": import_observations,
        "observations_total": review.observations_total,
        "observations_capped": review.observations_capped,
        "strings": [r.model_dump() for r in review.strings] if policy.string_values else [],
        "unknowns": review.unknowns,
        "excluded_content": [
            "Raw tool outputs, pseudocode and machine symbols are excluded.",
            "Version/finding annotations and previous function revisions are excluded.",
            *([] if policy.analyst_notes else ["Analyst overlays and notes"]),
            *([] if policy.overview else ["Overview"]),
            *([] if policy.observations else ["Observations"]),
            *(
                []
                if policy.technical_details
                else ["Technical evidence locations and profile parameters"]
            ),
            *([] if policy.string_values else ["String values"]),
            *([] if policy.original_names else ["Original filename"]),
        ],
        "privacy_notice": (
            "Original evidence remains in local storage. Export minimization does not delete it. "
            "Sensitive-value masking is heuristic; false positives and missed values are possible. "
            "Digests and identifiers remain for citation; this derivative is not anonymous."
        ),
    }
    if policy.overview:
        document["overview"] = {
            "selection_explanation": review.selection_explanation,
            "summary": "Static observations from pinned sources; no safety verdict.",
        }
    if policy.original_names:
        document["declared_filename"] = review.declared_filename
    if policy.mask_sensitive_values:
        document = mask_tree(document)
    return ExportDocument.model_validate(document).model_dump(mode="json", exclude_unset=True)


def export_bytes(document: dict[str, Any], format: Literal["json", "html"]) -> bytes:
    raw = canonical_json(document)
    if format == "json":
        return raw

    def escaped(value: Any) -> str:
        return html.escape(str(value))

    sections = ["<h1>Bytasm pinned static review</h1>"]
    sections.append(
        "<p>Review <code>"
        + escaped(document["review_id"])
        + "</code> · "
        + escaped(document["scope"])
        + "</p>"
    )
    sample = document["sample"]
    sections.append(
        "<p>"
        + escaped(sample["format"])
        + " · "
        + escaped(sample["size_bytes"])
        + " bytes. Sample SHA-256 <code>"
        + escaped(sample["sha256"])
        + "</code>.</p>"
    )
    if "overview" in document:
        sections.append(
            "<h2>Review summary</h2><p>"
            + escaped(document["overview"]["summary"])
            + "</p><p>"
            + escaped(document["overview"]["selection_explanation"])
            + "</p>"
        )
    sections.append("<h2>Actual inspection scope</h2><ul>")
    for source in document["sources"]:
        selected, latest = source["selected"], source["latest_attempt"]
        text = (
            source["tool"]
            + ": "
            + (
                "retained run " + selected["run_id"] + " (" + selected["status"] + ")"
                if selected
                else "no completed source in this scope"
            )
        )
        if latest:
            text += "; latest attempt " + latest["run_id"] + " (" + latest["status"] + ")"
        sections.append("<li>" + escaped(text) + "</li>")
    sections.append("</ul><h2>Retained observations</h2>")
    for item in document["observations"]:
        sections.append(
            "<article><h3>"
            + escaped(item["title"])
            + "</h3><p>"
            + escaped(item["statement"])
            + "</p><p>"
            + escaped(item["hypothesis"])
            + "</p><p>Why it matters: "
            + escaped(item["why_it_matters"])
            + "</p><ul>"
        )
        sections.extend(
            "<li>Alternative: " + escaped(text) + "</li>" for text in item["alternatives"]
        )
        sections.extend("<li>Limit: " + escaped(text) + "</li>" for text in item["limitations"])
        sections.append("</ul><p>Next step: " + escaped(item["next_step"]) + "</p></article>")
    for item in document.get("import_observations", []):
        sections.append(
            "<article><h3>"
            + escaped(item["title"])
            + "</h3><p>"
            + escaped(item["observation"])
            + "</p><p>Alternative: "
            + escaped(item["alternative"])
            + "</p><p>"
            + escaped(item["limitation"])
            + "</p><p>Next step: "
            + escaped(item["next_step"])
            + "</p></article>"
        )
    sections.append("<h2>Important unknowns</h2><ul>")
    sections.extend("<li>" + escaped(text) + "</li>" for text in document["unknowns"])
    sections.append(
        "</ul><h2>Privacy and exclusions</h2><p>" + escaped(document["privacy_notice"]) + "</p><ul>"
    )
    sections.extend("<li>" + escaped(text) + "</li>" for text in document["excluded_content"])
    sections.append(
        "</ul><h2>Canonical review appendix</h2><p>The exact JSON derivative, "
        "including source provenance and the applied inclusion policy:</p><pre>"
        + escaped(raw.decode())
        + "</pre>"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>Bytasm pinned review</title><style>"
        "body{font:16px/1.6 system-ui;margin:2rem;max-width:80rem;overflow-wrap:anywhere}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85rem}"
        "article{border-bottom:1px solid #888;padding-block:1rem}"
        "@media print{body{margin:0}article{break-inside:avoid}}"
        "</style></head><body>" + "".join(sections) + "</body></html>\n"
    ).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


if __name__ == "__main__":
    import json

    print(json.dumps(ExportDocument.model_json_schema(), indent=2, sort_keys=True))
