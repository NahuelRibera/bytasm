"""Separate canonical Ghidra report contract; historical report schemas stay immutable."""

import html
import json
from typing import Any

from bytasm.reports.ghidra_dossier import dossier_body


def canonical_json(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def html_export(document: dict[str, Any]) -> bytes:
    """Render only canonical JSON content as escaped, self-contained static HTML."""
    canonical = canonical_json(document).decode("ascii")
    overview = document["overview"]
    sections = []
    for title, key in (
        ("Verified observations", "observations"),
        ("Evidence-based hypotheses", "hypotheses"),
        ("Analyst notes", "analyst_notes"),
        ("Recommended next steps", "recommendations"),
        ("Unknowns and limits", "limitations"),
    ):
        values = overview["summary"][key]
        items = "".join(
            "<li>" + html.escape(value["text"] if isinstance(value, dict) else value) + "</li>"
            for value in values
        )
        sections.append(
            f"<section><h2>{title}</h2>"
            + (f"<ul>{items}</ul>" if items else "<p>None recorded in this report.</p>")
            + "</section>"
        )
    body = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        "<title>Bytasm Ghidra static review</title>"
        "<style>body{font:16px system-ui;max-width:70rem;margin:2rem auto;padding:0 1rem;"
        "color:#171717;background:#fff;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "li{margin:.5rem 0}h2{margin-top:2rem}dd,td,code{overflow-wrap:anywhere}"
        "dd{margin:0 0 .5rem}table{border-collapse:collapse;width:100%;table-layout:fixed}"
        "th,td{text-align:left;border-bottom:1px solid #bbb;padding:.5rem;vertical-align:top}"
        "article{border-top:1px solid #bbb;margin-top:2rem;padding-top:1rem}"
        "@media print{body{margin:0}h2,h3,h4{break-after:avoid}}</style>"
        "<main><h1>Ghidra static review</h1><p>Run "
        + html.escape(overview["run_id"])
        + " · Version "
        + html.escape(overview["version_id"])
        + "</p>"
        + "".join(sections)
        + (dossier_body(document) if document["schema_version"] == "bytasm-ghidra-report-2" else "")
        + "<details><summary>Canonical report and function evidence</summary><pre>"
        + html.escape(canonical)
        + "</pre></details></main></html>"
    )
    return body.encode("utf-8")
