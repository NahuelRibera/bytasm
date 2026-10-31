"""Readable static report-2 body, rendered from validated canonical JSON only."""

import html
from typing import Any


def _text(value: object) -> str:
    return html.escape(str(value))


def _address(value: dict[str, str]) -> str:
    return _text(value["space"] + ":" + value["address"])


def dossier_body(document: dict[str, Any]) -> str:
    overview = document["overview"]
    analysis = document["analysis"]
    functions = analysis["functions"]
    result = [
        "<section><h2>Analysis scope and provenance</h2><dl>",
        "<dt>Sample SHA-256</dt><dd><code>" + _text(overview["input_sha256"]) + "</code></dd>",
        "<dt>Ghidra</dt><dd>" + _text(analysis["ghidra_version"]) + "</dd>",
        "<dt>Language</dt><dd>" + _text(analysis["language_id"]) + "</dd>",
        "<dt>Profile SHA-256</dt><dd><code>" + _text(analysis["profile_sha256"]) + "</code></dd>",
        "<dt>Script SHA-256</dt><dd><code>" + _text(analysis["script_sha256"]) + "</code></dd>",
        "<dt>Invocation</dt><dd>" + _text(overview["invocation_id"]) + "</dd>",
        "</dl><p>"
        + _text(len(functions))
        + " retained inventory entries of "
        + _text(analysis["function_count"])
        + " identified functions. "
        + ("Inventory capped. " if analysis["functions_truncated"] else "")
        + "These counts do not measure whole-program understanding or safety.</p>",
        "<p>Pseudocode is reconstruction, not original source. Body size counts addresses, "
        "possibly discontiguous. Static calls are references, "
        "not observed execution.</p></section>",
    ]
    if overview.get("source_run_id"):
        result.append(
            "<p>Selected inspection from source run <code>"
            + _text(overview["source_run_id"])
            + "</code>; source output SHA-256 "
            + "<code>"
            + _text(overview["source_output_sha256"])
            + "</code>.</p>"
        )
    result.append("<section><h2>Selected function dossiers</h2>")
    detailed = 0
    for index, fn in enumerate(functions):
        if fn["pseudocode_status"] == "not_selected":
            continue
        detailed += 1
        result.append(
            f'<article id="dossier-{index}"><h3>'
            + _text(fn["name"])
            + "</h3><p>"
            + _address(fn["entry"])
            + " · Body: "
            + ("Unavailable" if fn["body_size"] is None else _text(fn["body_size"]) + " addresses")
            + " · "
            + ("External" if fn["external"] else "Internal")
            + "</p><p>Canonical tool pointer: <code>/functions/"
            + str(index)
            + "</code>. Pseudocode status: "
            + _text(fn["pseudocode_status"])
            + ".</p><h4>Ghidra pseudocode</h4>"
        )
        result.append("<p>Output capped.</p>" if fn["pseudocode_truncated"] else "")
        result.append(
            "<p>No pseudocode was retained.</p>"
            if fn["pseudocode"] is None
            else "<pre>" + _text(fn["pseudocode"]) + "</pre>"
        )
        result.append("<h4>Assembly and instruction bytes</h4>")
        if fn["instructions_truncated"]:
            result.append("<p>Instruction window capped; this is not a complete listing.</p>")
        if fn["instructions"]:
            result.append(
                "<table><caption>Retained instructions</caption><thead><tr>"
                '<th scope="col">Address</th><th scope="col">Bytes (hex)</th>'
                '<th scope="col">Instruction</th></tr></thead><tbody>'
            )
            for ins in fn["instructions"]:
                result.append(
                    "<tr><td>"
                    + _address(ins["address"])
                    + "</td><td>"
                    + _text(ins["bytes_hex"])
                    + (" (capped)" if ins["bytes_truncated"] else "")
                    + "</td><td>"
                    + _text(ins["text"])
                    + (" (capped)" if ins["text_truncated"] else "")
                    + "</td></tr>"
                )
            result.append("</tbody></table>")
        else:
            result.append("<p>No instruction listing was retained.</p>")
        result.append("<h4>Direct static call references</h4>")
        if fn["calls_truncated"]:
            result.append("<p>Call window capped; additional references may exist.</p>")
        if fn["calls"]:
            result.append("<ul>")
            for call_index, call in enumerate(fn["calls"]):
                result.append(
                    "<li>"
                    + _address(call["source"])
                    + " → "
                    + _address(call["target"])
                    + " · <code>/functions/"
                    + str(index)
                    + "/calls/"
                    + str(call_index)
                    + "</code></li>"
                )
            result.append("</ul>")
        else:
            result.append("<p>No direct calls were retained; this does not establish absence.</p>")
        result.append("</article>")
    if not detailed:
        result.append("<p>No selected function detail records are available.</p>")
    result.append(
        "</section><details><summary>Function inventory (retained entries)</summary>"
        '<table><caption>Function inventory</caption><thead><tr><th scope="col">Record</th>'
        '<th scope="col">Function</th><th scope="col">Entry address</th>'
        '<th scope="col">Pseudocode status</th></tr></thead><tbody>'
    )
    for index, fn in enumerate(functions):
        label = _text(fn["namespace"] + "::" + fn["name"])
        if fn["name_truncated"] or fn["namespace_truncated"]:
            label += " (name capped)"
        if fn["pseudocode_status"] != "not_selected":
            label = f'<a href="#dossier-{index}">' + label + "</a>"
        result.append(
            "<tr><td>"
            + str(index)
            + "</td><td>"
            + label
            + "</td><td>"
            + _address(fn["entry"])
            + "</td><td>"
            + _text(fn["pseudocode_status"])
            + "</td></tr>"
        )
    result.append(
        "</tbody></table></details><p>Review before sharing: symbols, paths and "
        "pseudocode can be sensitive. Unsupported non-call references and analyst "
        "annotations are not included.</p>"
    )
    return "".join(result)
