"""Fixed, user-facing explanations for runs and their steps.

Like the import problem table (bytasm.api.problems), nothing a child process
printed is ever shown: the UI and the report get these sentences, built from
fixed codes and the step's tool name.
"""

from collections.abc import Sequence
from typing import Final

TOOL_LABELS: Final[dict[str, str]] = {
    "strings": "The strings extractor",
    "yara-x": "YARA-X",
    "capa": "capa",
    "ghidra": "Ghidra",
}
SHORT_LABELS: Final[dict[str, str]] = {
    "strings": "strings",
    "yara-x": "YARA-X",
    "capa": "capa",
    "ghidra": "Ghidra",
}

# Why the run stopped before a tool saw the sample (checked before every step).
ADMISSION_MESSAGES: Final[dict[str, str]] = {
    "input_policy": (
        "This sample is not admitted by the current input policy, so no analysis tool saw it."
    ),
    "sample_integrity": (
        "The stored sample is missing or no longer matches its recorded SHA-256, so no "
        "analysis tool saw it. Re-import the original file into a new sample."
    ),
}

STEP_MESSAGES: Final[dict[str, str]] = {
    "unsupported_format": "{tool} does not support this file format or architecture in Bytasm.",
    "tool_unavailable": "The pinned {tool} tool is unavailable.",
    "timeout": "{tool} did not finish within the time limit.",
    "not_configured": "Ghidra is not configured in the analysis worker.",
    "installation_invalid": "The configured Ghidra installation is invalid or unavailable.",
    "unsupported_version": "The configured Ghidra version is not supported by this profile.",
    "java_missing": "The configured Ghidra JDK is missing or invalid.",
    "java_incompatible": "The configured Ghidra JDK is incompatible.",
    "unsupported_host": "This host is not supported by the Ghidra provider.",
    "resource_constraint": "The Ghidra worker lacks required resource limits.",
    "startup_failed": "The Ghidra Headless launcher could not start.",
    "profile_integrity": "The queued profile no longer matches the reviewed extraction script.",
    "isolation_unavailable": "The offline worker or required resource controls are unavailable.",
    "rules_invalid": (
        "Bytasm's rule set did not compile with the installed YARA-X. Open Rules and run "
        "Validate to see the compiler errors."
    ),
    "rules_integrity": (
        "The stored copy of the rule set is missing or no longer matches its SHA-256, so the "
        "scan did not start."
    ),
    "killed_by_signal": "{tool} was stopped by a resource limit or a signal.",
    "nonzero_exit": "The {tool} process failed.",
    "invalid_output": "{tool} returned output that Bytasm could not validate.",
    "output_overflow": "{tool} wrote more output than allowed.",
    "orphan_processes": "{tool} left other processes running.",
    "output_not_closed": "{tool} did not close its output.",
    "cancel_requested": "{tool} was stopped because the run was cancelled.",
    "worker_interrupted": "{tool} was stopped because the analysis worker stopped.",
    "internal_error": "Something went wrong inside Bytasm while recording this step.",
}
_NOT_KEPT: Final = " No results from this step were kept."


def tool_label(tool: str) -> str:
    return TOOL_LABELS.get(tool, tool)


def short_label(tool: str) -> str:
    return SHORT_LABELS.get(tool, tool)


def step_message(tool: str, status: str, reason: str | None) -> str | None:
    """One sentence for a step that did not succeed (None for a succeeded or pending step)."""
    if status in ("succeeded", "queued", "running"):
        return None
    if status == "skipped":
        return _not_run(tool, reason)
    template = STEP_MESSAGES.get(reason or "", STEP_MESSAGES["internal_error"])
    return template.format(tool=tool_label(tool)) + _NOT_KEPT


def _not_run(tool: str, reason: str | None) -> str:
    label = short_label(tool)
    if reason in ADMISSION_MESSAGES:
        return f"Not run ({label}): the sample did not pass its admission checks."
    if reason == "cancelled":
        return f"Not run ({label}): the run was cancelled first."
    if reason == "worker_interrupted":
        return f"Not run ({label}): the analysis worker stopped first."
    return f"Not run ({label}): an earlier problem ended the run."


def _join(labels: Sequence[str]) -> str:
    if len(labels) <= 1:
        return "".join(labels)
    return ", ".join(labels[:-1]) + " and " + labels[-1]


def run_message(status: str, reason: str | None, steps: Sequence[tuple[str, str]]) -> str | None:
    """Plain-language summary of a finished run, from (tool, step status) pairs.

    The `partial` text is the banner blueprint 7.3 asks for on the run, the
    findings, and the report.
    """
    done = [short_label(tool) for tool, step in steps if step == "succeeded"]
    missing = [(tool, step) for tool, step in steps if step != "succeeded"]
    why = ADMISSION_MESSAGES.get(reason or "")
    if why is None and reason is not None:
        failed_tool = next((t for t, s in missing if s != "skipped"), "")
        why = STEP_MESSAGES.get(reason, STEP_MESSAGES["internal_error"]).format(
            tool=tool_label(failed_tool) if failed_tool else "A step"
        )
    if status == "failed":
        return (why + " " if why else "") + (
            "No step kept any results, so this run says nothing about the file's strings or "
            "whether the patterns occur."
        )
    if status == "partial":
        text = f"Partial result: {_join([short_label(t) for t, _ in missing])} did not complete."
        if why:
            text += f" {why}"
        text += f" Results from {_join(done)} are complete and kept."
        if any(tool == "yara-x" for tool, _ in missing):
            text += (
                (
                    " This run has no YARA-X findings: absence of a match does not mean "
                    "the pattern is absent."
                )
                if "capa" in done
                else (
                    " This run has no findings: absence of a YARA-X match does not mean the "
                    "pattern is absent."
                )
            )
        if any(tool == "strings" for tool, _ in missing):
            text += " This run recorded no strings."
        return text
    if status == "cancelled":
        if done:
            return (
                f"Cancelled. {_join(done)} finished before the cancel and its results are "
                "kept; steps that had not finished kept nothing."
            )
        return "Cancelled before any step finished. Nothing was kept."
    return None
