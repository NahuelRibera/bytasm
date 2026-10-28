"""The strings step of an analysis run: run the extractor child, validate its result.

The child (bytasm.adapters.strings_extract) re-hashes the input before
reading it. Its result is untrusted: besides the schema, every string must lie
inside the file, be exactly the bytes at its offset decoded in its encoding,
cover a run of printable characters of the reported length, and appear in
(offset, encoding) order; the counts must add up. Any mismatch rejects the
whole result (`invalid_output`) and nothing from it is stored.

Strings are observations, stored as `string_occurrence` rows; they never
become findings on their own. Their values are never logged.
"""

import re
from typing import Any, Final

from pydantic import ValidationError

from bytasm.adapters.strings_extract import ADAPTER_VERSION, TOOL_VERSION, decode, patterns
from bytasm.adapters.strings_result import (
    ENCODINGS,
    MAX_CHARS,
    MAX_STRINGS,
    MIN_LENGTH,
    StringsAdapterResult,
)
from bytasm.db.models import Base, StringOccurrence
from bytasm.jobs.steps import ScanDeps, StepInput, StepOutcome
from bytasm.runner.limits import MAX_INPUT_BYTES, ParserLimits
from bytasm.runner.supervisor import INPUT_NAME, run_child

TOOL: Final = "strings"


def strings_argv(command: list[str], limits: ParserLimits, sample_sha256: str) -> list[str]:
    return [
        *command,
        "--input",
        INPUT_NAME,
        "--expected-sha256",
        sample_sha256,
        "--out",
        "result.json",
        "--max-input-bytes",
        str(MAX_INPUT_BYTES),
        "--min-length",
        str(MIN_LENGTH),
        "--max-strings",
        str(MAX_STRINGS),
        "--max-chars",
        str(MAX_CHARS),
        "--rlimit-as",
        str(limits.address_space_bytes),
        "--rlimit-cpu",
        str(limits.cpu_seconds),
        "--rlimit-fsize",
        str(limits.file_size_bytes),
    ]


def parse_strings_result(raw: bytes, sample_sha256: str) -> StringsAdapterResult | None:
    try:
        result = StringsAdapterResult.model_validate_json(raw)
    except ValidationError:
        return None
    if result.input.sha256 != sample_sha256:
        return None
    return result


def strings_are_consistent(result: StringsAdapterResult, data: bytes) -> bool:
    """Every string is what the file holds at its offset, in a stable order."""
    if result.input.size_bytes != len(data):
        return False
    if set(result.found_by_encoding) != set(ENCODINGS):
        return False
    if sum(result.found_by_encoding.values()) != result.total_found:
        return False
    if len(result.strings) > result.params.max_strings:
        return False
    if result.truncated != (result.total_found > len(result.strings)):
        return False
    full_run: dict[str, re.Pattern[bytes]] = patterns(MIN_LENGTH)
    previous: tuple[int, int] | None = None
    for item in result.strings:
        key = (item.offset, ENCODINGS.index(item.encoding))
        if previous is not None and key <= previous:
            return False
        previous = key
        width = 1 if item.encoding == "ascii" else 2
        if item.byte_length != item.length_chars * width:
            return False
        end = item.offset + item.byte_length
        if end > len(data) or full_run[item.encoding].fullmatch(data, item.offset, end) is None:
            return False
        kept = min(item.length_chars, result.params.max_chars)
        if len(item.value) != kept or item.value_truncated != (kept < item.length_chars):
            return False
        if decode(data[item.offset : item.offset + kept * width], item.encoding) != item.value:
            return False
    return True


def _invocation(result: StringsAdapterResult | None, exit_code: int | None) -> dict[str, Any]:
    return {
        "tool_name": TOOL,
        "tool_version": result.tool_version if result else TOOL_VERSION,
        "adapter_name": "strings_extract",
        "adapter_version": result.adapter_version if result else ADAPTER_VERSION,
        "args": {
            "encodings": list(ENCODINGS),
            "min_length": MIN_LENGTH,
            "max_strings": MAX_STRINGS,
            "max_chars": MAX_CHARS,
            "limits": result.resource_limits.model_dump() if result else None,
        },
        "exit_code": exit_code,
        "warnings": [],
        "summary": (
            {
                "total_found": result.total_found,
                "found_by_encoding": dict(result.found_by_encoding),
                "stored": len(result.strings),
                "truncated": result.truncated,
            }
            if result
            else None
        ),
    }


def _rows(result: StringsAdapterResult) -> Any:
    def build(invocation_id: str) -> list[Base]:
        return [
            StringOccurrence(
                invocation_id=invocation_id,
                file_offset=item.offset,
                encoding=item.encoding,
                length_chars=item.length_chars,
                byte_length=item.byte_length,
                value=item.value,
                value_truncated=item.value_truncated,
            )
            for item in result.strings
        ]

    return build


async def run_strings_step(deps: ScanDeps, step: StepInput) -> StepOutcome:
    outcome = await run_child(
        strings_argv(deps.strings_command, deps.limits, step.sample_sha256),
        step.workdir,
        deps.limits,
        parse_result=lambda raw: parse_strings_result(raw, step.sample_sha256),
        should_cancel=step.should_stop,
    )
    result = outcome.result
    fields = _invocation(result, outcome.exit_code)
    fields["duration_ms"] = outcome.duration_ms
    if outcome.status == "cancelled":
        return StepOutcome("cancelled", "cancel_requested", fields)
    if outcome.status == "timed_out":
        return StepOutcome("timed_out", "timeout", fields)
    if outcome.status != "succeeded" or result is None or outcome.result_bytes is None:
        # "rejected" (exit 2 + a reason code) is not part of this adapter's contract.
        reason = outcome.reason if outcome.status == "failed" else "nonzero_exit"
        return StepOutcome("failed", reason, fields)
    if not strings_are_consistent(result, step.data):
        fields["summary"] = None
        return StepOutcome("failed", "invalid_output", fields)
    return StepOutcome(
        "succeeded",
        None,
        fields,
        raw_output=outcome.result_bytes,
        rows=_rows(result),
        log_fields={
            "strings_found": result.total_found,
            "strings_stored": len(result.strings),
            "duration_ms": outcome.duration_ms,
        },
    )
