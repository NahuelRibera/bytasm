"""Controlled errors for `bytasm inspect` and the import API.

Every expected failure is an `InspectError` with a stable reason `code`, so the
CLI can print one clear JSON error instead of a traceback, and the API can map
it to an HTTP status. Messages about the adapter child come from the fixed
table below: text the child printed is never passed on.
"""

from typing import Final

# Exit code for "the input was refused" (same meaning as in the adapter
# contract, blueprint section 5.6).
EXIT_REJECTED: Final = 2
# Exit code for problems that are not about the input's bytes (missing file,
# unreadable manifest).
EXIT_OPERATIONAL: Final = 1

# Reason codes: input refused.
UNKNOWN_HASH: Final = "unknown_hash"
EMPTY_FILE: Final = "empty_file"
FILE_TOO_LARGE: Final = "file_too_large"
UNSUPPORTED_FORMAT: Final = "unsupported_format"
MALFORMED_INPUT: Final = "malformed_input"
PARSE_FAILED: Final = "parse_failed"
# The adapter child did not finish in time, or failed (crash, limit, bad output).
PARSE_TIMEOUT: Final = "parse_timeout"
ADAPTER_FAILED: Final = "adapter_failed"

# Reason codes: operational problems.
FILE_NOT_FOUND: Final = "file_not_found"
MANIFEST_ERROR: Final = "manifest_error"

_OPERATIONAL_CODES: Final = frozenset({FILE_NOT_FOUND, MANIFEST_ERROR})


class InspectError(Exception):
    """An expected, explainable failure. `code` is one of the constants above."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    @property
    def exit_code(self) -> int:
        return EXIT_OPERATIONAL if self.code in _OPERATIONAL_CODES else EXIT_REJECTED


# Fixed messages for adapter rejections (exit code 2 + reason code).
_REJECTION_MESSAGES: Final = {
    EMPTY_FILE: "The file is empty.",
    FILE_TOO_LARGE: "The file is larger than the size limit.",
    UNSUPPORTED_FORMAT: "The file is not a supported PE or ELF file.",
    MALFORMED_INPUT: "The file's PE or ELF headers are malformed or truncated.",
    PARSE_FAILED: "LIEF could not parse the file.",
}


def outcome_error(status: str, reason: str) -> InspectError:
    """Turn a non-successful adapter outcome into an InspectError with a fixed message."""
    if status == "rejected" and reason in _REJECTION_MESSAGES:
        return InspectError(reason, _REJECTION_MESSAGES[reason])
    if status == "timed_out":
        return InspectError(PARSE_TIMEOUT, "The file could not be parsed within the time limit.")
    return InspectError(
        ADAPTER_FAILED,
        f"The metadata adapter process failed ({reason}). No metadata was produced.",
    )
