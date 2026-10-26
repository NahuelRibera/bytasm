"""Controlled errors for `bytasm inspect`.

Every expected failure is an `InspectError` with a stable reason `code`, so the
CLI can print one clear JSON error instead of a traceback.
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
