"""Error responses: one fixed message per reason code (RFC 9457 "problem details" shape).

Messages come only from this table (plus Bytasm's own format-identification
text). Nothing an adapter child printed is ever included.
"""

from typing import Any, Final

from fastapi.responses import JSONResponse

_PROBLEMS: Final[dict[str, tuple[int, str, str]]] = {
    # Request guards
    "host_not_allowed": (
        400,
        "Host not allowed",
        "Bytasm only answers requests addressed to 127.0.0.1, localhost or [::1] on its own port. "
        "Open it at http://127.0.0.1:<port>/ (8000 by default).",
    ),
    "origin_not_allowed": (
        403,
        "Cross-origin request refused",
        "Bytasm does not accept requests from other web pages. Use the Bytasm UI itself.",
    ),
    "missing_request_header": (
        403,
        "Missing request header",
        "State-changing requests must include the X-Bytasm-Request: 1 header.",
    ),
    "not_loopback": (403, "Not a loopback connection", "Bytasm only serves loopback connections."),
    # General
    "not_found": (404, "Not found", "Nothing exists at this address."),
    "invalid_request": (422, "Invalid request", "The request body is missing or invalid."),
    "internal_error": (
        500,
        "Internal error",
        "Something went wrong inside Bytasm. Try again; if it happens again, find this "
        "request ID in the server log.",
    ),
    # Import
    "invalid_import_metadata": (
        422,
        "Invalid import details",
        "The import details (X-Bytasm-Import header) are missing or invalid. "
        "No file bytes were read.",
    ),
    "unsupported_media_type": (
        415,
        "Unsupported upload type",
        "Send the file as the raw request body with Content-Type: application/octet-stream.",
    ),
    "sample_exists": (
        409,
        "Sample name already used",
        "This project already has a sample with that name. Choose it to add a new version.",
    ),
    "parser_busy": (
        503,
        "Busy",
        "Another file is being validated. Try again in a few seconds.",
    ),
    "upload_too_large": (
        413,
        "File too large",
        "The file is larger than the 64 MiB limit. It was not imported.",
    ),
    "upload_incomplete": (
        400,
        "Upload incomplete",
        "The upload did not complete. Nothing was imported. Try again.",
    ),
    "empty_file": (422, "Empty file", "The file is empty. It was not imported."),
    "unsupported_format": (
        415,
        "Unsupported file format",
        "Only PE and ELF files are supported. The file was not imported.",
    ),
    "malformed_input": (
        422,
        "Malformed file",
        "The file's PE or ELF headers are malformed or truncated. It was not imported.",
    ),
    "input_policy": (
        403,
        "Refused by the input policy",
        "This version only accepts Bytasm's test fixtures. The file was not parsed or stored.",
    ),
    "duplicate_version": (
        409,
        "Already imported",
        "This exact file is already a version of this sample. Nothing new was imported.",
    ),
    "parse_failed": (
        422,
        "Could not parse",
        "LIEF could not parse the file. It was not imported.",
    ),
    "parse_timeout": (
        422,
        "Parsing timed out",
        "The file could not be parsed within 30 s. It was not imported.",
    ),
    "adapter_failed": (
        422,
        "Could not parse",
        "The metadata parser process failed on this file. It was not imported.",
    ),
    # Analysis runs and rules (v0.2)
    "provider_unavailable": (
        503,
        "Provider unavailable",
        "The Ghidra provider has not passed its real health check in an available worker. "
        "Open Tools for setup and recovery instructions. Nothing was queued.",
    ),
    "run_active": (
        409,
        "A run is already in progress",
        "This sample version already has a queued or running analysis. Wait for it to finish "
        "or cancel it before starting another.",
    ),
    "run_finished": (
        409,
        "Run already finished",
        "This run has already finished, so there is nothing to cancel.",
    ),
    "rules_unavailable": (
        500,
        "Rule set unavailable",
        "Bytasm could not read its bundled YARA-X rule set (rules/yara). Nothing was started. "
        "Check that the rule files are intact; the server log names the problem.",
    ),
    "rule_check_failed": (
        500,
        "Rule check failed",
        "The YARA-X process that compiles the rules failed. Try again; if it happens again, "
        "find this request ID in the server log.",
    ),
    "annotation_stale": (
        409,
        "Annotation changed",
        "This annotation has a newer revision. Reload it before saving your edit.",
    ),
    # Stored data
    "integrity_error": (
        409,
        "Stored file changed",
        "A stored file no longer matches its recorded SHA-256, so it was changed outside "
        "Bytasm. Nothing was exported. Re-import the original file into a new sample.",
    ),
}


def problem_status(code: str) -> int:
    return _PROBLEMS.get(code, _PROBLEMS["internal_error"])[0]


def problem(
    code: str,
    *,
    detail: str | None = None,
    request_id: str | None = None,
    extra: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    status, title, default_detail = _PROBLEMS.get(code, _PROBLEMS["internal_error"])
    body: dict[str, Any] = {
        "type": f"urn:bytasm:error:{code}",
        "code": code,
        "title": title,
        "status": status,
        "detail": detail or default_detail,
    }
    if request_id:
        body["request_id"] = request_id
    if extra:
        body.update(extra)
    return JSONResponse(
        body, status_code=status, media_type="application/problem+json", headers=headers
    )
