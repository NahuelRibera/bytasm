"""Receive a raw request body into a file, with a hard limit (blueprint 5.4.1 step 4).

This reads the ASGI `receive` channel directly instead of using form parsing
or `Request.stream()`, so Bytasm itself decides what a complete upload is:

- Only a body consumed to the final `http.request` message with
  `more_body: False` counts as complete. An `http.disconnect` (or anything
  else) before that means the upload is rejected and nothing is kept.
- Counting and hashing happen on every chunk. Once the count passes the limit,
  reading stops: the rest of the body is never read.
- The first bytes are checked early, so an archive or other non-PE/ELF file
  is refused before most of it is received.
- When `Content-Length` was sent, the received count must equal it. That is an
  additional consistency check, not proof of completion.
"""

import hashlib
import os
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bytasm.errors import InspectError
from bytasm.intake.identify import SIGNATURE_BYTES, check_signature

Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]


class UploadError(Exception):
    """The upload was refused or did not complete. `code` is a fixed reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ReceivedUpload:
    sha256: str
    size_bytes: int


async def receive_upload(
    receive: Receive, destination: Path, max_bytes: int, content_length: int | None
) -> ReceivedUpload:
    digest = hashlib.sha256()
    size = 0
    prefix = b""
    signature_checked = False
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        while True:
            message = await receive()
            if message["type"] != "http.request":
                # http.disconnect, or anything unexpected: not a complete upload.
                raise UploadError("upload_incomplete")
            chunk: bytes = message.get("body", b"")
            if chunk:
                size += len(chunk)
                if size > max_bytes:
                    raise UploadError("upload_too_large")
                if not signature_checked:
                    prefix = (prefix + chunk)[:SIGNATURE_BYTES]
                    if len(prefix) >= SIGNATURE_BYTES:
                        _check(prefix)
                        signature_checked = True
                digest.update(chunk)
                handle.write(chunk)
            if not message.get("more_body", False):
                break  # the ASGI completion signal

    if size == 0:
        raise UploadError("empty_file")
    if not signature_checked:
        _check(prefix)
    if content_length is not None and size != content_length:
        raise UploadError("upload_incomplete")
    return ReceivedUpload(sha256=digest.hexdigest(), size_bytes=size)


def _check(prefix: bytes) -> None:
    try:
        check_signature(prefix)
    except InspectError as error:
        raise UploadError("unsupported_format", error.message) from error
