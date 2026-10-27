"""The `X-Bytasm-Import` request header: import details sent before the file.

It is a base64url-encoded JSON document of at most 8 KiB. It is validated
completely before a single byte of the request body is read (blueprint 5.4.1
step 1). Unknown fields are refused, so a request cannot carry options such
as an input-policy override: there is no such field.
"""

import base64
import binascii
import json
from typing import Annotated, Final, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

HEADER_NAME: Final = "x-bytasm-import"
MAX_HEADER_BYTES: Final = 8 * 1024

# Only basis offered before isolation gate I1 (blueprint 2 J2).
BASIS_OWNED_OR_BUILT: Final = "owned_or_built"

Text200 = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorizationIn(_Strict):
    basis: Literal["owned_or_built"]
    statement: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)
    ]


class ImportMetadata(_Strict):
    sample_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None
    sample_name: Text200 | None = None
    version_label: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=100)] | None
    ) = None
    # As uploaded; untrusted, display only. Never used for any filesystem path.
    declared_filename: Annotated[str, Field(max_length=255)] | None = None
    authorization: AuthorizationIn

    @model_validator(mode="after")
    def _one_sample_target(self) -> Self:
        if (self.sample_id is None) == (self.sample_name is None):
            raise ValueError("give exactly one of sample_id or sample_name")
        return self


class InvalidImportMetadata(Exception):
    pass


def parse_import_header(value: str | None) -> ImportMetadata:
    if not value:
        raise InvalidImportMetadata("missing X-Bytasm-Import header")
    if len(value) > MAX_HEADER_BYTES:
        raise InvalidImportMetadata("X-Bytasm-Import header is larger than 8 KiB")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        document = json.loads(raw.decode("utf-8"))
        return ImportMetadata.model_validate(document)
    except (binascii.Error, ValueError, UnicodeDecodeError, ValidationError) as exc:
        raise InvalidImportMetadata("X-Bytasm-Import header is not valid") from exc


def encode_import_header(document: dict[str, object]) -> str:
    """The client-side encoding (used by tests; the UI does the same in TypeScript)."""
    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
