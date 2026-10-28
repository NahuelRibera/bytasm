"""Schema of the strings adapter's `result.json`, validated by the parent.

Same rules as the other adapter schemas: the parent size-caps the file before
reading it and validates it against these models; unknown fields, wrong
types, or anything over a cap make the whole result invalid, and nothing from
it is used. The parent then checks every string against the admitted bytes
(bytasm.jobs.strings_step).

What counts as a string (blueprint 3.1: "ASCII and UTF-16LE strings with
offsets, min length 6"):

- `ascii`: a run of at least MIN_LENGTH bytes, each a printable ASCII
  character (0x20-0x7E) or a tab.
- `utf-16le`: a run of at least MIN_LENGTH 16-bit little-endian code units,
  each a printable ASCII character or a tab followed by a zero byte. This is
  the classic `strings -e l` definition; UTF-16 text outside ASCII is not
  extracted.

Newlines and other control bytes end a run, so every value is one line of
printable ASCII. Runs are found at any byte alignment and do not overlap
within one encoding. The two encodings are searched independently, so the
same bytes can belong to an ASCII run and a UTF-16LE run (for example an
ASCII run's last character followed by a zero byte).
"""

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from bytasm.adapters.result import InputResult, ResourceLimitsResult

ADAPTER_NAME: Final = "strings_extract"
ENCODINGS: Final = ("ascii", "utf-16le")
# Blueprint 3.1.
MIN_LENGTH: Final = 6
# At most this many strings are kept per run (the first ones by offset). The
# total number found is still counted and reported.
MAX_STRINGS: Final = 5000
# A kept value holds at most this many characters; its full length is reported.
MAX_CHARS: Final = 256

Count = Annotated[StrictInt, Field(ge=0)]
Encoding = Literal["ascii", "utf-16le"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StringItem(_Strict):
    offset: Count
    encoding: Encoding
    # Characters in the whole run, and the bytes it occupies in the file.
    length_chars: Annotated[StrictInt, Field(ge=MIN_LENGTH)]
    byte_length: Annotated[StrictInt, Field(ge=MIN_LENGTH)]
    # The first MAX_CHARS characters of the run.
    value: Annotated[StrictStr, Field(min_length=1, max_length=MAX_CHARS)]
    value_truncated: StrictBool


class StringsParams(_Strict):
    encodings: tuple[Literal["ascii"], Literal["utf-16le"]]
    min_length: Literal[6]
    max_strings: Annotated[StrictInt, Field(ge=1, le=MAX_STRINGS)]
    max_chars: Annotated[StrictInt, Field(ge=1, le=MAX_CHARS)]


class StringsAdapterResult(_Strict):
    schema_version: Literal[1]
    adapter: Literal["strings_extract"]
    adapter_version: Annotated[StrictStr, Field(max_length=32)]
    tool: Literal["strings"]
    tool_version: Annotated[StrictStr, Field(max_length=32)]
    input: InputResult
    params: StringsParams
    # Every run found, before the MAX_STRINGS cap.
    total_found: Count
    found_by_encoding: dict[Encoding, Count]
    truncated: StrictBool
    # Sorted by (offset, encoding); at most params.max_strings items.
    strings: Annotated[list[StringItem], Field(max_length=MAX_STRINGS)]
    resource_limits: ResourceLimitsResult
