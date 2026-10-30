"""Conservative text-shape categories and exact raw-section containment."""

import re
from typing import Any, Literal

StringCategory = Literal["url_like", "path_like", "other"]
StringSort = Literal["offset", "length", "value", "category"]


def category_of(value: str) -> StringCategory:
    if re.match(r"^https?://[^\s]+", value, re.IGNORECASE):
        return "url_like"
    if value.startswith(("/", "\\\\", "./", "../")) or re.match(r"^[A-Za-z]:[\\/]", value):
        return "path_like"
    return "other"


def containing_section(
    offset: int, size: int, sections: list[dict[str, Any]], file_size: int
) -> dict[str, Any] | None:
    matches = [
        section
        for section in sections
        if 0 <= section["file_offset"] <= offset
        and offset + size <= section["file_offset"] + section["raw_size"] <= file_size
    ]
    return {"index": matches[0]["index"], "name": matches[0]["name"]} if len(matches) == 1 else None
