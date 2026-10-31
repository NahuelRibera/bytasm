"""Bounded discovery over an immutable, verified inventory; no tool execution."""

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from bytasm.ghidra_protocol import Function, GhidraResult


class InventoryQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    q: str = Field(default="", max_length=128)
    field: Literal["all", "name", "namespace", "address"] = "all"
    exact: bool = False
    external: bool | None = None
    pseudocode: Literal["available", "not_selected", "failed"] | None = None
    has_calls: bool | None = None


@dataclass(frozen=True)
class InventoryPage:
    items: list[tuple[int, Function]]
    matched: int
    offset: int
    next_cursor: str | None


def page_inventory(
    result: GhidraResult,
    scope: str,
    query: InventoryQuery,
    offset: int,
    limit: int,
    cursor: str | None,
) -> InventoryPage:
    if not 0 <= offset <= 1024 or not 1 <= limit <= 100:
        raise ValueError("Invalid page bounds")
    # Scope includes exact project/version/run/invocation/output identity. The
    # checksum detects mismatched cursors, not authorization: all reads revalidate
    # the run and its output. No server secret or personal data enters the token.
    binding = hashlib.sha256(
        json.dumps([scope, query.model_dump(), limit], sort_keys=True).encode()
    ).hexdigest()
    if cursor is not None:
        try:
            raw = base64.b64decode(cursor, altchars=b"-_", validate=True)
            position, supplied = json.loads(raw)
            if type(position) is not int or not 0 <= position <= 1024 or supplied != binding:
                raise ValueError("Invalid cursor")
            if offset != 0:
                raise ValueError("Cursor cannot be combined with offset")
            offset = position
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ValueError("Invalid cursor") from exc
    text = query.q.casefold()

    def matches(fn: Function) -> bool:
        fields = {
            "name": fn.name,
            "namespace": fn.namespace,
            "address": f"{fn.entry.space}:{fn.entry.address}",
        }
        values = list(fields.values()) if query.field == "all" else [fields[query.field]]
        if query.field in ("all", "address"):
            values.append(fn.entry.address)
        found = not text or any(
            text == value.casefold() if query.exact else text in value.casefold()
            for value in values
        )
        return (
            found
            and (query.external is None or fn.external == query.external)
            and (query.pseudocode is None or fn.pseudocode_status == query.pseudocode)
            and (query.has_calls is None or bool(fn.calls) == query.has_calls)
        )

    selected = sorted(
        ((i, fn) for i, fn in enumerate(result.functions) if matches(fn)),
        key=lambda item: (item[1].entry.space, item[1].entry.address, item[0]),
    )
    end = offset + limit
    token = (
        base64.urlsafe_b64encode(json.dumps([end, binding]).encode()).decode()
        if end < len(selected)
        else None
    )
    return InventoryPage(selected[offset:end], len(selected), offset, token)
