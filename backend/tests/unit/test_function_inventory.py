"""Stored inventory discovery never invokes a parser."""

import pytest
from test_ghidra_provider import document

from bytasm.function_inventory import InventoryQuery, page_inventory
from bytasm.ghidra_protocol import GhidraResult


def inventory() -> GhidraResult:
    value = document()
    first = value["functions"][0]
    value["functions"] = [
        {
            **first,
            "name": "beta",
            "namespace": "Lab",
            "entry": {"space": "ram", "address": "00100002"},
        },
        {
            **first,
            "name": "alpha",
            "namespace": "Global",
            "entry": {"space": "ram", "address": "00100001"},
        },
    ]
    value["function_count"] = 3
    value["functions_truncated"] = True
    return GhidraResult.model_validate(value)


def test_search_exact_fields_facets_and_retained_denominator() -> None:
    result = inventory()
    page = page_inventory(result, "scope", InventoryQuery(q="ram:00100002"), 0, 1, None)
    assert [item[0] for item in page.items] == [0]
    assert page.matched == 1 and page.next_cursor is None
    assert (
        page_inventory(
            result, "scope", InventoryQuery(q="Lab", field="namespace", exact=True), 0, 1, None
        ).matched
        == 1
    )
    assert (
        page_inventory(result, "scope", InventoryQuery(q="ALP", field="name"), 0, 1, None).matched
        == 1
    )
    assert page_inventory(result, "scope", InventoryQuery(external=True), 0, 1, None).matched == 0


def test_cursor_bound_to_scope_query_limit_and_output() -> None:
    result = inventory()
    query = InventoryQuery()
    first = page_inventory(result, "scope", query, 0, 1, None)
    assert first.items[0][0] == 1  # Stable address-space/address ordering, original evidence index.
    assert first.next_cursor
    second = page_inventory(result, "scope", query, 0, 1, first.next_cursor)
    assert second.items[0][0] == 0 and second.next_cursor is None
    for scope, changed, limit, cursor in [
        ("other-run", query, 1, first.next_cursor),
        ("scope", InventoryQuery(q="alpha"), 1, first.next_cursor),
        ("scope", query, 2, first.next_cursor),
        ("scope", query, 1, first.next_cursor + "!"),
    ]:
        with pytest.raises(ValueError):
            page_inventory(result, scope, changed, 0, limit, cursor)


def test_one_hop_bounds_exact_spaces_unknown_targets_and_provenance() -> None:
    from bytasm.function_relationships import relationships
    from bytasm.ghidra_protocol import Address, Call

    result = inventory()
    result.functions[0].calls = [
        Call(source=Address(space="ram", address="00100003"), target=result.functions[1].entry),
        Call(
            source=Address(space="ram", address="00100004"),
            target=Address(space="other", address="00100001"),
        ),
    ]
    view = relationships(result, "run", "inv", 0, node_limit=2)
    assert view.retained_matches == 2 and len(view.edges) == 1 and view.truncated
    assert view.edges[0].target_index == 1
    assert view.edges[0].citation.endswith("/inv/raw#/functions/0/calls/0")
    all_edges = relationships(result, "run", "inv", 0)
    assert all_edges.edges[1].target_index is None
    assert all_edges.edges[1].target.space == "other"
    incoming = relationships(result, "run", "inv", 1)
    assert len(incoming.edges) == 1 and incoming.edges[0].source_index == 0
    assert not incoming.inventory_complete
    with pytest.raises(ValueError):
        relationships(result, "run", "inv", 0, edge_limit=65)


def test_selected_profile_and_parser_bind_exact_function_set() -> None:
    from bytasm.ghidra_protocol import Address
    from bytasm.ghidra_provider import _parse, profile_digest, profile_snapshot

    result = inventory()
    selected = [result.functions[1].entry.model_copy(deep=True)]
    snapshot = profile_snapshot(selected)
    assert snapshot["steps"][0]["profile_sha256"] != profile_digest()
    assert profile_digest(selected) == profile_digest(list(reversed(selected)))
    for invalid in ([], selected * 2, [Address(space="ram", address=str(i)) for i in range(9)]):
        with pytest.raises(ValueError):
            profile_snapshot(invalid)
    result.profile_sha256 = profile_digest(selected)
    # Extra detailed functions fail exact selection validation.
    assert _parse(result.model_dump_json().encode(), result.input_sha256, selected) is None
    result.functions[0].pseudocode = None
    result.functions[0].pseudocode_status = "not_selected"
    result.functions[0].instructions = []
    assert _parse(result.model_dump_json().encode(), result.input_sha256, selected) == result
    result.functions[1].entry.space = "other"
    assert _parse(result.model_dump_json().encode(), result.input_sha256, selected) is None


def test_protocol_preserves_legacy_cap_and_new_inventory_bound() -> None:
    from pydantic import ValidationError

    value = document()
    fn = value["functions"][0]
    value["functions"] = [
        {
            **fn,
            "entry": {"space": "ram", "address": f"{i:08x}"},
            "pseudocode": None,
            "pseudocode_status": "not_selected",
            "instructions": [],
        }
        for i in range(1024)
    ]
    value["function_count"] = 1024
    value["schema_version"] = "ghidra-1"
    with pytest.raises(ValidationError, match="Legacy inventory"):
        GhidraResult.model_validate(value)
    value["schema_version"] = "ghidra-2"
    assert len(GhidraResult.model_validate(value).functions) == 1024
    value["functions"].append(
        {**value["functions"][0], "entry": {"space": "ram", "address": "fffffff0"}}
    )
    value["function_count"] = 1025
    with pytest.raises(ValidationError):
        GhidraResult.model_validate(value)
