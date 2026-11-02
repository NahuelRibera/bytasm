"""ghidra-5 strictness and historical-shape preservation, on real recordings."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from bytasm.ghidra_protocol import V5_FUNCTION_KEYS, GhidraResult

RECORDED = Path(__file__).resolve().parents[1] / "recorded"


def load(name: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((RECORDED / name).read_text())
    return value


V5 = "ghidra-5/hello_v1-x86_64.elf.ghidra.json"
V4 = "hello_v1-x86_64.elf.ghidra.json"


def selected(doc: dict[str, Any]) -> dict[str, Any]:
    fn: dict[str, Any] = next(f for f in doc["functions"] if f["name"] == "_init")
    return fn


def test_real_ghidra5_documents_validate_with_structure() -> None:
    for path in sorted((RECORDED / "ghidra-5").glob("*.json")):
        result = GhidraResult.model_validate(json.loads(path.read_text()))
        assert result.schema_version == "ghidra-5"
        detailed = [f for f in result.functions if f.pseudocode_status != "not_selected"]
        assert any(f.basic_blocks for f in detailed), path.name
        for fn in detailed:
            assert fn.basic_block_count is not None and fn.instruction_count is not None
            assert len(fn.basic_blocks) <= fn.basic_block_count
        for fn in result.functions:
            if fn.pseudocode_status == "not_selected":
                assert fn.basic_block_count is None and not fn.call_sites


def test_historical_documents_keep_their_exact_shape() -> None:
    raw = load(V4)
    result = GhidraResult.model_validate(raw)
    dumped = json.loads(result.model_dump_json())
    assert dumped == raw
    assert not any(key in fn for fn in dumped["functions"] for key in V5_FUNCTION_KEYS)


@pytest.mark.parametrize(
    "mutate",
    [
        # v5 fields under an older protocol
        lambda d: d.update(schema_version="ghidra-4"),
        # a target without its basis
        lambda d: selected(d)["call_sites"][0].update(target_basis=None),
        # an unresolved flow that is not computed
        lambda d: selected(d)["basic_blocks"][0]["flows"][0].update(target=None),
        # structure on an inventory-only function
        lambda d: d["functions"][-1].update(basic_block_count=1),
        # count below the retained blocks
        lambda d: selected(d).update(basic_block_count=0),
        # unknown field
        lambda d: selected(d)["basic_blocks"][0].update(guess="x"),
    ],
)
def test_malformed_structure_is_rejected(mutate: Any) -> None:
    doc = copy.deepcopy(load(V5))
    assert selected(doc)["call_sites"] and selected(doc)["basic_blocks"][0]["flows"]
    mutate(doc)
    with pytest.raises(ValueError):
        GhidraResult.model_validate(doc)
