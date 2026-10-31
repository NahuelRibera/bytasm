import pytest

from bytasm.import_catalog import CATALOG, classify_imports


@pytest.mark.parametrize("category", list(CATALOG))
def test_every_import_pattern_has_positive_and_benign_counterexample(category: str) -> None:
    entry = CATALOG[category]
    symbol = sorted(entry["symbols"])[0]
    matches = classify_imports([symbol, symbol], "1.0.0", "0.1.0")
    assert any(item["category"] == category for item in matches)
    match = next(item for item in matches if item["category"] == category)
    assert match["pointers"] == ["/metadata/imports/functions/0", "/metadata/imports/functions/1"]
    assert entry["alternative"] and "does not establish execution" in match["limitation"]
    assert (
        classify_imports(["ordinary_benign_symbol", symbol + "_documentation"], "1.0.0", "0.1.0")
        == []
    )


def test_unknown_provenance_and_malformed_values_are_not_interpreted() -> None:
    assert classify_imports(["system"], "unknown", "0.1.0") == []
    with pytest.raises(ValueError):
        classify_imports(["x" * 4097], "1.0.0", "0.1.0")
