"""Categories describe text shape only; section links need exact containment."""

from bytasm.string_review import category_of, containing_section


def test_heuristics_are_conservative_and_do_not_treat_schemes_as_links() -> None:
    assert category_of("HTTPS://example.invalid/path") == "url_like"
    assert category_of(r"C:\Users\someone\file.pdb") == "path_like"
    assert category_of("/lib64/ld-linux.so.2") == "path_like"
    assert category_of("javascript:alert(1)") == "other"
    assert category_of("password backup networking") == "other"


def test_only_a_unique_full_raw_range_gets_a_section_reference() -> None:
    sections = [{"index": 1, "name": ".data", "file_offset": 10, "raw_size": 20}]
    assert containing_section(12, 6, sections, 40) == {"index": 1, "name": ".data"}
    assert containing_section(28, 6, sections, 40) is None
    assert containing_section(12, 6, sections + sections, 40) is None
    assert containing_section(12, 6, [{**sections[0], "raw_size": 100}], 40) is None
