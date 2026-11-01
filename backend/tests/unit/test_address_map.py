"""Address translation refuses to guess: every non-mapped case has an explicit state."""

from types import SimpleNamespace
from typing import Any

import pytest

from bytasm.address_map import DeclaredLayout, GhidraMemoryMap, parse_address
from bytasm.ghidra_protocol import Address, GhidraResult


def section(index: int, name: str, offset: int, raw: int, va: int, vsize: int, *flags: str) -> Any:
    return SimpleNamespace(
        index=index,
        name=name,
        file_offset=offset,
        raw_size=raw,
        virtual_address=va,
        virtual_size=vsize,
        flags=list(flags),
    )


def pe(*sections: Any, image_base: int | None = 0x140000000) -> DeclaredLayout:
    header = {"format": "PE", "declared_header": {"pe_image_base": image_base}}
    return DeclaredLayout.from_import(header, list(sections))


def test_pe_rva_plus_image_base_and_virtual_size_bounds() -> None:
    layout = pe(
        section(0, ".text", 0x400, 0x600, 0x1000, 0x500),  # raw padding past VirtualSize
        section(1, ".bss", 0, 0, 0x2000, 0x100),
    )
    hit = layout.va_to_file_offset(0x140001010)
    assert hit.mapped and hit.file_offset == 0x410 and hit.region == ".text"
    # Raw bytes beyond VirtualSize are padding, not loaded content.
    assert layout.va_to_file_offset(0x140001500).state == "outside_known_regions"
    assert layout.va_to_file_offset(0x140002010).state == "not_file_backed"
    assert layout.va_to_file_offset(0x1010).state == "outside_known_regions"  # an RVA is not a VA
    assert layout.section_for_offset(0x410) is not None
    assert layout.section_for_offset(0x10) is None  # headers are outside every section
    assert pe(section(0, ".text", 0x400, 0x200, 0x1000, 0x200), image_base=None).va_to_file_offset(
        0x140001000
    ).state == ("unavailable")


def test_pe_overlapping_declarations_are_ambiguous() -> None:
    layout = pe(
        section(0, "a", 0x400, 0x200, 0x1000, 0x200),
        section(1, "b", 0x800, 0x200, 0x1000, 0x200),
    )
    assert layout.va_to_file_offset(0x140001000).state == "ambiguous"
    overlapping_file = pe(
        section(0, "a", 0x400, 0x200, 0x1000, 0x200),
        section(1, "b", 0x400, 0x200, 0x3000, 0x200),
    )
    assert overlapping_file.section_for_offset(0x410) is False


def test_elf_only_allocated_sections_have_addresses() -> None:
    header = {"format": "ELF", "declared_header": {}}
    layout = DeclaredLayout.from_import(
        header,
        [
            section(0, ".text", 0x1050, 0x100, 0x1050, 0x100, "ALLOC", "EXECINSTR"),
            section(1, ".comment", 0x3000, 0x20, 0, 0x20),
        ],
    )
    assert layout.va_to_file_offset(0x1060).file_offset == 0x1060
    assert layout.va_to_file_offset(0).state == "outside_known_regions"
    assert layout.sections[1].virtual_address is None


def ghidra(blocks: list[dict[str, Any]], version: str = "ghidra-4") -> GhidraResult:
    value: dict[str, Any] = {
        "schema_version": version,
        "input_sha256": "a" * 64,
        "ghidra_version": "12.2",
        "language_id": "x86:LE:64:default",
        "compiler": "gcc",
        "profile_sha256": "b" * 64,
        "script_sha256": "c" * 64,
        "functions": [],
        "function_count": 0,
        "functions_truncated": False,
        "analysis_timed_out": False,
        "limitations": [],
    }
    if version == "ghidra-4":
        value |= {"image_base": {"space": "ram", "address": "00100000"}, "memory_blocks": blocks}
    return GhidraResult.model_validate(value)


def block(
    name: str, start: int, end: int, ranges: list[tuple[int, int, int]], space: str = "ram"
) -> dict[str, Any]:
    def a(v: int) -> dict[str, str]:
        return {"space": space, "address": f"{v:08x}"}

    return {
        "name": name,
        "start": a(start),
        "end": a(end),
        "read": True,
        "write": False,
        "execute": False,
        "initialized": bool(ranges),
        "file_ranges": [{"start": a(s), "end": a(e), "file_offset": o} for s, e, o in ranges],
        "file_ranges_truncated": False,
    }


def test_ghidra_map_translates_both_ways_and_refuses_outside_bytes() -> None:
    result = ghidra(
        [
            block(".text", 0x101000, 0x101FFF, [(0x101000, 0x1017FF, 0x400)]),
            block(".bss", 0x104000, 0x1040FF, []),
            block("bad", 0x200000, 0x2000FF, [(0x200000, 0x2000FF, 0x1000)]),  # past file end
            block(".symtab", 0, 0xFF, [(0, 0xFF, 0xD00)], space=".symtab"),
        ]
    )
    gmap = GhidraMemoryMap.from_result(result, file_size=0x1000)
    assert gmap.available and gmap.rejected_ranges == 1
    hit = gmap.to_file_offset(Address(space="ram", address="00101010"))
    assert hit.mapped and hit.file_offset == 0x410
    assert gmap.to_file_offset(Address(space="ram", address="00101900")).state == (
        "not_file_backed"
    )
    assert gmap.to_file_offset(Address(space="ram", address="00104010")).state == (
        "not_file_backed"
    )
    assert gmap.to_file_offset(Address(space="ram", address="00200010")).state == (
        "not_file_backed"
    )
    assert gmap.to_file_offset(Address(space="EXTERNAL", address="1")).state == (
        "outside_known_regions"
    )
    assert gmap.to_file_offset(Address(space="ram", address="xyz")).state == "unsupported_address"
    assert gmap.to_addresses(0x410).addresses == (("ram", 0x101010),)
    # Non-loaded sections live in their own space and never alias ram.
    assert gmap.to_addresses(0xD10).addresses == ((".symtab", 0x10),)
    assert gmap.to_addresses(0x5).state == "outside_known_regions"


def test_ghidra_map_duplicate_mapping_is_ambiguous_and_legacy_unavailable() -> None:
    result = ghidra(
        [
            block("a", 0x101000, 0x1010FF, [(0x101000, 0x1010FF, 0x100)]),
            block("b", 0x102000, 0x1020FF, [(0x102000, 0x1020FF, 0x100)]),
        ]
    )
    gmap = GhidraMemoryMap.from_result(result, 0x1000)
    assert gmap.to_addresses(0x110).state == "ambiguous"
    legacy = GhidraMemoryMap.from_result(ghidra([], "ghidra-3"), 0x1000)
    assert not legacy.available and legacy.reason and "ghidra-4" in legacy.reason
    assert legacy.to_file_offset(Address(space="ram", address="00101000")).state == "unavailable"
    assert legacy.to_addresses(0).state == "unavailable"


@pytest.mark.parametrize("text", ["", "0x10", "g1", "1_0", " 10", "1" * 33])
def test_parse_address_rejects_non_plain_hex(text: str) -> None:
    assert parse_address(text) is None


def test_parse_address_accepts_ghidra_text() -> None:
    assert parse_address("140001450") == 0x140001450
    assert parse_address("ffffffffffffffff") == (1 << 64) - 1
