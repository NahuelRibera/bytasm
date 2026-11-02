"""Deep PE/ELF tables over real self-built fixtures, checked independently.

Expected offsets come from LIEF's own translation helpers (`rva_to_offset`,
`virtual_address_to_offset`) or from the fixture bytes, never from the
adapter's derived values.
"""

from pathlib import Path
from typing import Any

import lief
import pytest
from conftest import (
    ALL_FIXTURES,
    ELF_AARCH64,
    ELF_X86_64,
    ELF_X86_64_OBJECT,
    PE_X86_64_DLL,
    PE_X86_64_EXE,
)

from bytasm.adapters.deep_structure_lief import extract_deep_structure
from bytasm.adapters.metadata_lief import extract_metadata
from bytasm.adapters.result import DeepStructureResult, MetadataResult
from bytasm.intake.identify import identify_format
from bytasm.structure_source import _state


def deep(path: Path) -> tuple[dict[str, Any], Any, bytes]:
    data = path.read_bytes()
    lief.logging.disable()
    binary = lief.parse(data)
    fmt = "PE" if isinstance(binary, lief.PE.Binary) else "ELF"
    return extract_deep_structure(binary, data, fmt), binary, data


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_every_fixture_yields_valid_bounded_tables(fixture: Path) -> None:
    data = fixture.read_bytes()
    metadata = MetadataResult.model_validate(extract_metadata(data, identify_format(data)))
    tables = metadata.deep_structure
    assert tables is not None and tables.file_size == len(data)
    assert not metadata.warnings
    for slot in tables.import_slots:
        if slot.slot_file_offset is not None:
            assert 0 <= slot.slot_file_offset < len(data)
    first = extract_metadata(data, identify_format(data))["deep_structure"]
    assert first == extract_metadata(data, identify_format(data))["deep_structure"]


def test_pe_import_slots_match_lief_rva_translation() -> None:
    tables, binary, data = deep(PE_X86_64_EXE)
    assert isinstance(binary, lief.PE.Binary)
    base = binary.optional_header.imagebase
    expected = {(lib.name, e.name): e.iat_address for lib in binary.imports for e in lib.entries}
    assert len(tables["import_slots"]) == len(expected)
    for slot in tables["import_slots"]:
        rva = expected[(slot["library"], slot["name"])]
        assert slot["slot_rva"] == rva
        assert slot["slot_virtual_address"] == base + rva
        assert slot["slot_file_offset"] == binary.rva_to_offset(rva)
        assert slot["slot_basis"] == "lief_import_address_table"
    directories = {d["type"]: d for d in tables["pe"]["data_directories"]}
    assert directories["IMPORT_TABLE"]["file_range_state"] == "within_file"
    assert directories["IMPORT_TABLE"]["file_offset"] == binary.rva_to_offset(
        directories["IMPORT_TABLE"]["declared_rva"]
    )
    assert directories["EXPORT_TABLE"]["file_range_state"] == "not_present"
    assert tables["pe"]["relocations"]["entries"] == sum(
        len(block.entries) for block in binary.relocations
    )


def test_pe_exports_and_tls_of_the_self_built_dll() -> None:
    tables, binary, _ = deep(PE_X86_64_DLL)
    exports = {e["name"]: e for e in tables["pe"]["exports"]}
    assert set(exports) == {"bytasm_fixture_add", "bytasm_fixture_version"}
    for entry in exports.values():
        assert entry["file_offset"] == binary.rva_to_offset(entry["rva"])
        assert entry["forwarded"] is False
    assert tables["pe"]["tls"]["callback_count"] == len(binary.tls.callbacks)


@pytest.mark.parametrize("fixture", [ELF_X86_64, ELF_AARCH64], ids=lambda p: p.name)
def test_elf_slots_segments_and_build_id(fixture: Path) -> None:
    tables, binary, data = deep(fixture)
    assert isinstance(binary, lief.ELF.Binary)
    slots = tables["import_slots"]
    assert slots
    for slot in slots:
        assert slot["relocation_type"].endswith(("_JUMP_SLOT", "_GLOB_DAT"))
        assert slot["slot_file_offset"] == binary.virtual_address_to_offset(
            slot["slot_virtual_address"]
        )
    imported = {s.name for s in binary.dynamic_symbols if s.imported}
    assert {s["name"] for s in slots} & imported
    elf = tables["elf"]
    note = next(n for n in binary.notes if n.type.name == "GNU_BUILD_ID")
    assert elf["build_id"] == bytes(note.description).hex()
    assert elf["interpreter"] == binary.interpreter
    loads = [s for s in elf["segments"] if s["type"] == "LOAD"]
    assert loads and all(s["file_range_state"] == "within_file" for s in loads)
    assert any(".text" in s["sections"] and "x" in s["flags"] for s in loads)
    assert not tables["structural_observations"]


def test_relocatable_object_has_no_segments_or_entry_observations() -> None:
    tables, _, _ = deep(ELF_X86_64_OBJECT)
    assert tables["elf"]["file_type"] == "REL"
    assert tables["elf"]["segments"] == []
    assert tables["import_slots"] == []
    assert tables["structural_observations"] == []


def test_validation_rejects_out_of_contract_tables() -> None:
    tables, _, _ = deep(ELF_X86_64)
    DeepStructureResult.model_validate(tables)
    bad = dict(tables, import_slots=[dict(tables["import_slots"][0], slot_file_offset=-1)])
    with pytest.raises(ValueError):
        DeepStructureResult.model_validate(bad)
    with pytest.raises(ValueError):
        DeepStructureResult.model_validate(dict(tables, unexpected=True))


def test_historical_imports_report_why_tables_are_absent() -> None:
    state = _state(None, "0.2.0")
    assert state.tables is None
    assert state.unavailable_reason is not None and "0.2.0" in state.unavailable_reason
    assert "not reconstructed" in state.unavailable_reason
