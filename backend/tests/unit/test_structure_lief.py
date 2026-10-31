"""Real parser structural declarations and separately checked measurements."""

from conftest import ELF_X86_64, ELF_X86_64_OBJECT, PE_X86_64_EXE
from generated_inputs import minimal_pe64

from bytasm.adapters.metadata_lief import extract_metadata
from bytasm.adapters.result import StructureResult


def test_elf_loader_and_protection_declarations() -> None:
    structure = extract_metadata(ELF_X86_64.read_bytes(), "ELF")["structure"]
    StructureResult.model_validate(structure)
    declarations = structure["declarations"]
    assert declarations["needed_libraries"] == ["libc.so.6"]
    assert declarations["interpreter"].endswith("ld-linux-x86-64.so.2")
    assert declarations["gnu_relro"] is True
    assert declarations["gnu_stack_executable"] is False
    obj = extract_metadata(ELF_X86_64_OBJECT.read_bytes(), "ELF")["structure"]
    assert obj["declarations"]["interpreter"] is None
    assert obj["declarations"]["gnu_stack_executable"] is None
    assert obj["declarations"]["pie_flag"] is False


def test_pe_tls_and_signature_are_declarations() -> None:
    structure = extract_metadata(PE_X86_64_EXE.read_bytes(), "PE")["structure"]
    StructureResult.model_validate(structure)
    declarations = structure["declarations"]
    assert declarations["tls_present"] is True
    assert declarations["tls_callbacks"]
    assert declarations["signature_present"] is False
    assert declarations["signature_validation"] == "not_performed"
    assert declarations["version_resource_present"] is False


def test_overlay_measurement_matches_supplied_bytes() -> None:
    data = minimal_pe64() + b"authored overlay"
    structure = extract_metadata(data, "PE")["structure"]
    measurement = structure["measurements"]
    assert measurement["overlay_range_valid"] is True
    offset = measurement["overlay_file_offset"]
    size = measurement["overlay_size_bytes"]
    assert offset + size == len(data)
    assert data[offset:].endswith(b"authored overlay")


def test_shared_object_does_not_imply_pie_and_paths_are_bounded() -> None:
    from types import SimpleNamespace as NS

    from bytasm.adapters.structure_lief import extract_structure

    binary = NS(
        has_interpreter=False,
        libraries=["libexample.so"],
        header=NS(file_type=NS(name="DYN")),
        segments=[],
        dynamic_entries=[
            NS(tag=NS(name="RPATH"), paths=["/legacy"]),
            NS(tag=NS(name="RUNPATH"), paths=["/current"] * 129),
            NS(tag=NS(name="FLAGS_1"), flags=[NS(name="NOW")]),
        ],
    )
    structure = extract_structure(binary, b"", "ELF")
    declarations = structure["declarations"]
    assert declarations["elf_type"] == "DYN"
    assert declarations["pie_flag"] is False
    assert declarations["bind_now"] is True
    assert declarations["gnu_relro"] is False
    assert declarations["rpath"] == ["/legacy"]
    assert len(declarations["runpath"]) == 128
    assert structure["truncated"] == ["runpath"]
    StructureResult.model_validate(structure)


def test_structure_contract_rejects_over_budget_and_unknown_provenance() -> None:
    import pytest
    from pydantic import ValidationError

    structure = extract_metadata(minimal_pe64(), "PE")["structure"]
    structure["declarations"]["tls_callbacks"] = list(range(129))
    with pytest.raises(ValidationError):
        StructureResult.model_validate(structure)
    structure["declarations"]["tls_callbacks"] = []
    structure["provenance"] = "verified_runtime_protections"
    with pytest.raises(ValidationError):
        StructureResult.model_validate(structure)


def test_bounded_version_strings_are_untrusted_declarations() -> None:
    from types import SimpleNamespace as NS

    from bytasm.adapters.structure_lief import extract_structure

    table = NS(key="040904b0", entries=[NS(key="ProductName", value="Authored fixture")])
    node = NS(id=16, is_data=True, childs=[])
    binary = NS(
        optional_header=NS(dll_characteristics_lists=[]),
        has_signatures=False,
        has_tls=False,
        debug=[],
        has_resources=True,
        resources=NS(id=0, is_data=False, childs=[node]),
        resources_manager=NS(
            has_version=True,
            version=[NS(string_file_info=NS(children=[table]))],
        ),
        overlay_offset=0,
        overlay=[],
    )
    structure = extract_structure(binary, b"", "PE")
    assert structure["version_strings"] == [
        {"table": "040904b0", "key": "ProductName", "value": "Authored fixture"}
    ]
    assert structure["declarations"]["version_resource_present"] is True
    assert "untrusted" in structure["explanations"]["version_resource_present"]
    table.entries = [NS(key="ProductName", value="x" * 5000)] * 129
    structure = extract_structure(binary, b"", "PE")
    assert len(structure["version_strings"]) == 128
    assert len(structure["version_strings"][0]["value"]) == 4096
    assert set(structure["truncated"]) == {"version_strings", "version_string_length"}
    StructureResult.model_validate(structure)
