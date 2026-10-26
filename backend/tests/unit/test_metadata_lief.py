"""The LIEF adapter on fixtures and on generated (test-authored) inputs.

Generated inputs are passed to the adapter directly, as blueprint 9.2 allows
for M1. They are never in the committed manifest.
"""

from pathlib import Path
from typing import Any

import lief
import pytest
from conftest import (
    ALL_FIXTURES,
    ELF_AARCH64,
    ELF_AARCH64_STRIPPED,
    ELF_ENTROPY,
    ELF_X86_64,
    ELF_X86_64_OBJECT,
    ELF_X86_64_STRIPPED,
    PE_FIXTURES,
    PE_X86_64_DLL,
    PE_X86_64_EXE,
    independent_entropy,
    write_test_manifest,
)
from generated_inputs import (
    PE_ENTRY_RVA,
    PE_IMAGE_BASE,
    PE_TEXT_BYTES,
    PE_TIMESTAMP,
    minimal_pe64,
    with_elf64_section_offset,
)

from bytasm.adapters.metadata_lief import extract_metadata
from bytasm.errors import MALFORMED_INPUT, PARSE_FAILED, UNSUPPORTED_FORMAT, InspectError
from bytasm.inspection import inspect_file
from bytasm.intake.identify import Format


def _section(metadata: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [s for s in metadata["sections"] if s["name"] == name]
    assert len(matches) == 1, f"expected exactly one {name!r} section"
    section: dict[str, Any] = matches[0]
    return section


def test_aarch64_executable_metadata() -> None:
    metadata = extract_metadata(ELF_AARCH64.read_bytes(), "ELF")
    assert metadata["format"] == "ELF"
    assert metadata["architecture"] == "aarch64"
    assert metadata["bitness"] == 64
    assert metadata["endianness"] == "little"
    assert metadata["entry_point"] == 0x660
    assert metadata["declared_header"] == {
        "elf_file_type": "DYN",  # Debian GCC builds position-independent executables
        "elf_machine": "AARCH64",
        "elf_os_abi": "SYSTEMV",
    }
    assert metadata["imports"] == {
        "libraries": ["libc.so.6"],
        "functions": ["__cxa_finalize", "__libc_start_main", "abort", "puts"],
    }
    assert "main" in metadata["exports"]
    assert metadata["warnings"] == []

    text = _section(metadata, ".text")
    assert text["type"] == "PROGBITS"
    assert text["flags"] == ["ALLOC", "EXECINSTR"]
    assert text["file_size"] > 0
    assert 0.0 < text["entropy"] < 8.0


@pytest.mark.parametrize(
    ("full_path", "stripped_path"),
    [(ELF_AARCH64, ELF_AARCH64_STRIPPED), (ELF_X86_64, ELF_X86_64_STRIPPED)],
    ids=["aarch64", "x86_64"],
)
def test_stripping_removes_symbols_but_not_dynamic_imports(
    full_path: Path, stripped_path: Path
) -> None:
    full = extract_metadata(full_path.read_bytes(), "ELF")
    stripped = extract_metadata(stripped_path.read_bytes(), "ELF")
    full_names = {s["name"] for s in full["sections"]}
    stripped_names = {s["name"] for s in stripped["sections"]}
    assert ".symtab" in full_names
    assert ".symtab" not in stripped_names
    assert stripped["exports"] == []
    assert stripped["imports"] == full["imports"]
    assert stripped["entry_point"] == full["entry_point"]


def test_x86_64_relocatable_object_has_no_entry_point() -> None:
    metadata = extract_metadata(ELF_X86_64_OBJECT.read_bytes(), "ELF")
    assert metadata["architecture"] == "x86_64"
    assert metadata["bitness"] == 64
    assert metadata["declared_header"]["elf_file_type"] == "REL"
    assert metadata["entry_point"] is None
    assert metadata["imports"] == {"libraries": [], "functions": []}
    assert metadata["exports"] == ["main"]


def test_x86_64_executable_metadata() -> None:
    # Expected values cross-checked with binutils readelf in the fixture image.
    metadata = extract_metadata(ELF_X86_64.read_bytes(), "ELF")
    assert metadata["architecture"] == "x86_64"
    assert metadata["bitness"] == 64
    assert metadata["endianness"] == "little"
    assert metadata["entry_point"] == 0x1050
    assert metadata["declared_header"] == {
        "elf_file_type": "DYN",
        "elf_machine": "X86_64",
        "elf_os_abi": "SYSTEMV",
    }
    assert metadata["imports"] == {
        "libraries": ["libc.so.6"],
        "functions": ["__cxa_finalize", "__libc_start_main", "puts"],
    }
    assert {"main", "_start"} <= set(metadata["exports"])
    assert metadata["warnings"] == []

    text = _section(metadata, ".text")
    assert text["type"] == "PROGBITS"
    assert text["flags"] == ["ALLOC", "EXECINSTR"]
    assert text["file_offset"] <= 0x1050 < text["file_offset"] + text["file_size"]
    assert _section(metadata, ".interp")["type"] == "PROGBITS"
    assert _section(metadata, ".dynamic")["type"] == "DYNAMIC"

    bss = _section(metadata, ".bss")
    assert bss["type"] == "NOBITS"
    assert bss["file_size"] == 0
    assert bss["entropy"] is None


# PE section layout as reported by binutils objdump -h for the committed bytes:
# (name, file offset, raw size, virtual size). .bss has no raw data.
PE_EXE_SECTIONS = [
    (".text", 0x400, 0x1800, 0x16B0),
    (".data", 0x1C00, 0x200, 0x80),
    (".rdata", 0x1E00, 0xA00, 0x948),
    (".pdata", 0x2800, 0x400, 0x210),
    (".xdata", 0x2C00, 0x200, 0x18C),
    (".bss", 0, 0, 0x180),
    (".idata", 0x2E00, 0x600, 0x52C),
    (".tls", 0x3400, 0x200, 0x10),
    (".reloc", 0x3600, 0x200, 0x68),
]
# MinGW-w64 CRT imports common to the .exe and the .dll (objdump -p).
PE_COMMON_KERNEL32 = {
    "DeleteCriticalSection",
    "EnterCriticalSection",
    "GetLastError",
    "InitializeCriticalSection",
    "LeaveCriticalSection",
    "Sleep",
    "TlsGetValue",
    "VirtualProtect",
    "VirtualQuery",
}


def test_pe_executable_metadata() -> None:
    metadata = extract_metadata(PE_X86_64_EXE.read_bytes(), "PE")
    assert metadata["format"] == "PE"
    assert metadata["architecture"] == "x86_64"
    assert metadata["bitness"] == 64
    assert metadata["endianness"] == "little"
    assert metadata["entry_point"] == 0x1_4000_0000 + 0x13F0
    assert metadata["declared_header"] == {
        "pe_machine": "AMD64",
        "pe_magic": "PE32_PLUS",
        "pe_subsystem": "WINDOWS_CUI",
        "pe_image_base": 0x1_4000_0000,
        "pe_entry_point_rva": 0x13F0,
        # Built with --no-insert-timestamp, so the declared timestamp is 0.
        "pe_timestamp": 0,
    }
    assert metadata["warnings"] == []

    layout = [
        (s["name"], s["file_offset"], s["file_size"], s["declared_size"])
        for s in metadata["sections"]
    ]
    assert layout == PE_EXE_SECTIONS
    assert _section(metadata, ".text")["flags"] == ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
    assert _section(metadata, ".reloc")["flags"] == [
        "CNT_INITIALIZED_DATA",
        "MEM_DISCARDABLE",
        "MEM_READ",
    ]
    bss = _section(metadata, ".bss")
    assert bss["flags"] == ["CNT_UNINITIALIZED_DATA", "MEM_READ", "MEM_WRITE"]
    assert bss["entropy"] is None
    assert bss["entropy_note"] == "no file data"

    imports = metadata["imports"]
    assert imports["libraries"] == ["KERNEL32.dll", "msvcrt.dll"]
    assert set(imports["functions"]) == PE_COMMON_KERNEL32 | {
        "SetUnhandledExceptionFilter",
        "__C_specific_handler",
        "__getmainargs",
        "__initenv",
        "__iob_func",
        "__set_app_type",
        "__setusermatherr",
        "_amsg_exit",
        "_cexit",
        "_commode",
        "_fmode",
        "_initterm",
        "_onexit",
        "abort",
        "calloc",
        "exit",
        "fprintf",
        "free",
        "fwrite",
        "malloc",
        "memcpy",
        "puts",  # the one call hello_v1.c makes itself
        "signal",
        "strlen",
        "strncmp",
        "vfprintf",
    }
    assert imports["functions"] == sorted(imports["functions"])
    # An executable without __declspec(dllexport) has no export table.
    assert metadata["exports"] == []


def test_pe_dll_exports_and_imports() -> None:
    metadata = extract_metadata(PE_X86_64_DLL.read_bytes(), "PE")
    assert metadata["architecture"] == "x86_64"
    assert metadata["declared_header"]["pe_machine"] == "AMD64"
    assert metadata["declared_header"]["pe_magic"] == "PE32_PLUS"
    assert metadata["declared_header"]["pe_image_base"] == 0x1_E01E_0000
    assert metadata["declared_header"]["pe_entry_point_rva"] == 0x1330
    assert metadata["declared_header"]["pe_timestamp"] == 0

    # Exactly the two functions exports_v1.c marks __declspec(dllexport).
    assert metadata["exports"] == ["bytasm_fixture_add", "bytasm_fixture_version"]
    edata = _section(metadata, ".edata")
    assert (edata["file_offset"], edata["file_size"], edata["declared_size"]) == (
        0x2400,
        0x200,
        0x7C,
    )
    assert [s["name"] for s in metadata["sections"]] == [
        ".text",
        ".data",
        ".rdata",
        ".pdata",
        ".xdata",
        ".bss",
        ".edata",
        ".idata",
        ".tls",
        ".reloc",
    ]

    imports = metadata["imports"]
    assert imports["libraries"] == ["KERNEL32.dll", "msvcrt.dll"]
    assert set(imports["functions"]) == PE_COMMON_KERNEL32 | {
        "__iob_func",
        "_amsg_exit",
        "_initterm",
        "_lock",
        "_unlock",
        "abort",
        "calloc",
        "free",
        "fwrite",
        "puts",
        "realloc",
        "strlen",
        "strncmp",
        "vfprintf",
    }


@pytest.mark.parametrize("fixture", PE_FIXTURES, ids=lambda p: p.name)
def test_pe_sections_lie_within_the_file(fixture: Path) -> None:
    data = fixture.read_bytes()
    metadata = extract_metadata(data, "PE")
    for section in metadata["sections"]:
        assert section["file_offset"] + section["file_size"] <= len(data)
        if section["file_size"]:
            assert section["file_offset"] % 0x200 == 0  # FileAlignment


def test_entropy_fixture_sections() -> None:
    data = ELF_ENTROPY.read_bytes()
    metadata = extract_metadata(data, "ELF")

    blob = _section(metadata, ".blob")
    assert blob["file_size"] == 4096
    # 4 KiB of seeded pseudo-random bytes: close to, but not exactly, 8.
    assert 7.9 < blob["entropy"] < 8.0
    blob_bytes = data[blob["file_offset"] : blob["file_offset"] + blob["file_size"]]
    assert blob["entropy"] == pytest.approx(independent_entropy(blob_bytes), abs=1e-6)

    bss = _section(metadata, ".bss")
    assert bss["type"] == "NOBITS"
    assert bss["declared_size"] >= 4096
    assert bss["file_size"] == 0
    assert bss["entropy"] is None
    assert bss["entropy_note"] == "no file data"

    null_section = _section(metadata, "")
    assert null_section["type"] == "NULL"
    assert null_section["entropy"] is None


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_every_measured_section_matches_independent_entropy(fixture: Path) -> None:
    data = fixture.read_bytes()
    file_format: Format = "PE" if fixture in PE_FIXTURES else "ELF"
    for section in extract_metadata(data, file_format)["sections"]:
        if section["entropy"] is None:
            assert section["file_size"] == 0
            continue
        start, size = section["file_offset"], section["file_size"]
        expected = independent_entropy(data[start : start + size])
        assert section["entropy"] == pytest.approx(expected, abs=1e-6)


def test_section_past_end_of_file_gets_null_entropy_and_warning() -> None:
    data = ELF_ENTROPY.read_bytes()
    parsed = lief.ELF.parse(list(data))
    assert parsed is not None
    blob_index = [s.name for s in parsed.sections].index(".blob")
    patched = with_elf64_section_offset(data, blob_index, len(data) + 0x1000)

    metadata = extract_metadata(patched, "ELF")
    blob = _section(metadata, ".blob")
    assert blob["entropy"] is None
    assert blob["entropy_note"] == "declared range exceeds file size"
    assert metadata["warnings"] == [
        "Section '.blob' declares bytes past the end of the file; its entropy was not measured."
    ]


def test_generated_pe_metadata() -> None:
    metadata = extract_metadata(minimal_pe64(), "PE")
    assert metadata["format"] == "PE"
    assert metadata["architecture"] == "x86_64"
    assert metadata["bitness"] == 64
    assert metadata["endianness"] == "little"
    assert metadata["entry_point"] == PE_IMAGE_BASE + PE_ENTRY_RVA
    assert metadata["declared_header"] == {
        "pe_machine": "AMD64",
        "pe_magic": "PE32_PLUS",
        "pe_subsystem": "WINDOWS_CUI",
        "pe_image_base": PE_IMAGE_BASE,
        "pe_entry_point_rva": PE_ENTRY_RVA,
        "pe_timestamp": PE_TIMESTAMP,
    }
    assert metadata["imports"] == {"libraries": [], "functions": []}

    text = _section(metadata, ".text")
    assert text["file_size"] == len(PE_TEXT_BYTES)
    assert text["flags"] == ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
    assert text["entropy"] == 8.0  # every byte value appears equally often

    bss = _section(metadata, ".bss")
    assert bss["file_size"] == 0
    assert bss["declared_size"] == 0x100
    assert bss["entropy"] is None
    assert bss["entropy_note"] == "no file data"


def test_lief_exception_becomes_parse_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_parse(_data: bytes) -> None:
        raise RuntimeError("simulated LIEF failure")

    monkeypatch.setattr(lief, "parse", broken_parse)
    with pytest.raises(InspectError) as caught:
        extract_metadata(ELF_AARCH64.read_bytes(), "ELF")
    assert caught.value.code == PARSE_FAILED
    assert "simulated LIEF failure" in caught.value.message


def test_lief_returning_nothing_becomes_parse_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lief, "parse", lambda _data: None)
    with pytest.raises(InspectError) as caught:
        extract_metadata(ELF_AARCH64.read_bytes(), "ELF")
    assert caught.value.code == PARSE_FAILED


def test_format_disagreement_becomes_parse_failed() -> None:
    with pytest.raises(InspectError) as caught:
        extract_metadata(ELF_AARCH64.read_bytes(), "PE")
    assert caught.value.code == PARSE_FAILED


@pytest.mark.parametrize(
    ("content", "expected_code"),
    [
        (ELF_AARCH64.read_bytes()[:40], MALFORMED_INPUT),
        (b"PK\x03\x04" + bytes(60), UNSUPPORTED_FORMAT),
        (b"just some text\n", UNSUPPORTED_FORMAT),
    ],
)
def test_full_pipeline_refuses_listed_but_bad_inputs(
    tmp_path: Path, content: bytes, expected_code: str
) -> None:
    """Even a listed hash must still pass identification before LIEF runs."""
    path = tmp_path / "generated.bin"
    path.write_bytes(content)
    with pytest.raises(InspectError) as caught:
        inspect_file(path, write_test_manifest(tmp_path, path))
    assert caught.value.code == expected_code


def test_full_pipeline_accepts_generated_pe_with_test_manifest(tmp_path: Path) -> None:
    path = tmp_path / "minimal.exe"
    path.write_bytes(minimal_pe64())
    report = inspect_file(path, write_test_manifest(tmp_path, path))
    assert report["format"] == "PE"
    assert report["input_policy"]["manifest_entry"] == "minimal.exe"
