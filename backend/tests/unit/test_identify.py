"""Format identification from bytes, including controlled refusals."""

from pathlib import Path

import pytest
from conftest import ELF_AARCH64, ELF_FIXTURES, ELF_X86_64_OBJECT, PE_FIXTURES
from generated_inputs import minimal_pe64, truncated, with_elf64_shoff, with_pe_lfanew

from bytasm.errors import MALFORMED_INPUT, UNSUPPORTED_FORMAT, InspectError
from bytasm.intake.identify import identify_format


def test_fixtures_and_generated_pe_are_identified() -> None:
    assert identify_format(ELF_AARCH64.read_bytes()) == "ELF"
    assert identify_format(ELF_X86_64_OBJECT.read_bytes()) == "ELF"
    assert identify_format(minimal_pe64()) == "PE"
    for fixture in ELF_FIXTURES:
        assert identify_format(fixture.read_bytes()) == "ELF", fixture.name
    for fixture in PE_FIXTURES:
        assert identify_format(fixture.read_bytes()) == "PE", fixture.name


def test_pe_fixture_renamed_elf_is_still_pe(tmp_path: Path) -> None:
    """Identification uses bytes, never the file name (blueprint 9.1)."""
    renamed = tmp_path / "hello.elf"
    renamed.write_bytes(PE_FIXTURES[0].read_bytes())
    assert identify_format(renamed.read_bytes()) == "PE"


@pytest.mark.parametrize(
    ("content", "expected_words"),
    [
        (b"PK\x03\x04" + bytes(40), "ZIP"),
        (b"\x1f\x8b\x08" + bytes(40), "gzip"),
        (b"\xcf\xfa\xed\xfe" + bytes(40), "Mach-O"),
        (b"plain text, not a binary\n", "Unrecognised"),
        (b"", "Unrecognised"),
    ],
)
def test_unsupported_formats_are_refused(content: bytes, expected_words: str) -> None:
    with pytest.raises(InspectError) as caught:
        identify_format(content)
    assert caught.value.code == UNSUPPORTED_FORMAT
    assert expected_words in caught.value.message


def test_mz_file_without_pe_signature_is_refused() -> None:
    # e_lfanew = 0 points back at "MZ\0\0" instead of "PE\0\0": a DOS-style file.
    with pytest.raises(InspectError) as caught:
        identify_format(b"MZ" + bytes(100))
    assert caught.value.code == UNSUPPORTED_FORMAT
    assert "PE signature" in caught.value.message


def _elf() -> bytes:
    return ELF_AARCH64.read_bytes()


@pytest.mark.parametrize(
    ("content", "expected_words"),
    [
        (truncated(_elf(), 10), "identification bytes are truncated"),
        (truncated(_elf(), 40), "ELF header is truncated"),
        (_elf()[:4] + b"\x07" + _elf()[5:], "Invalid ELF class"),
        (_elf()[:5] + b"\x09" + _elf()[6:], "Invalid ELF data-encoding"),
        (with_elf64_shoff(_elf(), 2**40), "section header table extends past"),
        (truncated(_elf(), 2000), "section header table extends past"),
        (truncated(minimal_pe64(), 50), "DOS (MZ) header is truncated"),
        (with_pe_lfanew(minimal_pe64(), 10_000_000), "points past the file"),
    ],
)
def test_malformed_headers_are_refused(content: bytes, expected_words: str) -> None:
    with pytest.raises(InspectError) as caught:
        identify_format(content)
    assert caught.value.code == MALFORMED_INPUT
    assert expected_words in caught.value.message
    assert caught.value.exit_code == 2
