"""The reviewed Ghidra profile admits only explicitly supported native headers."""

from conftest import ELF_AARCH64, ELF_X86_64, PE_X86_64_EXE

from bytasm.jobs.ghidra_step import supported


def test_supported_native_fixtures_and_rejected_architecture_pairs() -> None:
    assert supported(ELF_X86_64.read_bytes())
    assert supported(ELF_AARCH64.read_bytes())
    assert supported(PE_X86_64_EXE.read_bytes())
    elf = bytearray(ELF_AARCH64.read_bytes())
    elf[4] = 1
    assert not supported(bytes(elf))
    elf = bytearray(ELF_X86_64.read_bytes())
    elf[18:20] = (3).to_bytes(2, "little")
    assert not supported(bytes(elf))
    elf[5] = 2
    assert not supported(bytes(elf))
    assert not supported(b"MZ")
    assert not supported(b"\\xcf\\xfa\\xed\\xfe")


def test_managed_pe_is_not_advertised_as_native_analysis() -> None:
    pe = bytearray(PE_X86_64_EXE.read_bytes())
    offset = int.from_bytes(pe[60:64], "little")
    directory = offset + 24 + 112
    pe[directory + 14 * 8 : directory + 15 * 8] = b"\x01" + b"\x00" * 7
    assert not supported(bytes(pe))
