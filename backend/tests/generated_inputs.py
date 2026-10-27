"""Test inputs generated in memory (blueprint 9.2: "generated in tests, not committed").

None of these bytes are listed in fixtures/MANIFEST.sha256, so the `bytasm
inspect` CLI refuses all of them. Tests that need to parse them either call the
adapter directly or build a temporary, test-only manifest.

Nothing here is ever executed.
"""

import struct

PE_TIMESTAMP = 0x5F5E1000
PE_ENTRY_RVA = 0x1000
PE_IMAGE_BASE = 0x1_4000_0000
# 512 bytes in which every byte value appears exactly twice: entropy is exactly 8.0.
PE_TEXT_BYTES = bytes(range(256)) * 2


def minimal_pe64() -> bytes:
    """A hand-assembled PE32+ (x86-64) image with two sections.

    - `.text`: 512 raw bytes (PE_TEXT_BYTES).
    - `.bss`: no raw data (SizeOfRawData = 0), so its entropy must be null.

    It has no imports and is not meant to be a working program.
    """
    file_alignment = 0x200

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew: PE header right after

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine: AMD64
        2,  # NumberOfSections
        PE_TIMESTAMP,  # TimeDateStamp (declared, not verified)
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        240,  # SizeOfOptionalHeader (PE32+)
        0x0022,  # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )
    optional_header = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # Magic: PE32+
        0,  # MajorLinkerVersion
        0,  # MinorLinkerVersion
        file_alignment,  # SizeOfCode
        0,  # SizeOfInitializedData
        0x100,  # SizeOfUninitializedData
        PE_ENTRY_RVA,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        PE_IMAGE_BASE,  # ImageBase
        0x1000,  # SectionAlignment
        file_alignment,  # FileAlignment
        6,  # MajorOperatingSystemVersion
        0,  # MinorOperatingSystemVersion
        0,  # MajorImageVersion
        0,  # MinorImageVersion
        6,  # MajorSubsystemVersion
        0,  # MinorSubsystemVersion
        0,  # Win32VersionValue
        0x3000,  # SizeOfImage
        file_alignment,  # SizeOfHeaders
        0,  # CheckSum
        3,  # Subsystem: WINDOWS_CUI (console)
        0x8160,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    ) + bytes(16 * 8)  # 16 empty data directories

    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        len(PE_TEXT_BYTES),  # VirtualSize
        0x1000,  # VirtualAddress
        len(PE_TEXT_BYTES),  # SizeOfRawData
        file_alignment,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x60000020,  # CODE | EXECUTE | READ
    )
    bss_section = struct.pack(
        "<8sIIIIIIHHI",
        b".bss",
        0x100,  # VirtualSize
        0x2000,  # VirtualAddress
        0,  # SizeOfRawData: no bytes in the file
        0,  # PointerToRawData
        0,
        0,
        0,
        0,
        0xC0000080,  # UNINITIALIZED_DATA | READ | WRITE
    )

    headers = (
        bytes(dos_header)
        + b"PE\x00\x00"
        + coff_header
        + optional_header
        + text_section
        + bss_section
    )
    assert len(headers) <= file_alignment
    return headers.ljust(file_alignment, b"\x00") + PE_TEXT_BYTES


def truncated(data: bytes, length: int) -> bytes:
    return data[:length]


def with_pe_lfanew(data: bytes, value: int) -> bytes:
    patched = bytearray(data)
    struct.pack_into("<I", patched, 0x3C, value)
    return bytes(patched)


def with_elf64_section_offset(data: bytes, section_index: int, new_offset: int) -> bytes:
    """Return a copy of a little-endian ELF64 file with one section's sh_offset changed."""
    patched = bytearray(data)
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    (shentsize,) = struct.unpack_from("<H", data, 0x3A)
    struct.pack_into("<Q", patched, shoff + section_index * shentsize + 0x18, new_offset)
    return bytes(patched)


def with_elf64_shoff(data: bytes, new_shoff: int) -> bytes:
    patched = bytearray(data)
    struct.pack_into("<Q", patched, 0x28, new_shoff)
    return bytes(patched)


def with_elf64_section_renamed(data: bytes, old_name: bytes, new_name: bytes) -> bytes:
    """Return a copy of a little-endian ELF64 file with one section renamed.

    The section-name string table (.shstrtab) is copied to the end of the file
    with `new_name` appended, and the section header now points at it. Used to
    give a fixture copy an HTML-like section name for the UI and report escaping
    tests (blueprint 9.1 "UI escaping"). PE section names are limited to 8
    bytes, which is why an ELF is used.
    """
    patched = bytearray(data)
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def header(index: int) -> int:
        return int(shoff + index * shentsize)

    str_offset, str_size = struct.unpack_from("<QQ", data, header(shstrndx) + 0x18)
    strtab = data[str_offset : str_offset + str_size]
    target = None
    for index in range(shnum):
        (name_offset,) = struct.unpack_from("<I", data, header(index))
        if strtab[name_offset:].split(b"\x00", 1)[0] == old_name:
            target = index
            break
    if target is None:
        raise ValueError(f"no section named {old_name!r}")

    new_strtab = strtab + new_name + b"\x00"
    padding = (-len(patched)) % 8
    new_offset = len(patched) + padding
    patched += b"\x00" * padding + new_strtab
    struct.pack_into("<QQ", patched, header(shstrndx) + 0x18, new_offset, len(new_strtab))
    struct.pack_into("<I", patched, header(target), len(strtab))
    return bytes(patched)
