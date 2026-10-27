"""Identify a file's format from its bytes (never from its name or extension).

This runs after the manifest check and before LIEF. It recognises the two
supported formats, PE and ELF, by their magic bytes and checks the few header
fields needed to know that the file is not obviously truncated. LIEF is
lenient: it can return an "ELF binary" with an empty header for a 14-byte file,
so Bytasm checks these basics itself.
"""

import struct
from typing import Final, Literal

from bytasm.errors import MALFORMED_INPUT, UNSUPPORTED_FORMAT, InspectError

Format = Literal["ELF", "PE"]

_ELF_MAGIC: Final = b"\x7fELF"
_MZ_MAGIC: Final = b"MZ"
_PE_SIGNATURE: Final = b"PE\x00\x00"

# Leading bytes of formats Bytasm recognises but refuses, with a reason.
_KNOWN_UNSUPPORTED: Final = (
    (b"PK\x03\x04", "a ZIP archive"),
    (b"PK\x05\x06", "an empty ZIP archive"),
    (b"\x1f\x8b", "a gzip archive"),
    (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"),
    (b"Rar!\x1a\x07", "a RAR archive"),
    (b"\xfe\xed\xfa\xce", "a Mach-O binary"),
    (b"\xfe\xed\xfa\xcf", "a Mach-O binary"),
    (b"\xce\xfa\xed\xfe", "a Mach-O binary"),
    (b"\xcf\xfa\xed\xfe", "a Mach-O binary"),
    (b"\xca\xfe\xba\xbe", "a Mach-O universal binary or Java class file"),
)


# Enough leading bytes to tell PE/ELF from the formats above.
SIGNATURE_BYTES: Final = 8


def check_signature(prefix: bytes) -> None:
    """Early check on the first bytes of an upload, before the rest arrives.

    Raises InspectError(UNSUPPORTED_FORMAT) unless the bytes start like an ELF
    or MZ file. The full header checks happen in `identify_format`.
    """
    if prefix.startswith(_ELF_MAGIC) or prefix.startswith(_MZ_MAGIC):
        return
    for magic, description in _KNOWN_UNSUPPORTED:
        if prefix.startswith(magic):
            raise InspectError(
                UNSUPPORTED_FORMAT,
                f"This file looks like {description}. Only PE and ELF are supported.",
            )
    raise InspectError(
        UNSUPPORTED_FORMAT, "Unrecognised file format. Only PE and ELF are supported."
    )


def identify_format(data: bytes) -> Format:
    """Return "ELF" or "PE", or raise InspectError explaining why not."""
    if data.startswith(_ELF_MAGIC):
        _check_elf_header(data)
        return "ELF"
    if data.startswith(_MZ_MAGIC):
        _check_pe_header(data)
        return "PE"
    for magic, description in _KNOWN_UNSUPPORTED:
        if data.startswith(magic):
            raise InspectError(
                UNSUPPORTED_FORMAT,
                f"This file looks like {description}. Only PE and ELF are supported.",
            )
    raise InspectError(
        UNSUPPORTED_FORMAT, "Unrecognised file format. Only PE and ELF are supported."
    )


def _check_elf_header(data: bytes) -> None:
    # e_ident[4] is the class (1 = 32-bit, 2 = 64-bit), e_ident[5] the byte order.
    if len(data) < 16:
        raise InspectError(MALFORMED_INPUT, "ELF identification bytes are truncated.")
    elf_class, byte_order = data[4], data[5]
    if elf_class not in (1, 2):
        raise InspectError(MALFORMED_INPUT, f"Invalid ELF class byte: {elf_class}.")
    if byte_order not in (1, 2):
        raise InspectError(MALFORMED_INPUT, f"Invalid ELF data-encoding byte: {byte_order}.")

    is_64 = elf_class == 2
    header_size = 64 if is_64 else 52
    if len(data) < header_size:
        raise InspectError(MALFORMED_INPUT, "ELF header is truncated.")

    endian = "<" if byte_order == 1 else ">"
    if is_64:
        # e_phoff, e_shoff at 0x20/0x28; e_phentsize..e_shnum at 0x36.
        phoff, shoff = struct.unpack_from(endian + "QQ", data, 0x20)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHH", data, 0x36)
    else:
        phoff, shoff = struct.unpack_from(endian + "II", data, 0x1C)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHH", data, 0x2A)

    _check_table(data, "program header", phoff, phentsize, phnum)
    _check_table(data, "section header", shoff, shentsize, shnum)


def _check_table(data: bytes, what: str, offset: int, entry_size: int, count: int) -> None:
    if count == 0:
        return
    if offset + entry_size * count > len(data):
        raise InspectError(MALFORMED_INPUT, f"ELF {what} table extends past the end of the file.")


def _check_pe_header(data: bytes) -> None:
    # The DOS header is 64 bytes; e_lfanew at 0x3C points to the "PE\0\0" signature.
    if len(data) < 64:
        raise InspectError(MALFORMED_INPUT, "DOS (MZ) header is truncated.")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    # Signature (4 bytes) + COFF file header (20 bytes) must fit in the file.
    if e_lfanew + 24 > len(data):
        raise InspectError(MALFORMED_INPUT, "PE header offset (e_lfanew) points past the file.")
    if data[e_lfanew : e_lfanew + 4] != _PE_SIGNATURE:
        raise InspectError(
            UNSUPPORTED_FORMAT, "MZ file without a PE signature (for example, a DOS program)."
        )
