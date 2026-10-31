"""LIEF metadata adapter: bytes in, a small JSON-ready metadata dict out.

Only call this with bytes that already passed the input policy (manifest check)
and `identify_format`. The caller, not this module, is responsible for that.

The CLI and the API never call `extract_metadata` in their own process. They
run this module as a child process (`python -I -m bytasm.adapters.metadata_lief`,
see bytasm.runner), whose `main` lowers its own resource limits *before* LIEF
is imported. That is why LIEF is imported inside `extract_metadata` rather
than at module level. The child is not a security sandbox: the input policy
is what keeps untrusted files away from LIEF.

Everything read from headers (architecture, entry point, timestamps, flags) is
what the file *declares*. Bytasm does not verify it.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from importlib.metadata import version
from typing import TYPE_CHECKING, Any

from bytasm.adapters.entropy import METHOD as ENTROPY_METHOD
from bytasm.adapters.entropy import shannon_entropy
from bytasm.adapters.structure_lief import extract_structure
from bytasm.errors import PARSE_FAILED, InspectError
from bytasm.intake.identify import Format, identify_format
from bytasm.runner import child

if TYPE_CHECKING:
    import lief

ADAPTER_NAME = "metadata_lief"
ADAPTER_VERSION = "0.2.0"

# LIEF's architecture names, mapped to the lowercase names Bytasm reports.
_ARCHITECTURES = {
    "X86": "x86",
    "X86_64": "x86_64",
    "ARM": "arm",
    "ARM64": "aarch64",
}


def lief_version() -> str:
    return version("lief")


def extract_metadata(data: bytes, expected_format: Format) -> dict[str, Any]:
    """Parse `data` with LIEF and return Bytasm's metadata for it.

    Raises InspectError(PARSE_FAILED) if LIEF cannot parse the bytes, or if it
    disagrees with the format identified from the magic bytes.
    """
    import lief

    lief.logging.disable()  # LIEF otherwise writes warnings to stderr.
    try:
        binary = lief.parse(data)
    except Exception as exc:  # LIEF can raise various errors on bad input.
        raise InspectError(PARSE_FAILED, f"LIEF could not parse the file: {exc}") from exc

    if isinstance(binary, lief.ELF.Binary) and expected_format == "ELF":
        metadata = _elf_metadata(binary)
    elif isinstance(binary, lief.PE.Binary) and expected_format == "PE":
        metadata = _pe_metadata(binary)
    else:
        raise InspectError(PARSE_FAILED, f"LIEF could not parse the file as {expected_format}.")

    metadata["structure"] = extract_structure(binary, data, expected_format)
    warnings: list[str] = []
    for section in metadata["sections"]:
        _add_entropy(section, data, warnings)
    metadata["warnings"] = warnings
    return metadata


def _common_header(binary: lief.Binary) -> dict[str, Any]:
    header = binary.abstract.header
    lief_arch = header.architecture.name
    return {
        "architecture": _ARCHITECTURES.get(lief_arch, lief_arch.lower()),
        "bitness": 64 if header.is_64 else 32,
        "endianness": header.endianness.name.lower(),
    }


def _elf_metadata(binary: lief.ELF.Binary) -> dict[str, Any]:
    import lief  # already loaded by extract_metadata

    header = binary.header
    file_type = header.file_type.name
    # Relocatable objects (.o) have no entry point; 0 also means "none".
    entry = header.entrypoint
    entry_point = None if file_type == "REL" or entry == 0 else entry

    sections = []
    for section in binary.sections:
        is_nobits = section.type == lief.ELF.Section.TYPE.NOBITS
        sections.append(
            {
                "name": section.name,
                # LIEF names the null section type "SHT_NULL_"; report "NULL".
                "type": section.type.name.removeprefix("SHT_").rstrip("_"),
                "file_offset": section.offset,
                # NOBITS sections (such as .bss) occupy no bytes in the file.
                "file_size": 0 if is_nobits else section.size,
                "virtual_address": section.virtual_address,
                "declared_size": section.size,
                "flags": sorted(str(flag.name) for flag in section.flags_list),
            }
        )

    return {
        "format": "ELF",
        **_common_header(binary),
        "entry_point": entry_point,
        "declared_header": {
            "elf_file_type": file_type,
            "elf_machine": header.machine_type.name,
            "elf_os_abi": header.identity_os_abi.name,
        },
        "sections": sections,
        "imports": {
            "libraries": sorted(set(binary.libraries)),
            # From the dynamic symbol table: the functions the loader must bind.
            # (.symtab repeats them with version suffixes such as puts@GLIBC_2.17.)
            "functions": sorted(
                {s.name for s in binary.dynamic_symbols if s.imported and s.is_function}
            ),
        },
        # Defined global functions, from .symtab and .dynsym. Stripping removes .symtab.
        "exports": sorted({f.name for f in binary.exported_functions}),
    }


def _pe_metadata(binary: lief.PE.Binary) -> dict[str, Any]:
    header = binary.header
    optional = binary.optional_header
    entry_rva = optional.addressof_entrypoint

    sections = [
        {
            "name": section.name,
            "type": None,  # PE sections have no type field; see flags.
            "file_offset": section.pointerto_raw_data,
            "file_size": section.sizeof_raw_data,
            "virtual_address": section.virtual_address,
            "declared_size": section.virtual_size,
            "flags": sorted(str(flag.name) for flag in section.characteristics_lists),
        }
        for section in binary.sections
    ]

    return {
        "format": "PE",
        **_common_header(binary),
        # Absolute virtual address (image base + entry RVA); 0 RVA means none.
        "entry_point": optional.imagebase + entry_rva if entry_rva else None,
        "declared_header": {
            "pe_machine": header.machine.name,
            "pe_magic": optional.magic.name,
            "pe_subsystem": optional.subsystem.name,
            "pe_image_base": optional.imagebase,
            "pe_entry_point_rva": entry_rva,
            # Compile timestamp as declared: it can be forged, zeroed, or a hash.
            "pe_timestamp": header.time_date_stamps,
        },
        "sections": sections,
        "imports": {
            "libraries": sorted({library.name for library in binary.imports}),
            "functions": sorted(
                {
                    entry.name
                    for library in binary.imports
                    for entry in library.entries
                    if entry.name
                }
            ),
        },
        "exports": sorted({f.name for f in binary.exported_functions}),
    }


def _add_entropy(section: dict[str, Any], data: bytes, warnings: list[str]) -> None:
    """Measure entropy over the section's bytes *in the file* (blueprint 3.2)."""
    start = section["file_offset"]
    size = section["file_size"]
    if size == 0:
        section["entropy"] = None
        section["entropy_note"] = "no file data"
        return
    if start + size > len(data):
        section["entropy"] = None
        section["entropy_note"] = "declared range exceeds file size"
        warnings.append(
            f"Section {section['name']!r} declares bytes past the end of the file; "
            "its entropy was not measured."
        )
        return
    section["entropy"] = shannon_entropy(data[start : start + size])
    section["entropy_note"] = None


def build_result(data: bytes, sha256: str, limits: dict[str, int | None]) -> dict[str, Any]:
    """Identify and parse `data`; return the adapter result document."""
    file_format = identify_format(data)
    return {
        "schema_version": 1,
        "adapter": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "tool": "lief",
        "tool_version": lief_version(),
        "entropy_method": ENTROPY_METHOD,
        "input": {"sha256": sha256, "size_bytes": len(data)},
        "resource_limits": limits,
        "metadata": extract_metadata(data, file_format),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Child entry point. The order of steps is part of the contract.

    1. Lower this process's resource limits (LIEF is not imported yet).
    2. Read the input and confirm its SHA-256 is the one the parent admitted.
    3. Identify and parse it, then write result.json.

    A refused input exits 2 and prints one reason code from a fixed list.
    Anything else that goes wrong is a failure (non-zero exit, no result).
    """
    args = child.parse_child_args(argv)
    try:
        limits = child.apply_resource_limits(args)
    except child.LimitsNotApplied:
        return child.EXIT_LIMITS_NOT_APPLIED
    try:
        data = child.read_admitted_input(args)
    except (OSError, ValueError):
        return child.EXIT_INPUT_MISMATCH

    try:
        document = build_result(data, args.expected_sha256, limits)
    except InspectError as error:
        sys.stdout.write(error.code + "\n")
        return child.EXIT_REJECTED

    payload = json.dumps(document, sort_keys=True, ensure_ascii=True).encode("ascii")
    child.write_result(args.out, payload)
    return child.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
