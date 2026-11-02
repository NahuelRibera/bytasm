"""Bounded PE/ELF structural tables from LIEF (metadata adapter 0.3.0, v0.11).

Every value keeps its kind of provenance explicit:

* *declared*: a header or table value the file states about itself
  (data-directory RVA/size, program-header ranges, dynamic tags).
* *parsed*: a structure LIEF decoded (import entries, relocations, notes).
* *verified range*: a declared or parsed file range that Bytasm checked
  against the admitted bytes (`file_range_state`).
* *derived*: a relationship Bytasm computed (section-to-segment mapping,
  import-slot file offsets through the declared section or segment table).

Tables are capped; each cap is reported in `truncated`. Structural
observations are factual statements about declarations (for example, a
section that is both writable and executable). None of them is a verdict.
"""

from itertools import islice
from typing import Any

SCHEMA = "bytasm-lief-deep-1"
MAX_ROWS = 4096
MAX_SEGMENTS = 64
MAX_DYNAMIC = 256
MAX_NOTES = 32
MAX_DEBUG = 32
MAX_SYMBOLS = 1024
MAX_RELOCATION_BLOCKS = 512
MAX_OBSERVATIONS = 64
MAX_NAME = 256
# ELF relocation types that fill an import slot (GOT/PLT entry) with a symbol.
SLOT_RELOCATIONS = ("JUMP_SLOT", "GLOB_DAT")
# PE characteristics/ELF segment flags.
PF_X, PF_W = 1, 2


def _name(value: Any) -> tuple[str, bool]:
    text = str(value)
    return text[:MAX_NAME], len(text) > MAX_NAME


def _range_state(offset: int | None, size: int, file_size: int) -> str:
    if offset is None:
        return "not_file_backed"
    if size == 0:
        return "empty"
    if offset < 0 or offset > file_size or size > file_size - offset:
        return "outside_file"
    return "within_file"


class _Caps:
    def __init__(self) -> None:
        self.truncated: list[str] = []

    def take(self, values: Any, limit: int, label: str) -> list[Any]:
        items = list(islice(iter(values), limit + 1))
        if len(items) > limit:
            self.truncated.append(label)
        return items[:limit]


def extract_deep_structure(binary: Any, data: bytes, file_format: str) -> dict[str, Any]:
    caps = _Caps()
    observations: list[dict[str, Any]] = []

    def observe(code: str, subject: str, detail: str) -> None:
        if len(observations) < MAX_OBSERVATIONS:
            observations.append({"code": code, "subject": _name(subject)[0], "detail": detail})
        elif "structural_observations" not in caps.truncated:
            caps.truncated.append("structural_observations")

    tables = (
        _pe(binary, data, caps, observe)
        if file_format == "PE"
        else _elf(binary, data, caps, observe)
    )
    return {
        "schema_version": SCHEMA,
        "format": file_format,
        "file_size": len(data),
        **tables,
        "structural_observations": observations,
        "truncated": sorted(set(caps.truncated)),
        "limitations": (
            "Declared values are the file's own claims. Verified ranges were only checked "
            "against the admitted file size; contents were not interpreted. Structural "
            "observations describe declarations and are not maliciousness indicators."
        ),
    }


# --------------------------------------------------------------------------- PE


def _pe_sections(binary: Any) -> list[tuple[int, int, int, int, str]]:
    """(rva, virtual span, raw offset, raw size, name) for RVA translation."""
    out = []
    for s in binary.sections:
        virtual = s.virtual_size or s.sizeof_raw_data
        out.append((s.virtual_address, virtual, s.pointerto_raw_data, s.sizeof_raw_data, s.name))
    return out


def _pe_rva_to_offset(sections: list[tuple[int, int, int, int, str]], rva: int) -> int | None:
    hits = {
        raw + rva - start
        for start, span, raw, size, _ in sections
        if start <= rva < start + span and rva - start < min(size, span)
    }
    return hits.pop() if len(hits) == 1 else None


def _pe(binary: Any, data: bytes, caps: _Caps, observe: Any) -> dict[str, Any]:
    optional = binary.optional_header
    image_base = optional.imagebase
    sections = _pe_sections(binary)
    file_size = len(data)

    directories = []
    for index, directory in enumerate(binary.data_directories):
        rva, size = directory.rva, directory.size
        present = bool(rva or size)
        # The certificate table's "RVA" is a file offset (PE/COFF specification).
        is_certificate = directory.type.name == "CERTIFICATE_TABLE"
        offset = (rva if is_certificate else _pe_rva_to_offset(sections, rva)) if present else None
        state = _range_state(offset, size, file_size) if present else "not_present"
        directories.append(
            {
                "index": index,
                "type": directory.type.name,
                "declared_rva": rva,
                "declared_size": size,
                "address_kind": "file_offset" if is_certificate else "rva",
                "section": _name(directory.section.name)[0]
                if present and directory.has_section
                else None,
                "file_offset": offset,
                "file_range_state": state,
            }
        )
        if present and state == "outside_file":
            observe(
                "data_directory_outside_file",
                directory.type.name,
                "A declared data directory range does not lie within the file bytes.",
            )

    imports = []
    slots: list[dict[str, Any]] = []
    for library in caps.take(binary.imports, MAX_ROWS, "import_libraries"):
        lib_name, lib_truncated = _name(library.name)
        entries = caps.take(library.entries, MAX_ROWS, "import_entries")
        imports.append(
            {
                "library": lib_name,
                "library_truncated": lib_truncated,
                "import_lookup_table_rva": library.import_lookup_table_rva,
                "import_address_table_rva": library.import_address_table_rva,
                "entry_count": len(entries),
            }
        )
        for entry in entries:
            if len(slots) >= MAX_ROWS:
                caps.truncated.append("import_slots")
                break
            name, name_truncated = (None, False) if entry.is_ordinal else _name(entry.name)
            iat_rva = entry.iat_address
            offset = _pe_rva_to_offset(sections, iat_rva)
            slots.append(
                {
                    "library": lib_name,
                    "name": name,
                    "name_truncated": name_truncated,
                    "ordinal": entry.ordinal if entry.is_ordinal else None,
                    "hint": None if entry.is_ordinal else entry.hint,
                    "slot_rva": iat_rva,
                    "slot_virtual_address": image_base + iat_rva,
                    "slot_file_offset": offset,
                    "slot_basis": "lief_import_address_table",
                    "relocation_type": None,
                }
            )

    exports = []
    if binary.has_exports:
        export = binary.get_export()
        for entry in caps.take(export.entries, MAX_ROWS, "exports"):
            name, truncated = _name(entry.name)
            exports.append(
                {
                    "name": name or None,
                    "name_truncated": truncated,
                    "ordinal": entry.ordinal,
                    "rva": entry.address,
                    "forwarded": bool(entry.is_forwarded),
                    "file_offset": None
                    if entry.is_forwarded
                    else _pe_rva_to_offset(sections, entry.address),
                }
            )

    relocation_types: dict[str, int] = {}
    blocks = 0
    entries_total = 0
    if binary.has_relocations:
        for block in caps.take(binary.relocations, MAX_RELOCATION_BLOCKS, "relocation_blocks"):
            blocks += 1
            for entry in block.entries:
                entries_total += 1
                key = entry.type.name
                relocation_types[key] = relocation_types.get(key, 0) + 1

    debug = []
    for entry in caps.take(binary.debug, MAX_DEBUG, "debug_entries"):
        offset = entry.pointerto_rawdata or None
        debug.append(
            {
                "type": entry.type.name,
                "declared_rva": entry.addressof_rawdata,
                "declared_file_offset": entry.pointerto_rawdata,
                "declared_size": entry.sizeof_data,
                "file_range_state": _range_state(offset, entry.sizeof_data, file_size),
            }
        )

    tls = None
    if binary.has_tls:
        t = binary.tls
        start, end = t.addressof_raw_data
        tls = {
            "raw_data_start_va": start,
            "raw_data_end_va": end,
            "index_va": t.addressof_index,
            "callbacks_va": t.addressof_callbacks,
            "callback_count": len(caps.take(t.callbacks, MAX_ROWS, "tls_callbacks")),
        }

    section_rows = []
    for index, s in enumerate(binary.sections):
        name, _ = _name(s.name)
        flags = {flag.name for flag in s.characteristics_lists}
        offset, size = s.pointerto_raw_data, s.sizeof_raw_data
        state = _range_state(offset if size else None, size, file_size)
        section_rows.append(
            {
                "index": index,
                "name": name,
                "rva": s.virtual_address,
                "virtual_size": s.virtual_size,
                "raw_offset": offset,
                "raw_size": size,
                "file_range_state": state,
                "characteristics": sorted(flags),
            }
        )
        if state == "outside_file":
            observe(
                "section_raw_range_outside_file",
                name,
                "The section's declared raw range extends beyond the file bytes.",
            )
        if "MEM_WRITE" in flags and "MEM_EXECUTE" in flags:
            observe(
                "writable_executable_section",
                name,
                "The section is declared both writable and executable.",
            )
    ranges = sorted(
        (r["raw_offset"], r["raw_offset"] + r["raw_size"], r["name"])
        for r in section_rows
        if r["raw_size"]
    )
    for (_, end, first), (start, _, second) in zip(ranges, ranges[1:], strict=False):
        if start < end:
            observe(
                "sections_overlap_in_file",
                f"{first}/{second}",
                "Two sections declare overlapping raw file ranges.",
            )
    entry_rva = optional.addressof_entrypoint
    if entry_rva:
        hit = [
            r
            for r in section_rows
            if r["rva"] <= entry_rva < r["rva"] + max(r["virtual_size"], r["raw_size"])
        ]
        if not hit:
            observe(
                "entry_point_outside_sections",
                "entry point",
                "The declared entry point RVA lies outside every declared section.",
            )
        elif not any("MEM_EXECUTE" in r["characteristics"] for r in hit):
            observe(
                "entry_point_in_non_executable_section",
                hit[0]["name"],
                "The declared entry point lies in a section not declared executable.",
            )

    return {
        "pe": {
            "image_base": image_base,
            "section_alignment": optional.section_alignment,
            "file_alignment": optional.file_alignment,
            "size_of_image": optional.sizeof_image,
            "size_of_headers": optional.sizeof_headers,
            "checksum_declared": optional.checksum,
            "entry_point_rva": entry_rva,
            "sections": section_rows,
            "data_directories": directories,
            "import_descriptors": imports,
            "exports": exports,
            "relocations": {
                "blocks": blocks,
                "entries": entries_total,
                "entries_by_type": dict(sorted(relocation_types.items())),
            },
            "debug_entries": debug,
            "tls": tls,
        },
        "import_slots": slots,
    }


# --------------------------------------------------------------------------- ELF


def _elf_va_to_offset(segments: list[Any], va: int) -> int | None:
    """Translate through PT_LOAD program headers: the loader's own file mapping."""
    hits = {
        s.file_offset + va - s.virtual_address
        for s in segments
        if s.type.name == "LOAD" and s.virtual_address <= va < s.virtual_address + s.physical_size
    }
    return hits.pop() if len(hits) == 1 else None


def _elf(binary: Any, data: bytes, caps: _Caps, observe: Any) -> dict[str, Any]:
    file_size = len(data)
    segments = caps.take(binary.segments, MAX_SEGMENTS, "segments")
    segment_rows = []
    for index, s in enumerate(segments):
        flags = int(s.flags)
        state = _range_state(s.file_offset if s.physical_size else None, s.physical_size, file_size)
        segment_rows.append(
            {
                "index": index,
                "type": s.type.name,
                "flags": ("r" if flags & 4 else "-")
                + ("w" if flags & PF_W else "-")
                + ("x" if flags & PF_X else "-"),
                "file_offset": s.file_offset,
                "file_size": s.physical_size,
                "virtual_address": s.virtual_address,
                "memory_size": s.virtual_size,
                "alignment": s.alignment,
                "file_range_state": state,
                "sections": [_name(sec.name)[0] for sec in islice(s.sections, 64)],
            }
        )
        if s.type.name == "LOAD" and state == "outside_file":
            observe(
                "segment_range_outside_file",
                f"segment {index}",
                "A loadable segment's declared file range extends beyond the file bytes.",
            )
        if s.type.name == "LOAD" and flags & PF_W and flags & PF_X:
            observe(
                "writable_executable_segment",
                f"segment {index}",
                "A loadable segment is declared both writable and executable.",
            )

    dynamic = []
    for entry in caps.take(binary.dynamic_entries, MAX_DYNAMIC, "dynamic_entries"):
        row: dict[str, Any] = {"tag": entry.tag.name, "value": entry.value}
        if entry.tag.name in ("NEEDED", "SONAME", "RPATH", "RUNPATH"):
            text = getattr(entry, "name", None) or ":".join(getattr(entry, "paths", []) or [])
            row["text"], row["text_truncated"] = _name(text)
        dynamic.append(row)

    symbols = []
    dynamic_symbols = list(binary.dynamic_symbols)
    for symbol in caps.take(dynamic_symbols, MAX_SYMBOLS, "dynamic_symbols"):
        name, truncated = _name(symbol.name)
        if not name:
            continue
        symbols.append(
            {
                "name": name,
                "name_truncated": truncated,
                "value": symbol.value,
                "size": symbol.size,
                "type": symbol.type.name,
                "binding": symbol.binding.name,
                "visibility": symbol.visibility.name,
                "section_index": symbol.shndx,
                "imported": bool(symbol.imported),
                "exported": bool(symbol.exported),
            }
        )

    slots: list[dict[str, Any]] = []
    relocation_types: dict[str, int] = {}
    relocation_total = 0
    for reloc in binary.relocations:
        relocation_total += 1
        kind = reloc.type.name
        relocation_types[kind] = relocation_types.get(kind, 0) + 1
        if (
            not kind.endswith(tuple(f"_{t}" for t in SLOT_RELOCATIONS))
            or not reloc.has_symbol
            or not reloc.symbol.name
        ):
            continue
        if len(slots) >= MAX_ROWS:
            caps.truncated.append("import_slots")
            continue
        name, truncated = _name(reloc.symbol.name)
        slots.append(
            {
                "library": None,
                "name": name,
                "name_truncated": truncated,
                "ordinal": None,
                "hint": None,
                "slot_rva": None,
                "slot_virtual_address": reloc.address,
                "slot_file_offset": _elf_va_to_offset(segments, reloc.address),
                "slot_basis": "lief_elf_relocation_load_segment",
                "relocation_type": kind,
            }
        )
    slots.sort(key=lambda s: (s["slot_virtual_address"], s["name"]))

    notes = []
    build_id = None
    for note in caps.take(binary.notes, MAX_NOTES, "notes"):
        kind = note.type.name if hasattr(note.type, "name") else str(note.type)
        description = bytes(note.description)
        name, _ = _name(note.name.rstrip("\x00"))
        row = {
            "type": kind,
            "owner": name,
            "description_size": len(description),
            "description_hex": description[:64].hex(),
            "description_truncated": len(description) > 64,
        }
        if kind == "GNU_BUILD_ID" and build_id is None:
            build_id = description[:64].hex()
        notes.append(row)

    loads = [s for s in segment_rows if s["type"] == "LOAD"]
    unmapped = []
    for section in binary.sections:
        if "ALLOC" not in {f.name for f in section.flags_list} or not section.virtual_address:
            continue
        inside = any(
            s["virtual_address"]
            <= section.virtual_address
            < s["virtual_address"] + max(s["memory_size"], 1)
            for s in loads
        )
        if not inside:
            unmapped.append(_name(section.name)[0])
    for name in unmapped[:8]:
        observe(
            "allocated_section_outside_load_segments",
            name,
            "An allocated section's address lies outside every loadable segment.",
        )
    entry = binary.header.entrypoint
    if entry and binary.header.file_type.name != "REL":
        hit = [
            s
            for s in loads
            if s["virtual_address"] <= entry < s["virtual_address"] + s["memory_size"]
        ]
        if not hit:
            observe(
                "entry_point_outside_load_segments",
                "entry point",
                "The declared entry point lies outside every loadable segment.",
            )
        elif "x" not in hit[0]["flags"]:
            observe(
                "entry_point_in_non_executable_segment",
                "entry point",
                "The declared entry point lies in a segment not declared executable.",
            )
    return {
        "elf": {
            "file_type": binary.header.file_type.name,
            "entry_point": entry,
            "interpreter": _name(binary.interpreter)[0] if binary.has_interpreter else None,
            "build_id": build_id,
            "segments": segment_rows,
            "dynamic_entries": dynamic,
            "dynamic_symbols": symbols,
            "symtab_symbol_count": len(list(binary.symtab_symbols)),
            "relocations": {
                "entries": relocation_total,
                "entries_by_type": dict(sorted(relocation_types.items())),
            },
            "notes": notes,
        },
        "import_slots": slots,
    }
