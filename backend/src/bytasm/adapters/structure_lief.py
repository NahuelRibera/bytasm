"""Bounded structural declarations; these are not runtime or trust verification."""

from itertools import islice
from typing import Any

LIMIT = 128


def extract_structure(binary: Any, data: bytes, file_format: str) -> dict[str, Any]:
    """Summarize parsed declarations, keeping measurements separately identified."""
    declarations: dict[str, Any] = {}
    measurements: dict[str, int | str | bool | None] = {}
    truncated: list[str] = []
    version_strings: list[dict[str, str]] = []

    def bounded(values: Any, label: str) -> list[Any]:
        items = list(islice(iter(values), LIMIT + 1))
        if len(items) > LIMIT:
            truncated.append(label)
        return items[:LIMIT]

    if file_format == "ELF":
        declarations["interpreter"] = binary.interpreter if binary.has_interpreter else None
        declarations["needed_libraries"] = bounded(binary.libraries, "needed_libraries")
        declarations["rpath"] = []
        declarations["runpath"] = []
        flags: set[str] = set()
        for entry in binary.dynamic_entries:
            tag = entry.tag.name
            if tag in {"RPATH", "RUNPATH"}:
                declarations[tag.lower()].extend(bounded(entry.paths, tag.lower()))
                declarations[tag.lower()] = declarations[tag.lower()][:LIMIT]
            if tag in {"FLAGS", "FLAGS_1"}:
                flags.update(flag.name for flag in entry.flags)
            if tag == "BIND_NOW":
                flags.add("BIND_NOW")
        segments = list(binary.segments)
        stack = next((s for s in segments if s.type.name == "GNU_STACK"), None)
        declarations.update(
            elf_type=binary.header.file_type.name,
            pie_flag="PIE" in flags,
            gnu_relro=any(s.type.name == "GNU_RELRO" for s in segments),
            bind_now=bool({"BIND_NOW", "NOW"} & flags),
            gnu_stack_executable=None if stack is None else bool(int(stack.flags) & 1),
        )
    else:
        optional = binary.optional_header
        characteristics = {flag.name for flag in optional.dll_characteristics_lists}
        declarations.update(
            dynamic_base="DYNAMIC_BASE" in characteristics,
            nx_compat="NX_COMPAT" in characteristics,
            high_entropy_va="HIGH_ENTROPY_VA" in characteristics,
            guard_cf="GUARD_CF" in characteristics,
            signature_present=binary.has_signatures,
            signature_validation="not_performed",
            tls_present=binary.has_tls,
            tls_callbacks=(
                bounded(binary.tls.callbacks, "tls_callbacks") if binary.has_tls else []
            ),
        )
        declarations["debug_types"] = [
            item.type.name for item in bounded(binary.debug, "debug_types")
        ]
        resources = []
        pending = [(binary.resources, 0)] if binary.has_resources else []
        visited = 0
        while pending and visited < LIMIT:
            node, depth = pending.pop()
            visited += 1
            if node.is_data:
                resources.append(node.id)
            if depth < 8:
                children = bounded(node.childs, "resource_children")
                pending.extend((child, depth + 1) for child in reversed(children))
            elif not node.is_data:
                truncated.append("resource_depth")
        if pending:
            truncated.append("resource_nodes")
        declarations["resource_data_ids"] = resources
        declarations["version_resource_present"] = bool(
            binary.has_resources and any(node.id == 16 for node in binary.resources.childs)
        )
        if binary.has_resources and binary.resources_manager.has_version:
            versions = bounded(binary.resources_manager.version, "version_records")
            for record in versions:
                info = record.string_file_info
                if info is None:
                    continue
                for table in bounded(info.children, "version_tables"):
                    for item in bounded(table.entries, "version_strings"):
                        if len(version_strings) >= LIMIT:
                            truncated.append("version_strings")
                            break
                        key, value = str(item.key), str(item.value)
                        if len(key) > 256 or len(value) > 4096:
                            truncated.append("version_string_length")
                        version_strings.append(
                            {
                                "table": str(table.key)[:256],
                                "key": key[:256],
                                "value": value[:4096],
                            }
                        )
        # Overlay is a parser-selected range, then independently range-checked.
        offset = binary.overlay_offset
        size = len(binary.overlay)
        valid = size > 0 and 0 <= offset <= len(data) and size <= len(data) - offset
        measurements.update(
            overlay_file_offset=offset if valid else None,
            overlay_size_bytes=size if valid else 0,
            overlay_range_valid=valid if size else None,
        )
    return {
        "schema_version": 1,
        "provenance": "lief_static_declarations",
        "declarations": declarations,
        "measurements": measurements,
        "version_strings": version_strings,
        "explanations": {
            key: FIELD_EXPLANATIONS[key] for key in declarations.keys() | measurements.keys()
        },
        "truncated": sorted(set(truncated)),
        "limitations": (
            "Header flags and resource/signature presence are declarations; protection efficacy, "
            "resource contents, publisher identity and signature validity are not verified. "
            "DYN alone does not establish PIE; GNU_RELRO and immediate binding "
            "are reported separately."
        ),
    }


FIELD_EXPLANATIONS = {
    "interpreter": "Declared ELF program interpreter path; no loader is launched or trusted.",
    "needed_libraries": (
        "DT_NEEDED dependency names; availability and actual resolution are unverified."
    ),
    "rpath": "Legacy DT_RPATH search paths; resolution depends on loader and RUNPATH context.",
    "runpath": "DT_RUNPATH search paths; environment and loader rules may affect resolution.",
    "elf_type": (
        "ELF header object type. DYN can describe shared libraries as well as PIE executables."
    ),
    "pie_flag": "DF_1_PIE declaration only; absence does not disprove position independence.",
    "gnu_relro": "GNU_RELRO segment declaration; runtime page protections are not measured.",
    "bind_now": "BIND_NOW or NOW dynamic flag requests immediate symbol binding.",
    "gnu_stack_executable": "GNU_STACK execute flag; null means no stack declaration was found.",
    "dynamic_base": "PE DYNAMIC_BASE flag requests relocation support; runtime ASLR is unverified.",
    "nx_compat": "PE NX_COMPAT declaration; runtime DEP enforcement is unverified.",
    "high_entropy_va": "PE HIGH_ENTROPY_VA declaration; requires platform and relocation support.",
    "guard_cf": "PE GUARD_CF declaration; instrumentation and load-config consistency unverified.",
    "signature_present": (
        "Parser reports certificate/signature data; no authenticity is established."
    ),
    "signature_validation": (
        "Signature cryptography, chain, timestamp and revocation were not checked."
    ),
    "tls_present": "PE TLS directory presence; callbacks are not executed.",
    "tls_callbacks": "Declared callback virtual addresses, not RVAs or file offsets; maximum 128.",
    "debug_types": "Declared PE debug-entry types; debug payloads and paths are not read.",
    "resource_data_ids": (
        "Data-leaf resource IDs from a bounded tree walk; not globally unique names."
    ),
    "version_resource_present": (
        "RT_VERSION resource declaration; string values remain untrusted claims."
    ),
    "overlay_file_offset": (
        "Parser-selected overlay offset, independently checked against supplied bytes."
    ),
    "overlay_size_bytes": (
        "Parser-selected overlay length after file-range checking; may include certificates."
    ),
    "overlay_range_valid": (
        "Whether the nonempty parser-selected overlay range fits the supplied file."
    ),
}
