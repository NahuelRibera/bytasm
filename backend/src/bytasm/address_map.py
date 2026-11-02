"""Exact address-space translation with explicit provenance and refusal states.

Two independent sources can relate a program address to a file offset:

* `GhidraMemoryMap`: Ghidra's own memory blocks and their file-byte ranges
  (protocol ghidra-4). A Ghidra address is translated only through these
  tool-reported ranges; Bytasm never guesses Ghidra's load base.
* `DeclaredLayout`: the section table LIEF parsed at import. PE sections
  declare RVAs, so a PE virtual address is `image base + RVA`. ELF sections
  declare virtual addresses directly; only SHF_ALLOC sections with file bytes
  are mapped.

Every translation returns a state. `mapped` is the only state that carries a
value; the others say why no value exists. Callers must never treat an
unmapped value as absent evidence.
"""

import re
from dataclasses import dataclass
from typing import Any, Literal

from bytasm.ghidra_protocol import MEMORY_MAP_PROTOCOLS, Address, GhidraResult

State = Literal[
    "mapped",
    "not_file_backed",  # inside a known region that has no file bytes (e.g. .bss)
    "outside_known_regions",
    "ambiguous",  # more than one distinct answer; none is chosen
    "unsupported_address",  # not a hexadecimal address in a plain memory space
    "unavailable",  # the source needed for this translation does not exist
]

GHIDRA_BASIS = "ghidra_memory_block_file_bytes"
DECLARED_BASIS = "lief_section_declaration"
MAX_ADDRESS_TEXT = 32
_HEX = re.compile(r"[0-9a-fA-F]{1,32}")


@dataclass(frozen=True)
class Translation:
    state: State
    basis: str
    file_offset: int | None = None
    region: str | None = None

    @property
    def mapped(self) -> bool:
        return self.state == "mapped"


@dataclass(frozen=True)
class Located:
    state: State
    basis: str
    addresses: tuple[tuple[str, int], ...] = ()


def parse_address(text: str) -> int | None:
    """Ghidra prints plain-space addresses as unprefixed hexadecimal."""
    # int(text, 16) alone would also accept "0x", "_" and whitespace.
    return int(text, 16) if _HEX.fullmatch(text) else None


@dataclass(frozen=True)
class _Range:
    space: str
    start: int
    end: int  # inclusive
    file_offset: int
    region: str


@dataclass(frozen=True)
class _Block:
    space: str
    start: int
    end: int
    region: str


class GhidraMemoryMap:
    """Ghidra-reported memory map; unavailable for protocols before ghidra-4."""

    def __init__(
        self,
        available: bool,
        reason: str | None,
        ranges: list[_Range],
        blocks: list[_Block],
        rejected_ranges: int,
        truncated: bool,
        image_base: Address | None,
    ) -> None:
        self.available = available
        self.reason = reason
        self._ranges = ranges
        self._blocks = blocks
        self.rejected_ranges = rejected_ranges
        self.truncated = truncated
        self.image_base = image_base

    @classmethod
    def from_result(cls, result: GhidraResult, file_size: int) -> "GhidraMemoryMap":
        if result.schema_version not in MEMORY_MAP_PROTOCOLS or result.image_base is None:
            return cls(
                False,
                f"Protocol {result.schema_version} does not include Ghidra's memory map; "
                "a new Ghidra run (ghidra-4 or later) is required for address translation.",
                [],
                [],
                0,
                False,
                None,
            )
        ranges: list[_Range] = []
        blocks: list[_Block] = []
        rejected = 0
        truncated = result.memory_blocks_truncated
        for block in result.memory_blocks:
            truncated = truncated or block.file_ranges_truncated
            start, end = parse_address(block.start.address), parse_address(block.end.address)
            if start is not None and end is not None and start <= end:
                blocks.append(_Block(block.start.space, start, end, block.name))
            for item in block.file_ranges:
                low, high = parse_address(item.start.address), parse_address(item.end.address)
                # A range must be well formed and lie inside the admitted bytes.
                if (
                    low is None
                    or high is None
                    or low > high
                    or item.file_offset + (high - low) + 1 > file_size
                ):
                    rejected += 1
                    continue
                ranges.append(_Range(item.start.space, low, high, item.file_offset, block.name))
        return cls(True, None, ranges, blocks, rejected, truncated, result.image_base)

    def to_file_offset(self, address: Address) -> Translation:
        if not self.available:
            return Translation("unavailable", GHIDRA_BASIS)
        value = parse_address(address.address)
        if value is None:
            return Translation("unsupported_address", GHIDRA_BASIS)
        hits = {
            (r.file_offset + value - r.start, r.region)
            for r in self._ranges
            if r.space == address.space and r.start <= value <= r.end
        }
        offsets = {offset for offset, _ in hits}
        if len(offsets) > 1:
            return Translation("ambiguous", GHIDRA_BASIS)
        if hits:
            offset, region = min(hits)
            return Translation("mapped", GHIDRA_BASIS, offset, region)
        inside = [b for b in self._blocks if b.space == address.space and b.start <= value <= b.end]
        if inside:
            return Translation("not_file_backed", GHIDRA_BASIS, region=inside[0].region)
        return Translation("outside_known_regions", GHIDRA_BASIS)

    def to_addresses(self, file_offset: int) -> Located:
        """Every Ghidra address whose bytes come from `file_offset` (sorted)."""
        if not self.available:
            return Located("unavailable", GHIDRA_BASIS)
        found = sorted(
            {
                (r.space, r.start + file_offset - r.file_offset)
                for r in self._ranges
                if r.file_offset <= file_offset <= r.file_offset + (r.end - r.start)
            }
        )
        if not found:
            return Located("outside_known_regions", GHIDRA_BASIS)
        return Located("mapped" if len(found) == 1 else "ambiguous", GHIDRA_BASIS, tuple(found))


@dataclass(frozen=True)
class DeclaredSection:
    index: int
    name: str
    file_offset: int
    file_size: int  # bytes of the section that come from the file
    virtual_address: int | None  # absolute declared VA; None when not loaded
    virtual_size: int
    flags: tuple[str, ...]

    @property
    def file_end(self) -> int:  # exclusive
        return self.file_offset + self.file_size


class DeclaredLayout:
    """LIEF section declarations. Values are claims the file makes about itself."""

    def __init__(self, file_format: str, image_base: int | None, sections: list[DeclaredSection]):
        self.file_format = file_format
        self.image_base = image_base
        self.sections = sections

    @classmethod
    def from_import(cls, header: dict[str, Any], sections: list[Any]) -> "DeclaredLayout":
        file_format = str(header.get("format", ""))
        declared = header.get("declared_header") or {}
        image_base = declared.get("pe_image_base") if file_format == "PE" else None
        if file_format == "PE" and not isinstance(image_base, int):
            image_base = None
        result = []
        for row in sections:
            flags = tuple(row.flags)
            if file_format == "PE":
                # Raw bytes past VirtualSize are padding, not loaded content.
                # A zero VirtualSize is treated as SizeOfRawData (linker convention).
                virtual_size = row.virtual_size or row.raw_size
                file_size = min(row.raw_size, virtual_size)
                va = None if image_base is None else image_base + row.virtual_address
            else:
                virtual_size = row.virtual_size
                loaded = "ALLOC" in flags
                file_size = row.raw_size
                va = row.virtual_address if loaded else None
            result.append(
                DeclaredSection(
                    index=row.index,
                    name=row.name,
                    file_offset=row.file_offset,
                    file_size=file_size,
                    virtual_address=va,
                    virtual_size=virtual_size,
                    flags=flags,
                )
            )
        return cls(file_format, image_base, sorted(result, key=lambda s: s.index))

    def section_for_offset(self, file_offset: int) -> DeclaredSection | None | Literal[False]:
        """The one section whose file bytes contain the offset; False if overlapping."""
        hits = [
            s for s in self.sections if s.file_size and s.file_offset <= file_offset < s.file_end
        ]
        if len(hits) > 1:
            return False
        return hits[0] if hits else None

    def va_to_file_offset(self, va: int) -> Translation:
        if self.file_format == "PE" and self.image_base is None:
            return Translation("unavailable", DECLARED_BASIS)
        hits = []
        backed = []
        for s in self.sections:
            if s.virtual_address is None:
                continue
            if s.virtual_address <= va < s.virtual_address + max(s.virtual_size, s.file_size):
                backed.append(s)
                delta = va - s.virtual_address
                if delta < s.file_size:
                    hits.append((s.file_offset + delta, s.name))
        offsets = {offset for offset, _ in hits}
        if len(offsets) > 1:
            return Translation("ambiguous", DECLARED_BASIS)
        if hits:
            return Translation("mapped", DECLARED_BASIS, hits[0][0], hits[0][1])
        if backed:
            return Translation("not_file_backed", DECLARED_BASIS, region=backed[0].name)
        return Translation("outside_known_regions", DECLARED_BASIS)
