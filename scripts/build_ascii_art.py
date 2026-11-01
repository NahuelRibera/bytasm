"""Derive Bytasm's character art masks from the eight binary ASCII characters.

Two stages, both deterministic and stdlib-only:

``extract``
    Reads the untracked originals in ``docs/design/references/frontend-characters-ascii``
    (TXT grid + SVG with one tone per glyph) and writes compact, committed sources to
    ``frontend/art/source``: a byte-identical copy of each TXT and a ``.tone.png`` that
    stores each glyph's original RGB tone as one pixel per cell. Originals are only read.

``build`` / ``check``
    Classifies every cell of the committed sources and writes alpha masks to
    ``frontend/public/art/chars`` (``<name>.cutout.png`` and ``<name>.field.png``) plus
    the manifest ``frontend/src/art/characters.ts`` with its stylesheet ``characters.css``.
    ``check`` rebuilds in memory and fails if any committed output differs, so outputs can
    be verified in CI.

Classification (see docs/design/ASCII_INTEGRATION.md §3.3):

* A cell is *paper* when it is a ``1`` whose original tone is neutral near-white. The
  engravings were drawn on pure white paper while lit parts of the figures are cream or
  grey, and the SVG keeps that difference for every glyph.
* *Exterior* background is paper reachable from the grid border through paper cells.
* *Holes* are enclosed paper components (openings between limbs, rings, straps). A
  component is a hole when it is large, or when it is small and mostly surrounded by
  ink or mid-tones; small paper specks inside lit areas are highlights and stay.
* Explicit per-character corrections, if any, are listed in ``CORRECTIONS``.

The ``cutout`` mask keeps every non-background glyph at its original tone. The
``field`` mask keeps every glyph (original polarity).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFERENCES = ROOT / "docs/design/references/frontend-characters-ascii"
SOURCE_DIR = ROOT / "frontend/art/source"
OUTPUT_DIR = ROOT / "frontend/public/art/chars"
MANIFEST = ROOT / "frontend/src/art/characters.ts"
STYLESHEET = ROOT / "frontend/src/art/characters.css"

NAMES = ("wizard", "crow", "nohead", "mystic", "scavenger", "automaton", "executioner", "muerte")

# Paper: neutral near-white tone. Measured on the exterior background of all eight
# characters: luminance p5 >= 249, chroma p95 <= 2.
PAPER_MIN_LUMA = 246
PAPER_MAX_CHROMA = 4
# Enclosed paper components at least this large are always openings.
HOLE_MIN_CELLS = 20
# Smaller components (>= 2 cells) are openings when fewer than this share of their
# neighbours are lit `1` cells, i.e. they sit in ink or mid-tones, not in a highlight.
HOLE_MAX_LIT_NEIGHBOURS = 0.5

CELL_W, CELL_H = 5, 8  # output pixels per cell (source pitch is 4.8 x 8)
# Glyph alpha follows the original tone in steps of 16 (16 levels): visually identical at
# glyph size and about a third smaller to ship.
ALPHA_STEP = 16

# Glyph bitmaps for the output masks, drawn for a 5 x 8 cell like the source's 8 px mono.
GLYPHS = {
    "1": ("..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###.", "....."),
    "0": (".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###.", "....."),
}


@dataclass(frozen=True)
class Rim:
    """Keep original background glyphs within ``width`` cells of the figure, inside a
    cell rectangle, at ``alpha`` of their tone. Used where a dark detail is defined only
    by the paper around it (its interior was converted to spaces)."""

    rect: tuple[int, int, int, int]  # col0, row0, col1, row1 (exclusive)
    width: int
    alpha: float
    reason: str


@dataclass(frozen=True)
class Corrections:
    keep: tuple[tuple[int, int, int, int], ...] = ()  # force-keep paper cells in rects
    remove: tuple[tuple[int, int, int, int], ...] = ()  # force-remove paper cells in rects
    rims: tuple[Rim, ...] = ()


CORRECTIONS: dict[str, Corrections] = {
    "mystic": Corrections(
        rims=(
            Rim(
                rect=(148, 22, 214, 72),
                width=2,
                alpha=0.6,
                reason=(
                    "The raven on the hand is solid ink in the engraving and became spaces "
                    "in the TXT; only the paper around it defines its silhouette."
                ),
            ),
        )
    ),
}


# --------------------------------------------------------------------------- PNG I/O


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def write_png(width: int, height: int, color_type: int, rows: list[bytes]) -> bytes:
    """Encode 8-bit PNG (color_type 2 = RGB, 4 = gray+alpha), filter 0, fixed zlib level."""
    raw = b"".join(b"\x00" + row for row in rows)
    header = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(raw, 9))
        + _png_chunk(b"IEND", b"")
    )


def read_rgb_png(data: bytes) -> tuple[int, int, list[bytes]]:
    """Decode the RGB, filter-0 PNGs written by ``write_png``."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos, idat, width, height = 8, b"", 0, 0
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kind, body = data[pos + 4 : pos + 8], data[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, color_type = struct.unpack(">IIBB", body[:10])
            if (depth, color_type) != (8, 2):
                raise ValueError("expected 8-bit RGB")
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw, stride, rows = zlib.decompress(idat), width * 3 + 1, []
    for y in range(height):
        line = raw[y * stride : (y + 1) * stride]
        if line[0] != 0:
            raise ValueError("unsupported PNG filter")
        rows.append(line[1:])
    return width, height, rows


# ------------------------------------------------------------------------- extraction

_TEXT = re.compile(r'<text x="([\d.]+)" y="([\d.]+)" fill="rgb\((\d+),(\d+),(\d+)\)">([01])</text>')


def read_grid(text: str) -> list[str]:
    rows = text.split("\n")
    while rows and rows[-1] == "":
        rows.pop()
    width = max(len(r) for r in rows)
    return [r.ljust(width) for r in rows]


def extract(name: str) -> tuple[bytes, bytes]:
    """Return (TXT bytes, tone PNG bytes) for one character from the references."""
    txt = (REFERENCES / f"ascii-{name}-bw.txt").read_bytes()
    grid = read_grid(txt.decode("ascii"))
    height, width = len(grid), len(grid[0])
    tone = [bytearray(width * 3) for _ in range(height)]
    svg = (REFERENCES / f"ascii-{name}-bw.svg").read_text("utf-8")
    seen = 0
    for x, y, r, g, b, ch in _TEXT.findall(svg):
        col, row = round(float(x) / 4.8), round((float(y) - 6.4) / 8)
        if grid[row][col] != ch:
            raise ValueError(f"{name}: SVG glyph at {col},{row} does not match the TXT")
        tone[row][col * 3 : col * 3 + 3] = bytes((int(r), int(g), int(b)))
        seen += 1
    glyphs = sum(1 for row in grid for c in row if c != " ")
    if seen != glyphs:
        raise ValueError(f"{name}: SVG has {seen} glyphs, TXT has {glyphs}")
    return txt, write_png(width, height, 2, [bytes(r) for r in tone])


# ----------------------------------------------------------------------- classification

Cell = tuple[int, int]
_STEPS = ((1, 0), (-1, 0), (0, 1), (0, -1))


@dataclass
class Classified:
    grid: list[str]
    tone: list[bytes]
    exterior: set[Cell] = field(default_factory=set)
    holes: list[set[Cell]] = field(default_factory=list)
    kept_specks: int = 0
    rim: dict[Cell, float] = field(default_factory=dict)

    @property
    def background(self) -> set[Cell]:
        out = set(self.exterior)
        for hole in self.holes:
            out |= hole
        return out


def _luma_chroma(tone: list[bytes], col: int, row: int) -> tuple[float, int]:
    r, g, b = tone[row][col * 3 : col * 3 + 3]
    return (r + g + b) / 3, max(r, g, b) - min(r, g, b)


def _inside(rect: tuple[int, int, int, int], col: int, row: int) -> bool:
    c0, r0, c1, r1 = rect
    return c0 <= col < c1 and r0 <= row < r1


def classify(name: str, grid: list[str], tone: list[bytes]) -> Classified:
    height, width = len(grid), len(grid[0])
    fix = CORRECTIONS.get(name, Corrections())

    def paper(col: int, row: int) -> bool:
        if grid[row][col] != "1":
            return False
        if any(_inside(r, col, row) for r in fix.keep):
            return False
        if any(_inside(r, col, row) for r in fix.remove):
            return True
        luma, chroma = _luma_chroma(tone, col, row)
        return luma >= PAPER_MIN_LUMA and chroma <= PAPER_MAX_CHROMA

    is_paper = [[paper(c, r) for c in range(width)] for r in range(height)]
    result = Classified(grid=grid, tone=tone)

    queue: deque[Cell] = deque()
    for r in range(height):
        for c in range(width):
            if (r in (0, height - 1) or c in (0, width - 1)) and is_paper[r][c]:
                result.exterior.add((c, r))
                queue.append((c, r))
    while queue:
        c, r = queue.popleft()
        for dc, dr in _STEPS:
            n = (c + dc, r + dr)
            if (
                0 <= n[0] < width
                and 0 <= n[1] < height
                and is_paper[n[1]][n[0]]
                and n not in result.exterior
            ):
                result.exterior.add(n)
                queue.append(n)

    seen = set(result.exterior)
    for r in range(height):
        for c in range(width):
            if not is_paper[r][c] or (c, r) in seen:
                continue
            component, queue = {(c, r)}, deque([(c, r)])
            seen.add((c, r))
            while queue:
                a, b = queue.popleft()
                for dc, dr in _STEPS:
                    n = (a + dc, b + dr)
                    if (
                        0 <= n[0] < width
                        and 0 <= n[1] < height
                        and is_paper[n[1]][n[0]]
                        and n not in seen
                    ):
                        seen.add(n)
                        component.add(n)
                        queue.append(n)
            forced = any(any(_inside(rect, a, b) for rect in fix.remove) for a, b in component)
            if forced or len(component) >= HOLE_MIN_CELLS:
                result.holes.append(component)
                continue
            if len(component) < 2:
                result.kept_specks += 1
                continue
            border = {
                (a + dc, b + dr)
                for a, b in component
                for dc, dr in _STEPS
                if 0 <= a + dc < width
                and 0 <= b + dr < height
                and (a + dc, b + dr) not in component
            }
            lit = sum(1 for a, b in border if grid[b][a] == "1") / len(border)
            if lit < HOLE_MAX_LIT_NEIGHBOURS:
                result.holes.append(component)
            else:
                result.kept_specks += 1

    background = result.background
    for rim in fix.rims:
        c0, r0, c1, r1 = rim.rect
        for r in range(r0, r1):
            for c in range(c0, c1):
                if (c, r) not in background:
                    continue
                near = any(
                    0 <= c + dc < width
                    and 0 <= r + dr < height
                    and (c + dc, r + dr) not in background
                    for dr in range(-rim.width, rim.width + 1)
                    for dc in range(-rim.width, rim.width + 1)
                )
                if near:
                    result.rim[(c, r)] = rim.alpha
    return result


# ---------------------------------------------------------------------------- render


def render(cls: Classified, variant: str) -> bytes:
    """Gray+alpha PNG: white glyphs, alpha = original glyph luminance (x rim alpha)."""
    grid, tone = cls.grid, cls.tone
    height, width = len(grid), len(grid[0])
    background = cls.background if variant == "cutout" else set()
    rows = [bytearray(width * CELL_W * 2) for _ in range(height * CELL_H)]
    for r in range(height):
        for c in range(width):
            ch = grid[r][c]
            if ch == " ":
                continue
            scale = 1.0
            if (c, r) in background:
                if (c, r) not in cls.rim:
                    continue
                scale = cls.rim[(c, r)]
            luma, _ = _luma_chroma(tone, c, r)
            alpha = min(255, round(luma * scale / ALPHA_STEP) * ALPHA_STEP)
            for gy, line in enumerate(GLYPHS[ch]):
                row = rows[r * CELL_H + gy]
                for gx, px in enumerate(line):
                    if px == "#":
                        i = (c * CELL_W + gx) * 2
                        row[i], row[i + 1] = 255, alpha
    return write_png(width * CELL_W, height * CELL_H, 4, [bytes(r) for r in rows])


# ----------------------------------------------------------------------- orchestration


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_source(name: str) -> tuple[bytes, bytes, list[str], list[bytes]]:
    txt = (SOURCE_DIR / f"{name}.txt").read_bytes()
    tone_png = (SOURCE_DIR / f"{name}.tone.png").read_bytes()
    grid = read_grid(txt.decode("ascii"))
    width, height, tone = read_rgb_png(tone_png)
    if (width, height) != (len(grid[0]), len(grid)):
        raise ValueError(f"{name}: tone map does not match the grid")
    return txt, tone_png, grid, tone


def build_all() -> dict[Path, bytes]:
    outputs: dict[Path, bytes] = {}
    entries = []
    for name in NAMES:
        txt, tone_png, grid, tone = load_source(name)
        cls = classify(name, grid, tone)
        cutout, field_png = render(cls, "cutout"), render(cls, "field")
        outputs[OUTPUT_DIR / f"{name}.cutout.png"] = cutout
        outputs[OUTPUT_DIR / f"{name}.field.png"] = field_png
        entries.append(
            {
                "name": name,
                "cols": len(grid[0]),
                "rows": len(grid),
                "width": len(grid[0]) * CELL_W,
                "height": len(grid) * CELL_H,
                "sourceSha256": sha256(txt),
                "toneSha256": sha256(tone_png),
                "cutoutSha256": sha256(cutout),
                "fieldSha256": sha256(field_png),
                "exteriorCells": len(cls.exterior),
                "holeCount": len(cls.holes),
                "holeCells": sum(len(h) for h in cls.holes),
                "keptSpecks": cls.kept_specks,
                "rimCells": len(cls.rim),
            }
        )
    body = json.dumps(entries, indent=2)
    fields = [("name", "CharacterName")] + [
        (key, "string" if key.endswith("Sha256") else "number")
        for key in entries[0]
        if key != "name"
    ]
    lines = [
        "// Generated by scripts/build_ascii_art.py. Do not edit by hand.",
        "// Sources: frontend/art/source, copied from the untouched design references.",
        "",
        "export type CharacterName =",
        *(f'  | "{n}"' + (";" if n == NAMES[-1] else "") for n in NAMES),
        "",
        "export interface CharacterArt {",
        *(f"  {key}: {kind};" for key, kind in fields),
        "}",
        "",
        f"export const CHARACTERS = {body} as const satisfies readonly CharacterArt[];",
        "",
    ]
    outputs[MANIFEST] = "\n".join(lines).encode()
    css = [
        "/* Generated by scripts/build_ascii_art.py. Do not edit by hand. */",
        "/* One class per character and variant: the mask image and its aspect ratio. */",
    ]
    for entry in entries:
        for variant in ("cutout", "field"):
            css += [
                "",
                f".art-{entry['name']}-{variant} {{",
                f'  --art-src: url("/art/chars/{entry["name"]}.{variant}.png");',
                f"  aspect-ratio: {entry['width']} / {entry['height']};",
                "}",
            ]
    outputs[STYLESHEET] = ("\n".join(css) + "\n").encode()
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("extract", "build", "check"))
    args = parser.parse_args(argv)
    if args.command == "extract":
        SOURCE_DIR.mkdir(parents=True, exist_ok=True)
        for name in NAMES:
            txt, tone_png = extract(name)
            (SOURCE_DIR / f"{name}.txt").write_bytes(txt)
            (SOURCE_DIR / f"{name}.tone.png").write_bytes(tone_png)
            print(f"{name}: txt {sha256(txt)[:12]}  tone {sha256(tone_png)[:12]}")
        return 0
    outputs = build_all()
    if args.command == "check":
        stale = [p for p, data in outputs.items() if not p.exists() or p.read_bytes() != data]
        for p in stale:
            print(f"out of date: {p.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale else 0
    for path, data in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(f"wrote {path.relative_to(ROOT)} ({len(data):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
