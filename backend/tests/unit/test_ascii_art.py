"""The character art derivation (scripts/build_ascii_art.py): committed masks are
reproducible from the committed sources, only background is removed, and the
openings the owner marked on 2026-11-01 are transparent while artwork stays."""

import importlib.util
import struct
import sys
import zlib
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "build_ascii_art.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_ascii_art", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_ascii_art"] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


art = _load()
NAMES: tuple[str, ...] = art.NAMES


def _decode_gray_alpha(data: bytes) -> tuple[int, int, list[bytes]]:
    pos, idat, width, height = 8, b"", 0, 0
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kind, body = data[pos + 4 : pos + 8], data[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, color_type = struct.unpack(">IIBB", body[:10])
            assert (depth, color_type) == (8, 4)
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw, stride = zlib.decompress(idat), width * 2 + 1
    return width, height, [raw[y * stride + 1 : (y + 1) * stride] for y in range(height)]


def _cell_alpha(rows: list[bytes], col: int, row: int) -> list[int]:
    out: list[int] = []
    for y in range(row * art.CELL_H, (row + 1) * art.CELL_H):
        line = rows[y]
        out.extend(line[(col * art.CELL_W + x) * 2 + 1] for x in range(art.CELL_W))
    return out


@pytest.fixture(scope="module")
def built() -> dict[Path, bytes]:
    outputs: dict[Path, bytes] = art.build_all()
    return outputs


@pytest.fixture(scope="module")
def classified() -> dict[str, object]:
    out: dict[str, object] = {}
    for name in NAMES:
        _txt, _tone, grid, tone = art.load_source(name)
        out[name] = art.classify(name, grid, tone)
    return out


def test_committed_outputs_match_a_fresh_build(built: dict[Path, bytes]) -> None:
    stale = [p for p, data in built.items() if not p.exists() or p.read_bytes() != data]
    assert stale == [], "run: python3 scripts/build_ascii_art.py build"


def test_build_is_deterministic(built: dict[Path, bytes]) -> None:
    assert art.build_all() == built


@pytest.mark.skipif(
    not (art.REFERENCES / "ascii-crow-bw.txt").exists(),
    reason="design references are not in the repository (decision D6)",
)
@pytest.mark.parametrize("name", NAMES)
def test_committed_sources_match_the_untouched_references(name: str) -> None:
    txt, tone_png = art.extract(name)
    assert (art.SOURCE_DIR / f"{name}.txt").read_bytes() == txt
    assert (art.SOURCE_DIR / f"{name}.tone.png").read_bytes() == tone_png


@pytest.mark.parametrize("name", NAMES)
def test_background_is_only_ever_paper(name: str, classified: dict[str, object]) -> None:
    cls = classified[name]
    for col, row in cls.background:  # type: ignore[attr-defined]
        assert cls.grid[row][col] == "1"  # type: ignore[attr-defined]
        luma, chroma = art._luma_chroma(cls.tone, col, row)  # type: ignore[attr-defined]
        assert luma >= art.PAPER_MIN_LUMA
        assert chroma <= art.PAPER_MAX_CHROMA


@pytest.mark.parametrize("name", NAMES)
def test_cutout_keeps_field_glyphs_except_background(
    name: str, built: dict[Path, bytes], classified: dict[str, object]
) -> None:
    cls = classified[name]
    _w, _h, cutout = _decode_gray_alpha(built[art.OUTPUT_DIR / f"{name}.cutout.png"])
    _w, _h, field = _decode_gray_alpha(built[art.OUTPUT_DIR / f"{name}.field.png"])
    background = cls.background  # type: ignore[attr-defined]
    rim = cls.rim  # type: ignore[attr-defined]
    grid = cls.grid  # type: ignore[attr-defined]
    for row in range(len(grid)):
        for col in range(len(grid[0])):
            c, f = _cell_alpha(cutout, col, row), _cell_alpha(field, col, row)
            if (col, row) in background and (col, row) not in rim:
                assert not any(c), f"{name} {col},{row} should be transparent"
            elif (col, row) not in background:
                assert c == f, f"{name} {col},{row} should keep its original glyph"


# Cells inside openings marked on the owner's annotated screenshots (2026-11-01).
OPENINGS = {
    "muerte": [(121, 154), (160, 159)],  # between the horse's legs
    "automaton": [(108, 114), (79, 105)],  # wheel spokes, beside the crossbow
    "scavenger": [(57, 162), (123, 141)],  # under the saw, between the legs
    "executioner": [(58, 155), (120, 155), (63, 71)],  # between the legs, under the arm
    "nohead": [(110, 150), (168, 150)],  # between the legs and the cloak hem
    "wizard": [(105, 158)],  # between the feet
    "crow": [(114, 90)],  # between the raven's legs
    "mystic": [(59, 99), (71, 78)],  # beside the left arm
}
# Lit artwork the first derivation erased because it touched the outside paper.
RESTORED = {"wizard": (188, 9), "crow": (188, 133), "executioner": (203, 47)}


@pytest.mark.parametrize("name", NAMES)
def test_marked_openings_are_transparent(name: str, classified: dict[str, object]) -> None:
    background = classified[name].background  # type: ignore[attr-defined]
    for cell in OPENINGS[name]:
        assert cell in background


@pytest.mark.parametrize("name", sorted(RESTORED))
def test_artwork_touching_the_outside_is_kept(name: str, classified: dict[str, object]) -> None:
    assert RESTORED[name] not in classified[name].background  # type: ignore[attr-defined]


def test_mystic_raven_rim_is_local(classified: dict[str, object]) -> None:
    (rim,) = art.CORRECTIONS["mystic"].rims
    c0, r0, c1, r1 = rim.rect
    cells = classified["mystic"].rim  # type: ignore[attr-defined]
    assert cells
    assert all(c0 <= c < c1 and r0 <= r < r1 for c, r in cells)
    for name in NAMES:
        if name != "mystic":
            assert not classified[name].rim  # type: ignore[attr-defined]


def test_manifest_lists_every_character(built: dict[Path, bytes]) -> None:
    manifest = built[art.MANIFEST].decode()
    for name in NAMES:
        assert f'"name": "{name}"' in manifest
