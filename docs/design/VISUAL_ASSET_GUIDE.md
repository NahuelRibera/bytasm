# Bytasm — Visual Asset Guide

Status: inventory taken 2026-10-31 by opening every file listed below (images
viewed, SVG/TXT parsed); colour measurements of the boards and derivation renders
added 2026-11-01. Originals are untouched. All paths are relative to
`docs/design/references/`. The directory is currently **untracked** in git.

## 1. Inventory summary

| Directory | Files | Formats | Total | Role |
|---|---|---|---|---|
| `fronted-assets-goth/` | `asset-1` … `asset-10` | PNG 1536×1024 (1–6), 1672×941 (7–10) | ~24 MB | Primary graphic exploration (inspiration only) |
| `fronted-features-raw/` | `frontend-ref-1` … `-13` | PNG, mostly 2940×1912 retina screenshots | ~20 MB | Functional / structural references (inspiration only) |
| `frontend-characters-ascii/` | 8 characters × PNG/SVG/TXT + `ascii-art.txt` | PNG, SVG, TXT | ~17 MB SVG + ~11 MB PNG | **Production source** for the identity |
| `frontend-characters-raw/` | 8 PNG engravings | PNG ~1086×1448 | ~20 MB | Fidelity reference only (not shipped) |

Housekeeping findings:
- The two reference directory names are spelled `fronted-…` (missing `n`). Keep as-is
  while they are references, and use correct spelling for production paths (§6).
- `frontend-characters-raw/` contains a `.DS_Store`. Exclude it if the references are ever committed.
- `ascii-art.txt` is **byte-identical** to `ascii-nohead-bw.txt` (verified with `cmp`). It is a
  duplicate, not a ninth character.
- Reference size (~90 MB of PNG/SVG) argues against committing the boards to the main
  repository without Git LFS (open decision D6).

## 2. Characters

### 2.1 Inventory

| Name | ASCII PNG | ASCII SVG (bytes / `<text>` nodes) | TXT grid (cols×rows) | Raw engraving |
|---|---|---|---|---|
| automaton | 1022×1536 | 2,332,865 / 35,441 | 213×192 | crowned bell automaton, crossbow, chains |
| crow | 1084×1448 | 1,956,547 / 29,764 | 226×181 | raven on two skulls and rubble |
| executioner | 1022×1536 | 1,834,939 / 27,899 | 213×192 | hooded axe-bearer, chained wolf |
| muerte | 1084×1448 | 2,011,301 / 30,574 | 226×181 | hooded reaper on horseback, scythe |
| mystic | 1084×1448 | 2,158,693 / 32,828 | 226×181 | sun-rayed halo, censer, raven on hand |
| nohead | 1084×1448 | 2,069,936 / 31,468 | 226×181 | headless knight, sword, lantern |
| scavenger | 1022×1536 | 2,116,101 / 32,130 | 213×192 | hunched collector, pack, rat, sickle |
| wizard | 1084×1448 | ~2.0 MB / 30,241 | 226×181 | hooded mage, armillary sphere, flame |

Two aspect families: **213×192 cells** (1022×1536 px, 2:3) and **226×181 cells**
(1084×1448 px, 3:4). Any layout slot should accept either via `aspect-ratio` from data.

### 2.2 What the files actually are

- **Character set:** only `1`, `0` and space. `1` is about 80 % of glyphs.
- **Polarity:** the conversion is *positive* from a **white-background** engraving.
  The bright paper becomes a dense field of `1`. The figure's darkest ink becomes
  **spaces**, and mid-tones become `0`. Rendered as shipped, each image is a grey
  binary field with a **dark silhouette carved out of it**, not a bright figure on black.
  The gothic boards (asset-7/-8/-9 "character silhouettes") show the opposite: bright
  figures on black. This mismatch is the most important asset finding (see ASCII_INTEGRATION §3).
- **ASCII PNG:** RGBA, but alpha is 255 everywhere. The black background is baked in, so there is no transparency.
- **SVG:** one `<rect fill="#000000">` background, then one `<text>` per glyph with
  an individual `fill="rgb(r,g,b)"` (near-white to dark grey). Glyph pitch 4.8 × 8 px
  at `font-size: 8px`. Font is `Share Tech Mono`, loaded by
  `@import url('https://fonts.googleapis.com/…')` inside the SVG. That import is
  **blocked by Bytasm's CSP** (`default-src 'self'`, `guards.py`) and would leak a request
  to Google anyway, so the SVG falls back to the system monospace. Glyphs are absolutely
  positioned, so the fallback changes glyph shape but not alignment.
- **TXT:** 41,086–41,087 bytes, about **7 KB gzipped**. This is the most compact and most
  faithful source: the art *is* the character grid.
- **Raw engravings:** high-contrast ink on white, consistent hatching style across all
  eight. Use them to judge silhouette fidelity of any derived variant. Do not display them.

### 2.3 Format verdicts

| Format | Ship to the browser? | Use |
|---|---|---|
| TXT | **Yes (source of truth)** | Build-time input for derived variants; optionally real-text `<pre>` rendering |
| SVG (as provided) | **No** | 30k DOM nodes / 2 MB each, black rect, external font. Keep as archival/editable source |
| ASCII PNG | No (except as visual baseline) | Golden reference for fidelity checks in visual tests |
| Raw PNG | No | Fidelity reference for designers |

## 3. Gothic boards (`fronted-assets-goth/`)

Boards asset-7 … asset-10 are the newest (modified 2026-10-31 18:13–18:14, the
others 16:12–16:15) and are the **primary colour reference** for D3. Measured by
sampling every 7th pixel (saturation > 0.45, value > 0.35):

| Board | Saturated share of area | Brightest violet (p85) | Orchid highlight | Neutral background (median value) |
|---|---|---|---|---|
| asset-7 | 2.8 % | `#922BFC` (h 270°) | `#D163EA` | 3.1 % |
| asset-8 | 3.4 % | `#A04FF8` (h 269°) | `#E351FE` | 3.5 % |
| asset-9 | 2.8 % | `#9442FB` (h 267°) | `#E14AFF` | 3.5 % |
| asset-10 | 1.7 % | `#9F3DFA` (h 271°) | `#CC39EF` | 3.1 % |

No board contains pink-magenta (hue 317–349°); the Signal palette's magenta is a deliberate addition.

| File | Content | Usable ideas | Reject |
|---|---|---|---|
| asset-1 | White-ground kit: banners, chains, lanterns, moon phases, compass stars, runic row, frames, castle scenes with violet clouds | Moon-phase sequence (as a 5-step progress glyph), compass-star, runic dividers (abstracted) | Banners, chains, lanterns, castle scenes in the app |
| asset-2 | Dark version of asset-1, plus waveform/radar/histogram instrumentation, matrix rain columns | Ratio of purple to black; radar reticle as a decorative empty-chart frame | Matrix rain; skull icons |
| asset-3 | Mono kit: line dividers with centre nodes, square glyph buttons, `ANALYZE/SCAN/EXPORT/RESET` buttons, segmented progress, `[01] C:\BYTASM\SCAN` list, side nav with vertical rule | **Divider with centre node**, **segmented progress**, **bracketed index list**, vertical-rule nav | Fake `C:\` paths |
| asset-4 | Purple UI kit: hero with serif wordmark, buttons, inputs, tags, steps, panels, terminal, table, tooltips, alerts | Component inventory, step list `Intake → Identify → Inspect → Analyze → Report`, terminal log layout, key-value panel | SAFE/SUSPICIOUS tags, Mach-O/ARM64, red entropy alert, entropy histogram |
| asset-5 | Mono dashboard composition: sidebar `[01] Overview`, sections table, entropy, imports, disassembly, strings, hex view, terminal, sections map | **Overall layout density**, section-map bar, strings list with offset column, hex view | "Analysis result: SUSPICIOUS", drop zone for Mach-O |
| asset-6 | Mono kit variant with H1–H4 serif headings, hero banner variants | Hero banner crop ratios (≈ 3.2:1), footer banner | Serif UI headings |
| asset-7 | **ASCII characters inside UI**: hero with bright ASCII figure, sidebar with figure, empty states with crow/ruins, character silhouette strip | **Hero composition**, empty-state fragments, footer strip, **colour balance** (purple only on primary button, active nav, selected step, chart marks, moon) | Figures behind sample/finding cards; "Characters" nav |
| asset-8 | Brand system, hero variants, dashboard, file card, finding card, charts, character motifs (named Automaton, Raven, Executioner, Pilgrim, Orrery, Cartographer, Scavenger, Sun Priest) | Hero split layout, file card structure, terminal | Severity donut, `+12 %` deltas, "Medium risk"; the board's character names differ from the files (use file names) |
| asset-9 | Wordmarks, isotypes, app icons, hero sections, promo banners, section headers `ANALYZE 01 / OBSERVE 02 / INTERPRET 03 / REPORT 04` | **Section header pattern with number**, isotype explorations, misc glyphs | Behaviour indicators, SAFE badge, "Suspicious APIs" |
| asset-10 | Full dashboard: global search `⌘K`, filter chips, sample table, relationship graph, hex view, docs panel, status timeline, report preview | **Command search**, **filter chips**, **status timeline**, report preview card | Malicious/Clean badges, CSV/PDF export, dynamic-behaviour graph, "risk: high" |

## 4. Functional references (`fronted-features-raw/`)

| File | Source | Take | Reject |
|---|---|---|---|
| frontend-ref-1 | "Fortexa" security dashboard (tilted mockup) | Mini-chart metric cards, dense table rhythm | Risk Score gauge, % risk metrics, multi-hue icons |
| frontend-ref-2 | "PD" detections table | **Faceted filter popover with counts**, removable filter chips, sticky uppercase headers, status pills with dot | Lorem reasoning column |
| frontend-ref-3 | Nordlys hero | Massive light sans headline with a grey second line, mono meta line, single CTA with arrow cell | Silk shader |
| frontend-ref-4/-5/-6 | Nordlys page index | **Numbered section heads (`Homepages ⁰⁴`)**, mono captions under thumbnails | — |
| frontend-ref-7 | Nordlys design system page | **Two typefaces, five colours, one button**, "violet only as light", motion vocabulary table | — |
| frontend-ref-8 | Nordlys metric strip | **Big numeral + mono caption** strip with hairline separators | — |
| frontend-ref-9/-10 | Nordlys footer wordmark | Status line `ALL SYSTEMS NORMAL · BUILD 26.10.05` as a real status bar idea | Shader-filled wordmark (could be an ASCII-filled wordmark instead, landing only) |
| frontend-ref-11/-12 | Nordlys contact form | Underline inputs with mono labels, grouped `A / B / C` form sections, "What happens next" numbered list | — |
| frontend-ref-13 | Nordlys menu | **Keyboard-toggled overlay menu** with right-aligned mono metadata, a model for the command palette | — |

## 5. Inspiration vs production

| Production asset (shipped) | Inspiration only |
|---|---|
| Derived `cutout` and `field` variants of the 8 TXT characters (§6) | Every board PNG |
| A small, hand-built SVG glyph set: crosshair, compass-star, centre-node rule, corner bracket, moon-phase 5-step (≤ 12 glyphs, 24 px grid, `currentColor`) | Banners, chains, lanterns, castles, candles, ruins, landscapes |
| A 1-tile binary-noise texture (generated from a TXT crop, ≤ 4 KB) | Grunge / paper textures from asset-9 "Textures" |
| Self-hosted Inter + JetBrains Mono WOFF2 | Share Tech Mono (SVG source font) |

Castle and ruin landscapes are the most "fantasy-game" element on the boards, and
they are not part of the eight-character system. Recommendation: **do not produce
them**. If a landing panorama is wanted later, build it from ASCII as well.

## 6. Production organisation (implemented in M1)

```
scripts/
  build_ascii_art.py           stdlib-only, deterministic: extract | build | check
frontend/
  art/source/                  committed build inputs (decision D6: references stay out)
    <name>.txt                 byte-identical copy of ascii-<name>-bw.txt
    <name>.tone.png            one RGB pixel per cell: each glyph's original SVG tone
  public/art/chars/            served same-origin (CSP img-src 'self')
    <name>.cutout.png          default mask: original tones, background and openings removed
    <name>.field.png           original polarity, every glyph kept
  src/art/
    characters.ts              generated manifest: sizes, SHA-256 of sources and outputs, counts
    characters.css             generated: one mask class per character and variant
    BinaryArt.tsx              the decorative component (aria-hidden, CSS-tinted mask)
  src/styles/fonts.css         Inter + JetBrains Mono variable WOFF2 (Latin, via Fontsource)
docs/design/references/        unchanged originals, untracked
```

Rules:
- Originals in `docs/design/references/` are never edited. `extract` only reads them;
  a test re-extracts and compares with `frontend/art/source/` whenever the references
  are present locally.
- `build` writes the masks, manifest and stylesheet; `check` (and the backend test suite)
  fails if any committed output differs from a fresh build. The PNG encoder is part of
  the script (zlib level 9, filter 0), so output bytes do not depend on an image library.
- Masks are white glyphs whose alpha is the original glyph tone in 16 steps, 5 × 8 px per
  cell: 59–86 KB each (1130 × 1448 or 1065 × 1536 px). No 2x yet; the landing (M6) will
  need one.
- No `lit` variant ships (rejected in validation, ASCII_INTEGRATION §3.2).
- No art ships in exported HTML reports (`reports/html.py` CSP is `img-src 'none'`).
  Report branding stays text-only.

## 7. Review renders (not production assets)

For decision D1 all eight characters were rendered as raw engraving, shipped ASCII PNG,
`field`, `lit`, `cutout` and `cutout` with the Signal tint, plus 1× crops, by a scratch
script that reads only the TXT grids and records each TXT's SHA-256. They live in the
review page (DESIGN_SYSTEM §2.8), not in the repository. The M1 build script
(`scripts/build_ascii_art.py`) produces the `field` and `cutout` outputs deterministically;
its corrected `cutout` (enclosed openings, ASCII_INTEGRATION §3.4) supersedes the review renders.

| Character | TXT SHA-256 (first 12) | Figure cells |
|---|---|---|
| wizard | `f0ce59f9353b` | 46.2 % |
| crow | `84d761aef5f3` | 45.8 % |
| nohead | `352e3e3262af` | 46.3 % |
| mystic | `6653f51aff60` | 37.7 % |
| scavenger | `4fa2d1c38f65` | 48.5 % |
| automaton | `aa328046f8d5` | 41.1 % |
| executioner | `3378ccbe4205` | 58.4 % |
| muerte | `ce800de22e09` | 49.8 % |
