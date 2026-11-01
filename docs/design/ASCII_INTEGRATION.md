# Bytasm — ASCII Character Integration

Status: D1 approved 2026-11-01 (`cutout` default). §3.4 records the corrected
extraction (enclosed openings, owner-annotated screenshots of 2026-11-01), implemented in
`scripts/build_ascii_art.py` for M1. Measurements below come from parsing the actual files in
`docs/design/references/frontend-characters-ascii/`. Derivation prototypes were run in
a scratch directory only; nothing was written to the repository except these docs.

## 1. Philosophy

The eight characters are **material, not mascots**. They behave like light leaking
into the workstation: a figure emerging at a hero edge, a fragment in an empty
state, a silhouette crossing a section boundary. They are never a gallery, never a
row of eight cards, never an avatar, and never placed next to a specific sample's
data in a way that could read as a verdict.

Three tests for every placement:
1. **Does the composition improve?** If the slot is just empty, leave it empty.
2. **Does any real text lose contrast?** If yes, move or dim the figure.
3. **Could the figure be read as a statement about this sample?** If yes, remove it.

## 2. Inspection results

| Property | Finding | Consequence |
|---|---|---|
| Glyphs | `1`, `0`, space only; ~80 % `1` | Art is fully described by the TXT grid |
| Polarity | White-paper engraving → `1` field; ink → space; mid-tones → `0` | As-shipped renders a **dark figure carved out of a grey binary field** |
| SVG structure | 1 black `<rect>` + 27,899–35,441 `<text>` nodes, each with its own `rgb()` fill | Too heavy for the DOM (2 MB, 30k nodes); the per-glyph tone adds little over the TXT |
| SVG font | `Share Tech Mono` via Google Fonts `@import` | Blocked by CSP (`guards.py`: `default-src 'self'`), so it falls back to system mono. Never ship as-is |
| PNG | RGBA, alpha = 255 everywhere, black baked in | Cannot composite over surfaces; usable only as a visual-test baseline |
| TXT | 41 KB raw / ~7 KB gzip; grids 213×192 or 226×181 | Ideal build input |
| Duplicates | `ascii-art.txt` ≡ `ascii-nohead-bw.txt` | Ignore `ascii-art.txt` |

## 3. The polarity decision

The boards (asset-7, -8, -9) show **bright** binary figures on black, and that is
the look the brief describes ("figures emerging from dark backgrounds"). The
delivered assets are the **inverse**. Three treatments follow, all derived
deterministically from the unmodified TXT. All three were rendered for all eight
characters and compared side by side with the raw engraving and the shipped ASCII PNG
(review page: DESIGN_SYSTEM §2.8, section 04, with 1× crops).

Shared first step for `lit` and `cutout`: parse the TXT into a grid and flood-fill
`1` cells 4-connected from the border. Those cells are **background**. Every remaining
cell is **figure** (measured: mystic 38 %, automaton 41 %, crow 46 %, nohead 46 %,
wizard 46 %, scavenger 49 %, muerte 50 %, executioner 58 % of cells).

### 3.1 Variant `field`: original polarity (no reinterpretation)

The full grid, rendered light-on-transparent. The figure is a dark void inside a
lit binary field. To avoid a visible rectangle, the field's outer edges are faded
with a radial or edge mask, so only a halo of binary surrounds the silhouette.

- Fidelity: exact.
- Look: "the figure is the absence of signal". Strong for heroes and 404, eerie.
- Cost: the field is dense. Even at 12 % opacity it reads as texture behind text, so
  never put text over it.

### 3.2 Variant `lit`: inverted figure (validated, **not recommended**)

Inside the figure, density is mapped inversely: space → bright `1`, `0` → mid `0`,
enclosed `1` → dim `1`. Background cells are dropped.

Visual validation result: the silhouettes read, but the interior is a **tonal
negative** of the engraving. Highlights go dark and ink glows: the crow becomes a pale
bird, the skulls' eye sockets light up, the wizard's robe loses its folds, the
mystic's halo dims. That is a reinterpretation of the artwork, not a presentation of it.

### 3.3 Variant `cutout`: original tones, background removed (**recommended default**)

Inside the figure, the original mapping is kept: `1` (paper) bright, `0` mid, space
(ink) empty. Background cells are dropped.

Visual validation result: every character reads the right way round, as a pale
engraved figure on black, which is the boards' look. Hatching, faces, skulls, the
armillary sphere, the lantern and the halo keep their structure. It is a little
quieter than `lit` because dark-ink figures (crow, executioner) carry fewer glyphs,
which suits the 80/20 restraint.

This is a **presentation derivative**, not a regeneration: glyphs and positions come
from the original grid, and only background removal differs.

Decision D1 (approved 2026-11-01): `cutout` is the default for all placements;
`field` is kept for one or two dramatic moments (landing evidence band, 404); `lit` is
not shipped.

### 3.4 Enclosed openings: the corrected extraction

**Defect.** The first `cutout` removed only background reachable from the grid border.
Paper enclosed by the silhouette (between the horse's legs, inside the automaton's wheel,
under the scavenger's saw, between cloak and sword, the gaps of the armillary sphere)
was kept as solid `1` fields. The owner's annotated screenshots marked these regions on
all eight characters. A second, inverse defect existed too: lit artwork that touched the
outside paper through `1` cells (the wizard's flame, the crow's lower skull, the
executioner's axe blade) was flood-filled away as background.

**Why a flood fill cannot fix it.** The TXT has three symbols only. Paper and a lit
highlight inside the figure are both `1`, so connectivity alone cannot tell an opening
from a highlight.

**The discriminating evidence.** The original SVG keeps each glyph's tone, sampled from
the engraving. The engravings were drawn on **neutral pure-white paper**, while lit parts
of the figures are **cream or grey**. Measured over the exterior background of all eight
characters: luminance p5 ≥ 249, chroma p95 ≤ 2. Lit figure cells: luminance median
215–253, chroma median up to 17.

**Algorithm** (deterministic, `scripts/build_ascii_art.py`):
1. A cell is *paper* when it is a `1` with luminance ≥ 246 and chroma ≤ 4.
2. *Exterior* = paper reachable from the border through paper cells (4-connected).
   Cream artwork touching the outside is no longer removed.
3. Every other paper component is a candidate *opening*:
   - ≥ 20 cells: always an opening;
   - 2–19 cells: an opening when fewer than 50 % of its neighbours are lit `1` cells
     (it sits in ink or mid-tones, like a strap gap), otherwise a highlight and kept;
   - single cells: kept (too ambiguous to remove).
4. `CORRECTIONS` in the script holds explicit per-character keep/remove rectangles for
   cases the rule gets wrong. None were needed for the eight characters; the only entry
   is the mystic raven rim (§3.5).

No global brightness, opacity or dark-region erasure is involved: only paper cells are
ever removed (enforced by a test), and every retained cell keeps its original glyph and
tone.

| Character | Openings removed | Opening cells | Highlight specks kept |
|---|---|---|---|
| wizard | 29 | 488 | 23 |
| crow | 10 | 137 | 26 |
| nohead | 16 | 1,425 | 12 |
| mystic | 36 | 963 | 61 |
| scavenger | 39 | 3,763 | 70 |
| automaton | 45 | 3,369 | 72 |
| executioner | 14 | 820 | 27 |
| muerte | 13 | 2,773 | 14 |

Validation: side-by-side review against the raw engraving, the shipped ASCII PNG and the
previous `cutout` on a checkerboard (true alpha), plus regression tests that pin cells in
each annotated opening as transparent and cells of restored artwork as kept
(`backend/tests/unit/test_ascii_art.py`).

### 3.5 The mystic's raven

The raven on the mystic's hand is drawn as **solid black ink** in the engraving, with
only a few hatched feather highlights. The ASCII conversion maps ink to spaces, so the
TXT holds the bird mostly as empty cells (in its 62 × 50 cell region: 818 spaces, 259
`0`, and the rest paper `1`). In `cutout` empty cells render nothing, so the bird was
defined only by the absence of glyphs against an equally empty background: it vanished.
The standalone crow keeps its form because its engraving has much more mid-tone
hatching, which became `0` glyphs.

So the information was not lost to segmentation, resolution or WebP downsampling: the
silhouette survives in the TXT as the boundary between ink and paper, but its interior
detail was already lost in the original binary conversion.

Local, deterministic improvement (implemented): a **rim** of the original paper glyphs,
two cells wide and at 60 % of their tone, is kept around the figure inside the raven's
cell rectangle only (`CORRECTIONS["mystic"]`, 587 cells). The raven now reads as a dark
silhouette outlined by its own surrounding binary, which is how the shipped ASCII PNG
shows it. Nothing is redrawn and no glyph is added. If more detail is wanted, the fix
belongs in the source illustration and its conversion, not in this derivative.

## 4. Rendering approaches

| Approach | Fidelity | Weight | Tintable | A11y / selection | Verdict |
|---|---|---|---|---|---|
| A. Original SVG inline | High (per-glyph tone) | 2 MB, 30k nodes | Hard | Must `aria-hidden` 30k nodes | **Reject** |
| B. Original SVG as `<img>` | High, font falls back | 2 MB per image, slow raster | No | OK | Reject |
| C. TXT in `<pre>` with real text | Exact chars; one tone (or 3 tones via spans) | ~7 KB gzip; ~41k chars layout | Yes (CSS `color`) | Must be `aria-hidden`, `user-select:none`; real text inflates page text search (Ctrl F hits "1") | Use for **small fragments and motion** only |
| D. Pre-rendered **alpha PNG** from TXT + tone (build script) + CSS `mask-image` | Exact chars, crisp at 1x | 59–86 KB | **Yes:** used as a mask over any `background-color` / gradient | `<div aria-hidden>`; no text-search pollution | **Default, implemented in M1** |
| E. Canvas at runtime from TXT | Exact | ~7 KB + JS | Yes | aria-hidden | Use only for the reconstruction animation (§8) |

### 4.1 Default: mask technique (D)

```css
.binary-art {
  aspect-ratio: var(--art-aspect);            /* 1022/1536 or 1084/1448 */
  background: var(--art-tint, var(--art-ink));
  -webkit-mask: var(--art-src) center / contain no-repeat,
                var(--art-fade);              /* second layer = soft edge */
          mask: var(--art-src) center / contain no-repeat,
                var(--art-fade);
  mask-composite: intersect;
  pointer-events: none;
  user-select: none;
}
```

- The PNG is white glyphs on transparent. The element's background colour or
  gradient becomes the glyph colour. Tint is a token, so the same file produces
  off-white, cool grey, or purple-tinged figures without recolouring the asset.
- Mixed treatment ("grayscale with selective purple") = background
  `linear-gradient(to bottom, var(--art-ink) 0 40%, var(--art-signal) 82%, var(--art-orchid))`.
  The head and torso stay warm off-white, the lower hem turns electric purple and the
  last cells catch orchid. Magenta is not used in figures by default; one hero may use
  it as a single spark (e.g. the wizard's flame) if the screen has no other magenta.
- `--art-fade` is a `radial-gradient` or `linear-gradient` mask that dissolves the
  edge facing content, so there is never a hard rectangle.
- CSP: `mask-image: url(/art/…)` falls under `img-src 'self'`, so it is allowed. Custom
  properties carry the URL from a class, not an inline `style` attribute, because
  `style-src 'self'` blocks inline style attributes in markup. React `style={{}}` sets
  CSSOM and is fine, but classes per character are simpler and testable.

### 4.2 Real-text fragments (C)

For tiny decorative crops (≤ 40×20 cells, e.g. a crow head in an empty state, a
binary rule in the footer) and for motion, render a slice of the TXT in a `<pre
aria-hidden="true" class="ascii-fragment">` with `font: 8px/8px var(--font-mono)`,
`letter-spacing` tuned so the advance is 4.8 px (0.6 em). Crops are defined in
`characters.ts` as cell rectangles, so they stay faithful to the source.

## 5. Transparency, recolouring, compositing

- Never use `mix-blend-mode: screen` on the original black-background PNG as a
  shortcut. It brightens surfaces unevenly and fails on non-black surfaces.
- Tint tokens: `--art-ink` (`#E6E2DA`, warm off-white), `--art-ash` (`#6C6B76`, cool
  grey), `--art-signal` (`#A454FC`, = `--signal-400`), `--art-orchid` (`#D46BF2`),
  `--art-ghost` (`#2A2833`, barely visible on `--void`).
- Opacity is set by placement (§9), not globally. Typical range 0.18–0.9.
- Layering order inside a hero: `--void` or `--plum-950` background → noise texture (≤ 4 % opacity)
  → figure → hero gradient scrim on the text side → text. Text never sits on the figure.

## 6. Scaling

- Glyph pitch at 1x is 4.8 × 8 px. Below about 0.6x, glyphs merge into grey dither and the
  binary nature disappears. **Minimum display height**: 640 px for full figures. Below
  that, use a crop (head/torso) rather than shrinking.
- M1 ships 1x masks only (5 × 8 px cells). A 2x export for the landing hero is M6 work; choose via `image-set()` inside the mask.
- Above 1.5x the glyphs read as large type, which works for landing hero crops.
- Crops are expressed in **cells**, not pixels, so 1x/2x stay aligned.

## 7. Responsive behaviour

| Breakpoint | Hero figure | Section bleed | Empty-state fragment |
|---|---|---|---|
| ≥ 1280 | Full figure, right 45 %, bleeding off bottom | Visible | Crop ≈ 220 px tall |
| 768–1279 | Torso crop, right 40 %, 0.7 opacity | Visible, narrower | Same |
| < 768 | Head crop *behind* the headline top-right at 0.25, or hidden | Hidden | Hidden or 120 px |
| 360 (e2e `responsive.spec.ts`) | No horizontal overflow, ever | — | — |

Art containers use `overflow: clip` and `contain: paint` so bleed never widens the page.

## 8. Motion (optional, off by default in working screens)

| Effect | Implementation | Where | Duration |
|---|---|---|---|
| **Binary reconstruction** | Canvas (E) draws cells in randomised order, 3 frames per cell group; final frame swaps to the static mask element | Landing hero, once per visit | ≤ 1.2 s |
| Progressive reveal | Mask `linear-gradient` position animated bottom→top | Section transitions, on scroll into view | 600 ms |
| Decode flicker | `<pre>` fragment cycles `0/1` on ≤ 3 % of cells for 400 ms | Empty state first paint | 400 ms, once |
| Rare glitch | 2-frame horizontal slice offset (CSS `clip-path` + `translate`) | Landing only, on hover of hero CTA | 120 ms |

Rules:
- `@media (prefers-reduced-motion: reduce)`: render the final frame and run no motion
  (the existing stylesheet already zeroes animations at `styles.css:600`).
- A **"Reduce atmosphere"** toggle in the command palette and the status bar menu
  sets `data-atmosphere="off"` on `<html>` (stored in `localStorage`). This hides
  decorative art in working screens and disables all motion. Landing keeps static art.
- No continuous loops. No animation on screens with live run polling (RunPage).

## 9. Placements: all eight, organically

All eight characters are integrated, each in the context its symbolism fits (ART_DIRECTION
§8). They appear one at a time, never as a set. Assets for all eight are built in M1;
placements follow the screens each milestone restyles.

| Placement | Character | Variant / tint / opacity | Milestone | Notes |
|---|---|---|---|---|
| Projects (empty) | `crow` crop | cutout, ink→signal hem, 0.7 | **M1** | "No projects yet. Create a project." |
| Project page (no samples) | `scavenger` crop | cutout, ash, 0.6 | **M1** | "No samples yet. Import a binary." |
| 404 | `nohead` | field, ash, 0.5 | **M1** | "Nothing lives at this address." |
| Run: no rule matched | `crow` head crop | cutout, ghost, 0.5 | M2 | Copy must say "no rule matched", never "clean"; below the findings table, not inside it |
| Strings tab empty | `scavenger` torso crop | cutout, ghost, 0.4 | M2 | Use instead of the Project placement if both would show in one flow |
| Tools: Ghidra unavailable | `automaton` crop | cutout, ghost, 0.45 | M2 | Next to setup instructions |
| Intake rejected (policy) | `executioner`, **very** dim | cutout, ghost, 0.25 | M2 | Drop if it feels punitive in review |
| Run timed out / cancelled | `muerte` fragment | cutout, ghost, 0.3 | M2 | Page foot, outside the step list; never beside a sample's data |
| Annotations empty | `mystic` crop | cutout, ash, 0.5 | M3 | "No notes yet." |
| Landing hero | `wizard` (alt: `nohead`) | cutout, ink→signal→orchid, 0.9 | M6 | Full figure bleeding off the bottom-right; headline left |
| Landing "evidence first" band | `nohead` | field, ash, 0.35 | M6 | Crossing the boundary between two sections |
| Landing closing / footer | `muerte` | cutout, ghost, 0.5 | M6 | Small, right, with ASCII rule |
| App shell rail bottom | none by default | — | — | Asset-7 puts figures in the sidebar. Rejected: always visible means always noise |

**Never:** inside RunPage findings, evidence drawer, VersionPage metadata,
Compare diff, Ghidra workspace, ByteViewer, pinned-review preview, exported reports.

## 10. Good vs bad integration

| Good | Bad |
|---|---|
| Wizard occupies the hero's right half, fades into `--void` at the left and bottom; headline sits on clean black | Wizard centred behind the headline at 40 % |
| Crow head crop, 160 px, bottom-right of an empty table, with one-sentence copy and a single button | All eight figures as a "meet the characters" grid |
| One figure per screen, varying tint per placement | Same purple tint and opacity everywhere |
| Figure cut by a section boundary, half in each section | Figure inside a bordered card with a black rectangle |
| Static on working screens | Reconstruction animation on every navigation |

## 11. Accessibility

- All art is decorative: `aria-hidden="true"` on the container, no `alt` text needed
  (or `alt=""` if an `<img>` is ever used), `role="presentation"` on canvases.
- Not focusable, `pointer-events: none`, `user-select: none`.
- No art under body text. Measured contrast of text against the *brightest* glyph
  behind it must still be ≥ 4.5:1, enforced by keeping text on scrims.
- Real-text `<pre>` fragments are kept tiny so browser find (`Ctrl F`) is not flooded with `1`.
- Windows High Contrast / `forced-colors: active`: hide art entirely.

## 12. Performance budget

| Item | Budget |
|---|---|
| Landing hero art | ≤ 160 KB (2x mask) + optional ≤ 3 KB canvas script |
| Per working screen | ≤ 1 art asset, ≤ 60 KB, `loading` deferred until idle |
| DOM | No art element > 50 nodes |
| Paint | Art layers use `contain: strict` where sized; no `filter: blur` over art |

## 13. Preservation of source artwork

- `docs/design/references/frontend-characters-ascii/*` and `frontend-characters-raw/*` are read-only.
- Derived outputs are produced by `scripts/build_ascii_art.py` from committed copies of
  the TXT plus a per-cell tone map extracted from the SVG (VISUAL_ASSET_GUIDE §6). The
  script is deterministic: same input bytes give the same output bytes, with every
  source and output SHA-256 recorded in `characters.ts`.
- `backend/tests/unit/test_ascii_art.py` checks: committed outputs equal a fresh build;
  builds are byte-identical; sources match the untouched references (when present);
  only paper cells are ever removed; every retained `cutout` glyph is identical to the
  same cell in `field`; the annotated openings are transparent; artwork touching the
  outside is kept; the raven rim stays inside its rectangle.
