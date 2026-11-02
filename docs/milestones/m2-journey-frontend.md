# M2 Journey frontend — 2026-11-02

Base: `feat/m1-frontend-foundation` at `06799ae` (M1 + 360 px filter-row fix). **Not committed.**
Direction: Engraved Signal, "Journey" synthesis (Concept B structure, Concept A atmosphere,
Concept C instrumentation; asset boards 7–10 as the visual authority). Product behaviour,
analysis semantics, API contracts, the CSP and safety policies are unchanged; no backend file
was modified. The parallel `feat/v0.10-evidence-intelligence` worktree was not touched.

## What changed

### Branding
- The approved isotipo (`frontend/public/branding/bytasm-icon.svg`, `.png`) is the brand mark,
  used **as delivered**: geometry, proportions and its own black field are untouched. The SVG is
  a pixel-traced single path (white arch, star and blackletter B on a black 1254² square); the
  PNG is the 1254² RGB raster it was traced from (no alpha). Same artwork, two encodings.
- Top bar: the SVG at 28 px plus a Cormorant Garamond "Bytasm" wordmark. Masthead kicker: 20 px.
  The mark is drawn as a CSS background on a `<span>` (not an `<img>`), so the existing security
  tests that assert "no `<img>` reached the DOM from file-derived text" keep their meaning.
- Favicon: SVG first; `public/branding/derived/` holds plain `sips -z` downscales of the PNG
  (32 px raster favicon fallback, 180 px apple-touch-icon) so a touch icon does not pull the
  523 KB original. `index.html` gains description, application-name and theme-color `#050507`.
- The provisional quadrant `BrandMark` (D5) is removed.

### Typography
- **Cormorant Garamond** (variable, Latin, roman only; OFL-1.1, self-hosted via Fontsource,
  `THIRD_PARTY_NOTICES.md` updated) for display and editorial titles only: masthead, page
  titles, section labels, card titles, band labels, specimen names. Inter stays for reading and
  controls, JetBrains Mono for every measured value. This supersedes ART_DIRECTION §6's "no serif
  in the UI" (owner-approved in the M2 brief).
- Tokens: `--font-display`, `--type-mast`, `--type-page`, `--type-section`.

### Navigation (hybrid)
- The 76/200 px rail is replaced by a sticky **top bar**: isotipo + wordmark, Projects / Rules /
  Tools (real routes only, active underline with signal glow), input-policy pill and API LED.
  Below 900 px the status cluster drops to a second row; below 480 px nav icons hide.
- **Breadcrumb trail** (`Breadcrumbs`, `nav[aria-label=Breadcrumb]`, `aria-current=page`) on
  Project, Import, Version, Run, Compare, Report and stored Rules pages; untrusted names
  ellipsize at 32ch (22ch on phones).
- **Section index** (`SectionIndex`) on Run and Version only: grouped Understand / Investigate
  (/ Record), anchor links that move focus, current section from scroll position (works for
  sections that render asynchronously). Sticky column ≥ 1100 px, collapsible block below.
- **Status bar** keeps "local · static analysis only", version, YARA-X version, Reduce
  atmosphere and the Limits disclosure; the policy moved to the top bar (no duplication).

### Journey masthead (Projects)
- `art/JourneyScene.tsx`: original SVG gothic city composed from architectural primitives
  (towers with set-back belfries, corner pinnacles, spires and finials; twin-tower cathedral
  with rose window and buttressed nave; gabled lower town; split watchtower and broken wall;
  a fainter back row for depth), engraved hatching, a moonlit rim offset, a lit-window scatter,
  far ridge, hill, rocks, road to the west gate and three drifting fog bands.
- Small dithered violet moon (r = 38 of a 1200 × 420 scene) behind the crossing spire, with an
  astrolabe halo: broken rings, a fine tick ring, a long partial arc, cardinal ticks, diamond nodes.
- `art/binaryField.tsx`: canvas field of 0/1 glyphs from a seeded PRNG (mulberry32), brighter
  near the moon, masked away from the copy and the bottom edge, repainted on resize and font load.
- The approved **muerte** rider (cutout mask, new `moonlit` tint) stands on the outcrop at the
  right, facing the city. Copy on the left over a scrim: kicker, serif headline "Static analysis
  for unknown lands", lede, real actions (New project → the form; Open a project → the list),
  and the real order of work (Import → Inspect → Run static analysis → Pin a review).
- Motion: one arrival (field and halo fade in) and slow fog drift, only under
  `prefers-reduced-motion: no-preference` and atmosphere on. Reduced atmosphere removes the scene
  and leaves a plain void masthead.

### Shared system
- `PageMast` (workspace level: horizon silhouette + astrolabe ring; instrument level: ring edge
  only; optional character crop), `Panel` (engraved double-rule head), `BinaryRule`,
  `DitherMoon`, `FileMap`, `Breadcrumbs`, `SectionIndex`, `Isotipo`.
- Cards gain a serif title on an engraved double rule; metrics gain a signal gauge tick; frame
  brackets get a signal tip; `.chip`, `.button-large`, `.button-ghost`, primary glow on hover.
- Every decorative layer carries `.atmo` / `.binary-art`: one rule hides it for Reduce
  atmosphere and forced colours; print hides it too.

### Pages
| Route | M2 |
|---|---|
| Projects | Journey masthead; metric strip (projects, samples, newest project — all from the API); ledger table (serif names, descriptions, sample-count bars, newest first); framed New project panel; crow empty scene with the dithered moon |
| Project | Workspace mast; metrics (samples, versions, distinct formats, last import); **specimens**: each sample a card with its versions on a spine (oldest first, format/arch chips, admission pill, short hash, size, import time) and the real Compare link; **field log** rail (activity API, oldest first as the API returns it); "An empty satchel" scavenger scene leading to Import |
| Run | Instrument mast with status sentence; 4 metrics (steps, findings, strings, summed step time); section index; **Understand** band (plain-language summary from the API, Coverage step chain with each status's meaning, strings summary, the backend's "Why these observations appear"); **Investigate** band (Ghidra workspace, findings with **file map** + docked inspector, steps and raw output, log, sample and provenance) |
| Version | Instrument mast; index; Understand (guided overview, pinned review) / Investigate (runs, identity + header, file structure with a sections-only file map, bytes, provenance) / Record (reports, compare, annotations; mystic crop on the band) |
| Import | Workspace mast with a scavenger crop; trail |
| Rules | Instrument mast with the wizard crop; stored-set trail |
| Tools | Instrument mast with the automaton crop; tool cards with availability LED; profiles as numbered step chains |
| Compare, Report | Trail + instrument mast |
| 404 | Serif title, nohead field (unchanged placement) |

### Technical instrument: the file map
`FileMap.tsx` draws the stored file as one track: sections' **raw byte ranges as declared**
(file offsets, overlaps not resolved, zero-size sections skipped) and, on the Run page, one tick
per matched byte range of the currently filtered findings (capped at 400). Clicking a tick
selects that finding and opens the same inspector as the table; the selected finding glows. The
SVG has a computed `aria-label` summary (sizes, counts, how many ranges fall inside a section)
and the findings and sections tables remain the keyboard path. "Outside every section" is the
byte count outside the union of declared ranges. It is a file-offset map only: it makes no claim
about memory layout or execution.

### ASCII placements
muerte: Projects masthead. crow: Projects empty. scavenger: empty samples, Import mast.
wizard: Rules mast. mystic: Version "Record" band (annotations / pinned review context).
automaton: Tools mast. nohead: 404. executioner: kept, unused (not tied to any failure or
verdict). No figure inside a panel that shows sample data; Run has no figure at all.

## Evidence intelligence (§16 of the brief)
This checkout has **no evidence-graph endpoints** (no nodes, edges, neighbourhoods or citation
graph beyond `/sample-versions/{id}/citation-targets`); they live on the unmerged
`feat/v0.10-evidence-intelligence` branch, which M2 did not touch. Understand / Investigate is
therefore built on the APIs that exist: run summary, step states, review observations, findings
and evidence, sections, Ghidra overview/functions. No frontend interpretation logic, scores or
verdicts were added. When v0.10 lands, its graph belongs in the Investigate band beside the file map.

## Validation
| Check | Result |
|---|---|
| TypeScript, ESLint | Clean |
| Vitest | 21 files, 129 tests passed (123 existing, some updated for the new shell; 6 new in `journey.test.tsx`: file map summary and overlap union, unusable size, PRNG determinism, breadcrumbs, section index, project spine + isotipo) |
| Playwright (real `bytasm serve` + worker) | 24 passed (22 existing, some updated for the trail; 2 new in `m2-journey.spec.ts`); 0 axe violations on every checked screen |
| Screens 1440 / 1024 / 768 / 390 / 360 | No document-level horizontal overflow on Projects (empty and populated), Project, Run, Version, Rules, Tools, Import, Compare, 404 (dev-server sweep plus `m2-journey.spec.ts`) |
| External requests | None (fonts and art from Bytasm's origin; asserted in m1 and m2 specs) |
| Browser console | No errors or warnings on the swept screens |

Test changes: `shell.test.tsx` now finds the policy in the top bar (`banner`) and the limits in
the status bar; Compare's breadcrumb assertion follows the trail; three e2e specs click the
right trail link (`.last()` / by name) now that the trail has several links;
`e2e/m2-journey.spec.ts` is new (branding assets, favicon link, serif loaded, file-map ticks and
selection, five viewports, reduced-atmosphere masthead; screenshots to `test-results/m2/`).

## Known limitations and remaining work
- The city is composed from primitives in SVG, not an engraved illustration; at close range the
  rim offset reads as outline on thin spires. A hand-engraved landscape asset (VISUAL_ASSET_GUIDE)
  would raise fidelity to the boards.
- Mast character crops on Import/Rules/Tools are deliberately faint; they may be too quiet.
- `ReviewPanel`, `InspectionOverview`, `GhidraPanel`, `AnnotationsPanel`, `ByteViewer` and
  `SectionMap` kept their internal markup; they inherit the card system but were not redesigned.
- The section index's mobile block opens by default; it could start collapsed on phones.
- Real-Ghidra browser lane (`scripts/check-ghidra-browser.mjs`) not run.
- Owner review of rendered screens still required.
