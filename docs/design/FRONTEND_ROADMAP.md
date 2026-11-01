# Bytasm — Frontend Roadmap

Status: written 2026-10-31 against `main` at `476f955` (v0.9, PR #13); decisions approved
and M1 implemented 2026-11-01 (§12, §13).
Revised 2026-11-01: Engraved Signal approved, D3 palette replaced, D1 re-scoped after
visual validation, M1 plan updated (§8, §11, §12).
Nothing here is implemented yet. "Exists" means verified in `frontend/src` or the API client.

## 1. Existing frontend assessment

### 1.1 Stack and architecture
- React 19 + TypeScript 6, Vite 8, TanStack Query 5. No router library: `router.tsx`
  is a ~70-line history router with 10 routes. No CSS framework, no component library,
  no chart library. Charts (`SectionMap`, `FunctionRelationships`) are hand-written SVG.
- One global stylesheet, `styles.css` (945 lines), with tokens as custom properties and
  light/dark themes via `prefers-color-scheme`. `prefers-reduced-motion` is handled at line 600.
- Shared presentational helpers in `components.tsx`: `StatusPill`, `AdmittedPill`,
  `KeyValues`, `CopyButton`, `ErrorPanel`, `Loading`, `Empty`, `SelfBuiltBanner`,
  `Declared`, `FindingsMeaning`, and formatters `hex`, `formatBytes`, `formatDate`, `shortHash`.
- Served same-origin by the API after build. The CSP (`api/guards.py`) is `default-src
  'self'; script-src 'self'; style-src 'self'; img-src 'self' data:`, so there are no external
  fonts or CDNs and no inline `<style>`. Exported HTML reports have `img-src 'none'`.
- Tests: Vitest + Testing Library (~20 test files), Playwright e2e (12 specs including
  `responsive.spec.ts` at 360 px and axe-core checks), plus `lint-rules.test.ts`.

### 1.2 Routes and screens (exists)
| Route | Screen | Main content |
|---|---|---|
| `/` | ProjectsPage | Projects table, new-project form |
| `/projects/:id` | ProjectPage + ProjectActivity | Samples table, recent activity |
| `/projects/:id/import` | ImportPage | Supported inputs, authorisation attestation, upload |
| `/versions/:id` | VersionPage + AnalysisPanel + InspectionOverview + GhidraPanel + ReviewPanel/PinnedReview + Annotations + ExportReportButton | Identity, provenance, header metadata, sections/imports/exports/strings tabs, section map, runs, guided overview, Ghidra workspace, pinned reviews |
| `/runs/:id` | RunPage (707 lines) | Run summary, steps, log, findings table + filters, evidence drawer with matched byte ranges, capa evidence |
| `/projects/:id/compare/:sampleId` | ComparePage | Version or pinned-review comparison |
| `/rules`, `/rules/:id` | RulesPage | Rule set, validation, sources |
| `/tools` | ToolsPage | Tool versions, built-in rules, Ghidra availability |
| `/reports/:id` | ReportPage | Report review |

### 1.3 Strengths to keep
- Honest wording and provenance everywhere (`Declared`, `FindingsMeaning`, partial banners).
- Good semantics: skip link, labelled tables, ARIA tabs, live regions, `role="alert"`.
- Status = dot + label. Untrusted values rendered as text children.
- Light dependency footprint.

### 1.4 Weaknesses
- Generic look: system fonts, 10 px radius cards, indigo accent; no identity.
- Top-bar navigation only; no persistent context in deep screens (VersionPage is very long).
- VersionPage stacks many large panels vertically; information hierarchy flattens.
- One monolithic stylesheet; page-specific selectors (`.ghidra-workspace …`) mixed with primitives.
- RunPage and VersionPage are large single components (707 / 513 lines), which makes restyling risky.

## 2. Capability map (what the UI may show)

| Capability | Status | UI implication |
|---|---|---|
| Guarded intake, fixtures / self_built policy, SHA-256 | Implemented | Import page, policy pill always visible |
| PE/ELF identification, LIEF metadata, per-section entropy, structural declarations (v0.9) | Implemented | Version overview, sections, structure panel |
| Imports / exports / strings | Implemented | Tabs with filter |
| YARA-X (5 text/format rules), capa (7 rules) | Implemented | Findings, evidence |
| Optional Ghidra: function inventory, selected-function detail, references (`ghidra-3`), call map | Implemented, optional | Ghidra workspace; "unavailable" state |
| Annotations (Note / Interpretation / Conclusion with citations) | Implemented | Annotation cards |
| Pinned reviews, function notes, private exports, review comparison | Implemented | Review panel, compare |
| JSON + static HTML reports | Implemented | Export |
| Third-party / untrusted binaries (gate I1) | **Not satisfied**, deferred | No UI may suggest it |
| Mach-O, raw blobs | Not supported | Never show |
| Global search, cross-project activity | **No API** | Command palette uses existing lists only |
| Sliding-window entropy, byte histograms | Not computed | Do not design screens for them yet |
| Function diffing, investigative graph beyond one hop | Not planned | Conceptual only |
| Risk scores, verdicts | **Never** (blueprint §1.4) | — |

## 3. Proposed information architecture

```
Bytasm (app shell: rail · workspace header · status bar · ⌘K)
├─ Projects                       /
│   └─ Project                    /projects/:id
│       ├─ Import                 /projects/:id/import
│       ├─ Compare                /projects/:id/compare/:sampleId
│       └─ Version (sample)       /versions/:id
│           ├─ Overview           #overview   (identity, guided inspection, metric strip)
│           ├─ Structure          #structure  (sections, map, header metadata, structural declarations)
│           ├─ Symbols            #symbols    (imports, exports)
│           ├─ Strings            #strings
│           ├─ Runs & findings    #runs       → Run /runs/:id
│           ├─ Ghidra             #ghidra     (optional)
│           ├─ Reviews            #reviews    (pinned reviews, notes, exports)
│           └─ Reports            #reports
├─ Rules                          /rules
└─ Tools                          /tools
(Public landing: separate static site, see decision D7)
```

The Version screen gets a **local section nav** (sticky sub-rail or tabs at ≥ 1024 px,
select at < 768 px) using hash anchors. No route changes are needed, so existing deep
links and tests keep working.

## 4. Page designs

### 4.1 Public landing (new; outside the app)
Bytasm is local-first and is not a hosted service. A landing page is therefore a
**static project site** (e.g. GitHub Pages), not an app route.
1. **Hero** on `--void`: headline left, `wizard` (cutout, Signal tint) bleeding off the right/bottom,
   reconstruction animation once. Copy direction: **"The unknown is not unreadable."**
   Sub: "A local workbench for static analysis of binaries you're authorised to
   inspect. Evidence first. Nothing executed." CTAs: *Read the docs* (primary), *View on GitHub*.
2. **Metric strip** (Nordlys ref-8), with true statements only: "0 samples executed ·
   PE + ELF · 5 YARA rules · 7 capa rules · optional Ghidra 12.2". Must be generated from
   the repo at build time to stay true.
3. **Workflow** `01 Intake → 02 Identify → 03 Inspect → 04 Annotate → 05 Report`, each
   with a real screenshot crop of the app (not mock data).
4. **Evidence-first band**: `nohead` (field) crossing the boundary; explains provenance,
   tool versions, "observations, not verdicts".
5. **Safety and scope**: plain text of what Bytasm will not do (blueprint §1.4).
6. **Closing**: giant ASCII-filled wordmark (an answer to ref-9/-10 without a shader), footer with `muerte` fragment.

### 4.2 Application overview
There is no overview route and no cross-project API. **Projects is home.** Proposal:
Projects page gains a compact header band (`HeroBand`, small, no figure by default)
with counts derived from `/api/v1/projects` (projects, samples) and the input-policy
state. "Recent activity across projects" is deferred until an API exists (dependency X1).

### 4.3 Projects / Project
- Projects: `TechTable` (name, samples, created, last activity if the API returns it), search filter
  (client-side), "New project" as a primary button opening an inline form or dialog.
  Empty state: `crow` crop + "No projects yet. A project groups the samples you
  analyse." + one button.
- Project: header (name, sample count, actions: Import, Compare), samples table
  (filename as untrusted mono chip, format, arch, SHA-256 short + copy, versions, latest run status),
  activity list styled as a timeline (asset-10 "status timeline", with real events only).

### 4.4 Samples and intake (ImportPage)
Restrained, with no art on the working form. Layout: left = steps `A Source & authorisation →
B File → C Confirm` (Nordlys contact form grouping), right = "Supported inputs"
panel (PE/ELF, size limit, policy mode, what happens to the file). Rejections use
`ErrorPanel` with the fixed server-side message, "Nothing was imported" in bold, and
request ID in technical details. The policy wording stays verbatim.

### 4.5 Version (sample) screen
- Header: filename (untrusted), format/arch pills, SHA-256 + copy, admitted-under pill,
  actions (Start run, Export report, Compare).
- `MetricStrip`: sections · imports · exports · strings · runs · pinned reviews (counts from existing endpoints).
- Overview: `InspectionOverview` (guided "What was inspected / observed / unknown")
  becomes the first panel, which answers the brief's six questions in order.
- Structure: section map (proportional bar) + sections table + entropy bars (one per section).
- Ghidra section: keeps its own disclosure; inventory table + selected function inspector.

### 4.6 Analysis run (RunPage), the flagship screen
```
┌ Run 3f2a… · default-static · ● Partial · 4m 12s ───────── [Cancel] [Export] ┐
│ 01 Steps     [01] metadata  LIEF 1.0.0     ● Succeeded   412 ms            │
│              [02] strings   bytasm 0.9     ● Succeeded    95 ms            │
│              [03] yara-x    1.x · rules@…  ● Succeeded    61 ms            │
│              [04] capa      10.0.0         ● Timed out  180 s  (why?)      │
│ ⚠ Partial result: capa timed out. Absence of a capa match is not evidence… │
├ 02 Findings ─ [tool ▾] [kind ▾] [search…]  chips: yara-x ×  ───────────────┤
│ table (neutral rows, tool badge, rule id, location)  │ Inspector: evidence │
│                                                      │ byte ranges + hex   │
│                                                      │ raw output link     │
├ 03 Log (collapsed) ───────────────────────────────────────────────────────┤
```
No character art while the run shows data or is still polling. The only identity
details are bracket indices, mono labels, the centre-node rule between sections and
purple on the selected finding and focus. Two exceptions, from M2 and only after
polling stops: the "no rule matched" empty state (`crow`) and the timed-out or
cancelled page foot (`muerte`), both outside data panels (ASCII_INTEGRATION §9).

### 4.7 Technical investigation patterns
| Pattern | Now (exists) | Design |
|---|---|---|
| Sections | Table + SectionMap | Map + table linked by hover/selection |
| Imports / exports | Tables | Grouped by library, collapsible, count badges |
| Strings | Paginated filtered table | Offset │ section │ value (untrusted chip); filter |
| Entropy | Per-section value | Bars per section, 0–8 fixed axis |
| Rules & matches | Findings + evidence | Inspector with matched ranges in ByteViewer |
| Hex | ByteViewer excerpts | Offset/hex/ASCII columns, range highlight |
| Functions (Ghidra) | Inventory, detail, refs, call map | Inventory table ↔ inspector; references table; call map |
| Comparison | ComparePage | Two-column header A/B, `+ − ~` deltas, compatibility notice first |
| Pinned reviews | PinnedReview, history nav | Timeline list, prev/next, human preview of derivative |
| Evidence graphs | — | **Conceptual only** (doc), no controls until scheduled |

### 4.8 Empty, loading, error
- Empty: art fragment allowed (ASCII_INTEGRATION §9), one sentence, one action.
- Loading: existing skeleton rows matching layout; text after 300 ms (blueprint §7.3).
- Error: `ErrorPanel`, never art, `--danger` left border, readable copy first.
- Partial/cancelled/timed out: persistent banner, same text as in the report.

## 5. Component strategy

1. **Tokens first** (`tokens.css`), aliasing old names so pages migrate one at a time.
2. Split `styles.css` into `tokens.css`, `base.css`, `components/*.css` (imported in
   `main.tsx`; still served as `'self'` stylesheets).
3. Grow `components.tsx` into `components/` only when a component gets real logic
   (CommandPalette, BinaryArt, InspectorPanel). Keep simple ones as CSS classes.
4. Extract sub-components from RunPage/VersionPage **only along the new layout seams**
   (StepList, FindingsTable, EvidenceInspector, VersionHeader), with tests moving alongside.

## 6. Incremental stages

| Stage | Scope | Depends on |
|---|---|---|
| **M1 — Foundation & proof** | §8 below | Gate 0 (D1, D3 on the review page) |
| M2 — Version screen | Section nav, header, metric strip, structure/strings/imports restyle, Ghidra workspace restyle; character placements for run, strings, tools, intake (ASCII_INTEGRATION §9) | M1 |
| M3 — Reviews & compare | Pinned reviews timeline, compare layout (series A purple / B magenta), annotation cards, `mystic` placement | M2 |
| M4 — Command palette & keyboard map | Palette with existing data sources, shortcuts, atmosphere toggle | M1 |
| M5 — Charts | Section map v2, per-section entropy bars, run timeline | M2 |
| M6 — Landing site | Static site, hero art, reconstruction motion | D7, branding D5 |
| Later | Cross-project overview, global search | API X1/X2 |

## 7. Dependencies on future functionality

| ID | Needed for | Backend work |
|---|---|---|
| X1 | Cross-project recent activity on home | Aggregated activity endpoint |
| X2 | Global search (samples, strings, symbols) | Search endpoint with bounded results |
| X3 | Byte-distribution or sliding-window entropy charts | New measurement in LIEF adapter, with provenance |
| X4 | Multi-hop function graph | Ghidra provider budget changes |

None are assumed by M1–M5.

## 8. First implementation milestone (M1)

**Goal:** prove the approved language on real screens without redesigning everything.

### 8.1 Gate 0 (before any M1 code)

1. **D3:** owner approves the Signal tokens on the review page (DESIGN_SYSTEM §2.8),
   or names changes. The page shows the same components in the old and new palettes.
2. **D1:** owner picks the default character derivation from the side-by-side renders
   (`cutout` recommended, `lit` rejected, `field` for one or two dramatic placements).
3. Owner confirms the eight-character placement map (ASCII_INTEGRATION §9).

### 8.2 Scope

1. `tokens.css` with the DESIGN_SYSTEM §2–§5 and §11 tokens (Signal palette), aliases for old names.
2. Self-hosted Inter + JetBrains Mono (WOFF2, subset), with license notices.
3. Base primitives restyled: buttons (primary fill, hover, pressed), inputs, pills,
   tables (selected row on plum), cards, tabs, segmented control, `KeyValues`,
   `ErrorPanel`, `Loading`, `Empty`, and the `--signal-300` focus ring everywhere.
4. App shell: `NavRail`, workspace header with breadcrumb, `StatusBar` (policy pill + health + version). Keep `SelfBuiltBanner`.
5. **ProjectsPage + ProjectPage** fully restyled (the representative project screen).
6. **RunPage** restyled to §4.6 (the representative analysis screen), including StepList,
   neutral findings with tool badges, inspector on ≥ 1280 px. No art on RunPage in M1.
7. ASCII: `scripts/build_ascii_art.py` (TXT + tone → `cutout` and `field` PNG masks) for
   **all eight** characters with the fidelity check, `characters.ts` manifest, `BinaryArt`
   component, and the three M1 placements: `crow` (Projects empty), `scavenger`
   (Project with no samples), `nohead` (404). The other five are built and scheduled
   (ASCII_INTEGRATION §9), not placed.
8. `data-atmosphere` toggle (status bar menu) + reduced-motion handling. No animation yet.
9. Contrast script in CI that recomputes the DESIGN_SYSTEM §2 table from `tokens.css`
   and fails if any role drops below its threshold.

Out of M1: landing, command palette, charts, VersionPage restructure, branding change.

## 9. Validation methodology

| Check | How | Pass criterion |
|---|---|---|
| Rendered screenshots | Playwright screenshots of every M1 screen at 1440×900, 1024×768, 390×844, 360×740, with fake API (`src/test/fakeApi.ts`) and real fixtures | Reviewed side by side with asset-5 / ref-7 / ref-2 |
| Visual regression | Playwright `toHaveScreenshot` on the shell, ProjectsPage (data + empty), RunPage (succeeded, partial, failed), 404 | Threshold 0.2 %, updates reviewed in PR |
| Accessibility | Existing axe-core e2e on all screens; manual keyboard pass; VoiceOver smoke test on RunPage | 0 axe violations; focus visible everywhere |
| Contrast | Token table (DESIGN_SYSTEM §2) re-verified by script in CI, per role and surface | Text ≥ 4.5:1, focus/controls/graphics ≥ 3:1; `--signal-400` never used as small text |
| Palette balance | Share of saturated pixels (`--signal-*`, orchid, magenta) in each M1 screenshot | ≤ ~5 % per working screen; ≤ 1 magenta element; no glowing cards |
| Functional regression | Full Vitest + Playwright suites unchanged in assertions (selectors may move to roles) | Green |
| Performance | Lighthouse (local build): LCP, CLS; bundle diff | CSS+fonts ≤ +150 KB; art ≤ 60 KB per screen; CLS < 0.05 |
| ASCII fidelity | `cutout` glyphs identical to `field` cell by cell; only paper removed; annotated openings transparent (unit tests); side-by-side with raw engraving on a checkerboard | Tests green; owner approves the `cutout` look in the real app |
| Consistency | Checklist: one focal point, no art in data panels, no verdict wording (grep for `malicious|safe|risk`) | Pass |
| Manual UX | 30-minute walkthrough: import fixture → run → inspect finding → annotate → export | No regressions; notes filed |

A passing build alone is not acceptance.

## 10. Risks and tradeoffs

| Risk | Mitigation |
|---|---|
| Art reads as fantasy/game | 80/20 rule, no art on working screens, review screenshots against §10 of ART_DIRECTION |
| Death imagery implies verdicts | Placement table forbids figures near sample data |
| Board patterns leak unsupported features (verdicts, Mach-O, CSV/PDF) into implementation | Capability map §2 is the gate; wording grep in CI |
| Restyle breaks tests on large components | Seam-only extraction, migrate a page at a time behind aliases |
| Dark-only hurts printing/exported reports | Keep a light print stylesheet; reports keep their own CSS |
| Font weight on low-end devices | Subset + `font-display: swap`, ≤ 120 KB |
| Character derivation judged unfaithful | Validated 2026-11-01: `lit` rejected as a tonal negative; `cutout` default, `field` fallback |
| Electric purple overwhelms the UI | §2.6 restraint rules in DESIGN_SYSTEM; saturated share measured on M1 screenshots (≤ ~5 %) |
| Magenta read as an error colour | Magenta never used for state; danger orange-red with glyph + label (DESIGN_SYSTEM §2.7) |
| Removing the footer disclaimer weakens safety messaging | Decision D4; keep it visible on Import and empty Projects |

## 11. Definition of done (M1)

- [ ] Gate 0 recorded: D3 tokens and D1 derivation approved on the review page.
- [ ] Tokens and fonts in place; old token names aliased; no external requests (CSP unchanged).
- [ ] Contrast CI script green; palette balance measured on screenshots.
- [ ] App shell, ProjectsPage, ProjectPage and RunPage match the spec at 4 viewports; screenshots attached to the PR.
- [ ] All eight characters derived by the script (`cutout` + `field`); three M1 placements live; originals untouched; fidelity checks pass.
- [ ] Reduced-motion and atmosphere toggle verified.
- [ ] Vitest, Playwright and axe green; no new axe violations; manual keyboard pass recorded.
- [ ] No verdict/risk wording; no unsupported formats or controls.
- [ ] Owner review of rendered screens (not mockups) recorded in `docs/milestones/`.

## 12. Decisions (owner, 2026-11-01)

| ID | Decision | Outcome |
|---|---|---|
| — | Engraved Signal direction, 80/20 balance, organic use of all eight characters | **Approved** |
| D1 | Default character derivation | **Approved:** `cutout`, with the enclosed-opening correction (ASCII_INTEGRATION §3.4); `field` for 1–2 dramatic placements; `lit` not shipped |
| D2 | Dark-only app | **Approved** for the initial redesign; a light print stylesheet remains |
| D3 | Signal palette | **Approved** as documented in DESIGN_SYSTEM §2 |
| D4 | Safety messaging | **Approved:** contextual messages on Import and empty states, plus an accessible global "Limits" disclosure in the status bar |
| D5 | Branding | **Provisional:** the quadrant mark in the rail is a placeholder |
| D6 | Reference assets | **Approved:** references stay out of production paths and are never modified; only derived sources and outputs are committed |
| D7 | Public landing | **Deferred** |

## 13. M1 implementation status (2026-11-01)

Implemented on branch `feat/m1-frontend-foundation` (not committed). Results and the
remaining owner review are recorded in `docs/milestones/m1-frontend-foundation.md`.
