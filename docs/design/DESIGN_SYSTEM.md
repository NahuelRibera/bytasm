# Bytasm — Design System

Status: approved 2026-11-01 (D2 dark-only, D3 Signal palette). Implemented in M1:
`frontend/src/styles/tokens.css` (tokens and aliases), `styles/shell.css` (shell and
identity pieces), `styles/fonts.css`; contrast roles re-checked by `styles/tokens.test.ts`. Contrast ratios below were computed (WCAG 2.x relative
luminance), not estimated. Names follow the existing frontend: plain CSS custom
properties in `frontend/src/styles.css`, BEM-light class names (`.card`, `.pill-ok`,
`.kv-row`), and React function components in `components.tsx`. No CSS framework,
no component library, and no charting library are introduced.

## 1. Principles

1. Dark-first. The current light theme is retired for the app shell (open decision D2:
   keep a light theme for printing/exports only).
2. Two families, five core colours, one button shape, one border weight.
3. Values from files or tools are mono and copyable; Bytasm's own words are sans.
4. Colour never carries meaning alone (keeps the existing dot + label rule).
5. Everything works at 360 px (existing `e2e/responsive.spec.ts`) and by keyboard.

## 2. Colour tokens

Ratios in this section are computed against the surfaces a role can actually sit on.
Thresholds: 4.5:1 for text, 3:1 for control boundaries, focus indicators and
meaningful graphics (WCAG 2.2 SC 1.4.3, 1.4.11, 2.4.13).

### 2.1 Neutral foundation

| Token | Value | Use | Contrast |
|---|---|---|---|
| `--void` | `#050507` | Behind art, hero bands, status bar, rail | — |
| `--bg` | `#0A0A0D` | Page | — |
| `--surface` | `#121216` | Panels, tables | — |
| `--raised` | `#1A1A20` | Popovers, inspector, drawer, hover rows, menus | — |
| `--line` | `#25252D` | Hairline dividers, table row rules (decorative) | not for control boundaries |
| `--line-strong` | `#34343F` | Panel borders, table header rule | 1.6:1 on bg (decorative structure) |
| `--control` | `#74737F` | **Input/select/checkbox borders**, segmented control outline | 4.24 bg / 4.01 surface / 3.71 raised ✓ |
| `--text` | `#EFEBE4` | Primary text (warm off-white) | 16.64 bg / 15.73 surface / 14.58 raised / 14.51 plum-800 ✓ |
| `--text-muted` | `#A3A1AB` | Secondary text, labels, help (cool grey) | 7.76 bg / 7.34 surface / 6.80 raised / 6.77 plum-800 ✓ |
| `--text-faint` | `#6C6B76` | **Decoration only** (serials, coordinates, ornaments) | 3.77 bg ✗ for text, so never for meaningful copy |

### 2.2 Dark purple surfaces

| Token | Value | Use | Contrast |
|---|---|---|---|
| `--plum-950` | `#0E0917` | Pocket behind hero figures, landing bands | `--text` 16.52, `--signal-300` 7.42 |
| `--plum-900` | `#170E26` | Selected table row, active rail item, annotation card | `--text` 15.68, `--text-muted` 7.31, `--signal-200` 11.24 |
| `--plum-800` | `#221338` | Selected segment, selected + hover | `--text` 14.51, `--signal-200` 10.40, focus ring 6.52 |
| `--plum-700` | `#3A1F63` | Purple-tinted hairline (decorative, never the only boundary) | 1.47 bg |

### 2.3 Signal purple

One hue family (266–271°), split by job so that no single shade has to serve every
accessibility role.

| Token | Value | Use | Contrast | Not for |
|---|---|---|---|---|
| `--signal-600` | `#7E22E0` | Primary pressed | white label 6.58 ✓ | — |
| `--signal-500` | `#902EFD` | **Primary fill**: primary button, progress fill, selected chip fill | white label 5.26 ✓; boundary 3.76 bg / 3.55 surface / 3.29 raised ✓ | Text on dark |
| `--signal-500h` | `#9A3CFE` | Primary hover | white label 4.72 ✓ | — |
| `--signal-400` | `#A454FC` | **Highlight graphics**: active rail bar, tab underline, selected row/segment edge, annotation edge, chart series 1, brand glyph | 4.95 bg / 4.67 surface / 4.33 raised / 4.66 plum-900 ✓ (3:1) | Small text (4.33 on raised fails 4.5) |
| `--signal-300` | `#BC85FF` | **Readable purple**: links, purple text, focus ring, purple borders that must pass 3:1 | 7.70 void / 7.47 bg / 7.06 surface / 6.55 raised / 6.52 plum-800 ✓ | Fills behind white text |
| `--signal-200` | `#D9BDFF` | Text on plum surfaces, active tab and rail labels | 11.24 plum-900 / 10.40 plum-800 ✓ | — |
| `--signal-glow` | `rgb(164 84 252 / .18)` | Focus halo on inputs, matched byte range, hero art bloom | — | Cards, panels, secondary buttons |

Owner references and where they landed: `#902EFD` → `--signal-500` (exact);
`#A454FC` → `--signal-400` (exact); `#9627FF` and `#9442FC` sit between the fill and its
hover; `#A050F8` is within 2 % of `--signal-400`. They were not all kept as separate
tokens because five near-identical purples would blur the roles above.

### 2.4 Secondary accents

| Token | Value | Use | Contrast | Rule |
|---|---|---|---|---|
| `--orchid-400` | `#D46BF2` | Art gradients, chart hover emphasis, brand glyph detail | 6.97 void / 6.39 surface | Only inside purple compositions |
| `--magenta-400` | `#FF4FB8` | Compare series B, pinned-review marker, rare atmospheric highlight | 6.28 surface / 5.82 raised | **At most one magenta element per screen.** Never for state, never a button fill |
| `--magenta-900` | `#2A0B1F` | Background behind a magenta marker | `--magenta-400` on it 6.06 | — |

### 2.5 Semantic (state only)

| Token | Text/dot | Background | Contrast on own bg | Meaning in Bytasm |
|---|---|---|---|---|
| `--ok` | `#4FD18B` | `#0F2A1C` | 7.91 | Run/step `succeeded`, intake admitted |
| `--warn` | `#F2B84B` | `#2E2410` | 8.53 | `partial`, `self_built` mode, measurement warnings |
| `--danger` | `#FF6B57` | `#2E1411` | 6.12 | `failed`, `timed_out`, rejected import, API error |
| `--info` | `#79B8FF` | `#0F1D30` | 8.16 | `running`, informational notices |
| `--neutral` | `--text-muted` | `--raised` | 6.80 | `queued`, `cancelled`, `skipped`, `unsupported`, `unavailable` |

Hard rules:
- Semantic colours describe **process state**. They never describe a sample or a finding.
- Findings, rule matches and capa capabilities use **neutral** styling plus a tool
  badge (blueprint §7.5 "neutral card, tool badge"). There is no severity colour.
- Analyst annotations use a `--signal-400` 2 px left edge on `--plum-900`, so purple
  means human interpretation and grey means tool observation.
- `danger` is orange-red so that it stays apart from magenta (ΔE 61 normal vision), and
  it always carries the `✕` glyph and a word, because the two converge under tritan
  vision (ΔE 13). Magenta never appears in a state context.

### 2.6 Usage and restraint

- Saturated colour (all `--signal-*` fills and highlights, orchid, magenta) stays at or
  below ~5 % of a working screen. The newest boards measure 2–3 %.
- Purple goes on: focus, selection, the active path (rail, tab, breadcrumb end),
  the primary action, chart series 1, analyst annotations, hero and transition art.
- Purple does not go on: panel fills, card borders by default, secondary buttons,
  table headers, decorative gradients behind content.
- Glow is limited to focus halos, matched byte ranges and hero art. No card or button glows.
- Magenta: at most one element per screen. Orchid: only next to purple, never alone.

### 2.7 Colour-vision check

CIE76 ΔE after Machado simulation (severity 1.0):

| Pair | Normal | Protan | Deutan | Tritan | Consequence |
|---|---|---|---|---|---|
| `signal-400` / `magenta-400` | 55 | 41 | 61 | 63 | Distinct hues, but luminance contrast only 1.34:1, so the compare chart labels series directly and hatches series B |
| `magenta-400` / `danger` | 61 | 62 | 56 | **13** | Magenta never used for state; danger always has glyph + label |
| `signal-400` / `info` | 74 | 43 | 32 | 55 | Running uses label text too (existing dot + label rule) |

### 2.8 Visual review

The palette was compared with the previous lavender pair on the same Bytasm components
(RunPage header and steps, findings table with selection, evidence inspector, annotation,
per-section entropy and compare charts with real fixture values, empty state with
character art, focus ring on each surface). Review page: "Bytasm Signal Palette",
<https://claude.ai/artifact/Rkn6ZuypNZGN5N7eJuHVad> (private to the owner). D3 stays open until the owner signs off
on that page **and** on M1 screenshots of the real app (FRONTEND_ROADMAP §8).

### 2.9 Diff semantics (Compare)

`+` added → `--ok` text with a `+` glyph; `−` removed → `--danger` text with a `−` glyph; `~` changed →
`--warn` with a `~` glyph. The glyph and a text label are mandatory (existing rule).
"Added" is not "good", so the copy says "present in B only". Series colours in compare
charts are A = `--signal-400`, B = `--magenta-400` (hatched); they never encode added/removed.

## 3. Typography

### 3.1 Families

| Role | Family | Fallback stack | Notes |
|---|---|---|---|
| Sans | **Inter** variable (opsz) | `system-ui, -apple-system, "Segoe UI", sans-serif` | `font-feature-settings: "tnum" 1, "cv11" 1, "ss01" 1` in tables |
| Mono | **JetBrains Mono** variable | `ui-monospace, "SF Mono", Menlo, Consolas, monospace` | Dotted zero distinguishes `0`/`O`, important for hex |

Both OFL-1.1. **Self-host** WOFF2 in `frontend/src/fonts/`, because the CSP
(`backend/src/bytasm/api/guards.py`) has `default-src 'self'` and no external
`font-src`, and Bytasm is local-first. Subset to Latin + Latin-1 + box-drawing +
`· — → ← ⌘ ∷`. Budget ≤ 120 KB total. Add a `THIRD_PARTY_NOTICES.md` entry.

Alternatives considered: IBM Plex Sans/Mono (heavier, more corporate); Geist + Geist
Mono (as in Nordlys, slightly less legible at 12 px for dense tables); Share Tech Mono
(source font of the SVGs, too stylised for data).

### 3.2 Scale (base 14 px for app, 16 px for landing)

| Token | Size / line | Weight | Family | Use |
|---|---|---|---|---|
| `--type-display` | 64/64 (clamp 40–88) | 300 | Sans, tracking −0.03em | Landing hero only |
| `--type-h1` | 24/30 | 600 | Sans, −0.01em | Page title |
| `--type-h2` | 17/24 | 600 | Sans | Section title |
| `--type-h3` | 14/20 | 600 | Sans | Panel title |
| `--type-body` | 14/21 | 400 | Sans | Copy |
| `--type-small` | 13/19 | 400 | Sans | Help, captions |
| `--type-label` | 11/16 | 500 | **Mono uppercase, +0.08em** | Field labels, eyebrows, column headers |
| `--type-data` | 13/20 | 400 | Mono | Hashes, offsets, addresses, rule IDs |
| `--type-metric` | 28/32 | 400 | Mono, `tnum` | Metric strip numbers |

Long hashes/paths: `overflow-wrap: anywhere` (already used), with middle truncation
(`a3f5…9c2e`, existing `shortHash`) plus copy button for full value.

## 4. Spacing, layout, radius

- Spacing scale (keep existing names): `--space-1` 4, `-2` 8, `-3` 12, `-4` 16,
  `-5` 24, `-6` 32, add `-7` 48, `-8` 64.
- Radius: `--radius` **4 px** (was 10), `--radius-small` 2 px, pills 999 px. The boards are near-square.
- Grid: app content max 1440 px, 24 px gutters; landing 12-col, max 1280.
- Density: table row 32 px (`.table-dense` 28 px), control height 32 px (small 26 px).

### 4.1 App shell

```
┌ rail 56px ┬──────────────────────────────────────────────────────────────┐
│ ▚         │ workspace header: breadcrumb · title · actions     [⌘K]      │
│ ◇ Proj    ├──────────────────────────────────────────────────────────────┤
│ ≡ Rules   │                                                              │
│ ⚙ Tools   │   main (scrolls)                         │ inspector (opt.)  │
│           │                                          │ 360px, resizable  │
│           │                                          │                   │
├───────────┴──────────────────────────────────────────┴───────────────────┤
│ status bar 24px: ● fixtures only · API ok · local · static only · v0.9   │
└──────────────────────────────────────────────────────────────────────────┘
```

- Rail: icon + label on hover/focus; expands to 200 px at ≥ 1440 px or on toggle.
  Items: Projects, Rules, Tools (existing routes only). Active item: `--plum-900`
  background, 2 px `--signal-400` bar on the left, `--signal-200` icon.
- At < 768 px the rail becomes a top bar with a menu button. The status bar collapses
  to the input-policy pill only.
- The input-policy pill and `SelfBuiltBanner` stay visible at all times (safety-critical).
- The existing footer disclaimer moves into the status bar as an "About this tool"
  popover, and stays as visible text on the Import page and Projects empty state
  (open decision D4: do not remove it without review).

## 5. Surfaces and elevation

Elevation is conveyed by surface value and border, **not shadow** (shadows are invisible on near-black).

| Level | Surface | Border | Example |
|---|---|---|---|
| 0 | `--bg` | none | Page |
| 1 | `--surface` | 1 px `--line-strong` | `.card`, tables, panels |
| 2 | `--raised` | 1 px `--line-strong` | Drawer, popover, menu, palette |
| Scrim | `rgb(7 8 11 / .72)` | — | Behind dialogs and palette |

## 6. Borders and technical framing

- Default panel: 1 px `--line-strong`, 4 px radius.
- **Corner bracket** (identity detail): `.frame-bracket` draws four 8 px L-corners with
  `background` gradients (no extra DOM). Use only on: landing feature panels, the
  run summary header, empty states. Never on every card.
- **Centre-node rule**: `<hr class="rule-node">`, a 1 px line with a 5 px diamond at
  the centre (from asset-3). Use between major page sections only.
- Section numbering: `01 —` mono label above `h2` on long pages (VersionPage,
  RunPage, landing).

## 7. Components

Existing → proposed. "Keep" means behaviour, semantics and test IDs are preserved; only styling changes.

### 7.1 Navigation
| Component | Status | Spec |
|---|---|---|
| `AppShell` (from `App.tsx` header/main/footer) | Restructure | Rail + workspace header + main + status bar (§4.1). Keep skip link and `#main` |
| `NavRail` | New | `<nav aria-label="Main">`, `aria-current="page"` (existing pattern) |
| `Breadcrumb` | Keep (`aria-label="Breadcrumb"` exists on 5 pages) | Mono, `/` separators, last item `--text` |
| `CommandPalette` | New | `⌘K`/`Ctrl K`, `role="dialog"` + combobox/listbox, sources: projects, recent versions/runs (existing APIs), static commands. No new backend search endpoint. Focus trap and return focus |
| `StatusBar` | New | `role="contentinfo"` region; input policy, API health (existing `/health` query), version, `⌘K` hint |

### 7.2 Content
| Component | Spec |
|---|---|
| `SectionHeader` | Number label (mono 11 px) + `h2` + optional actions; numbering only where order matters |
| `Card` / `Panel` | Level 1. Title row: `h3` + mono eyebrow + actions. Padding 16 |
| `MetricStrip` | Nordlys-style row: big mono number + mono label, hairline separators. Only **counts the API returns** (sections, imports, strings, findings, rule matches, functions inventoried) |
| `KeyValues` | Keep. Label column mono 11 px uppercase, value `--type-data` when technical |
| `Disclosure` | `<details>` (already widely used), with a chevron and "Technical details" convention |
| `Empty` | Keep API (`children`); add optional `art` prop with a character crop key (ASCII_INTEGRATION §9) |
| `InspectorPanel` | New, optional right panel for evidence detail (replaces inline `.evidence-panel` on ≥ 1280 px; inline below) |

### 7.3 Interaction
| Component | Spec |
|---|---|
| `Button` primary | `--signal-500` fill (hover `--signal-500h`, pressed `--signal-600`), white label, 32 px, optional **arrow cell** (Nordlys split: label │ →) for forward navigation only |
| Button secondary | Transparent, 1 px `--control`, `--text` |
| Button ghost | No border, `--text-muted` → `--text` on hover |
| Button danger | Transparent, 1 px `--danger`, `--danger` label. Used for delete annotation / cancel run |
| `IconButton` | 32×32, required `aria-label` (`CopyButton` pattern) |
| `Tabs` | Keep ARIA tabs (VersionPage). Selected: 2 px `--signal-400` underline, `--signal-200` label; mono labels optional |
| `SegmentedControl` | For mutually exclusive view toggles (e.g. table/map in Ghidra). `role="radiogroup"`. Selected: `--plum-800` fill, `--signal-200` label, 2 px `--signal-400` bottom edge |
| Inputs / select / textarea | 32 px, `--surface` fill, 1 px `--control`, focus: 1 px `--signal-300` border + 3 px `--signal-glow` halo, plus the standard ring (§12) |
| `SearchField` | Leading glyph, `type="search"`, clear button; existing filter inputs adopt it |
| `FilterChips` | From ref-2: removable chips showing active filters on RunPage findings (`tool`, `kind`, `q` exist) |
| `Dialog` | Native `<dialog>` + `showModal()`; existing "Start run?" confirm moves here |
| `Tooltip` | Only for supplementary text; never the only place information lives (e.g. `Declared` keeps visible text) |

### 7.4 Data
| Component | Spec |
|---|---|
| `TechTable` (`.table`) | Sticky header, mono 11 px uppercase headers, numeric columns right-aligned `tnum`, row hover `--raised`, selected row `--plum-900` + left 2 px `--signal-400`. Keep `.table-scroll` wrapper for narrow screens |
| `StatusPill` | Keep labels/tones from `components.tsx`. Style: 20 px, mono 11 px, dot + label, tone bg from §2.5. `danger` uses the `✕` glyph instead of the dot |
| `ToolBadge` | New neutral badge `YARA-X · rule_id`, `capa · rule`, `LIEF 0.2.0`. Mono, `--raised` bg, `--line-strong` border |
| `FindingRow` | Neutral. Tool badge + observation wording ("matched", "reported"). Never coloured by kind |
| `AnnotationCard` | `--plum-900` background, `--signal-400` 2 px left border, author, label **Note / Interpretation / Conclusion**, citation list |
| `StepList` | Run steps: `[01]` index, tool + version mono, status pill, duration, message. Live region announces changes (exists) |
| `RunLog` | `.run-log` restyled: 3 columns (time, level, message), `--void` bg, mono 12 px, no colour except level text |
| `ByteViewer` | Offset │ hex │ ASCII columns, matched range highlighted with `--signal-glow`, `--signal-200` text and a `--signal-400` underline (not colour only) |
| `HashRow` | Mono value, middle truncation on narrow widths, `CopyButton` |
| `ProgressSegmented` | 5–20 segments, for **known** step counts only (run steps). Indeterminate states use text + 3-cell `∷` pulse (reduced-motion: static) |

### 7.5 Visual identity
| Component | Spec |
|---|---|
| `BinaryArt` | Props: `character`, `variant: "cutout" \| "field"`, `crop`, `tint`, `fade`, `className`. Renders `<div aria-hidden>` with mask (ASCII_INTEGRATION §4.1). Respects `data-atmosphere="off"` |
| `AsciiFragment` | `<pre aria-hidden>` slice of a TXT by cell rect; for rules and tiny crops |
| `NoiseLayer` | Single tiled PNG at 3–4 % opacity on `--void` regions only |
| `HeroBand` | Landing and (optionally) Projects header: `--void`, art right, scrim, text left |
| `Glyph` | ≤ 12 inline SVG icons from §9, `currentColor` |

Not created: decorative frame components for cards, banner components, "character card".

## 8. Technical data representation

| Data | Representation |
|---|---|
| SHA-256 | Mono, full on detail pages with copy, `shortHash` in tables |
| Offsets / VAs / RVAs | `hex()` → `0x…`, mono, right-aligned; coordinate space labelled (file offset vs VA) as Ghidra `ghidra-3` provides |
| Sizes | `formatBytes` (existing), mono `tnum` |
| Dates | `formatDate` (existing, UTC) |
| Declared header values | Keep `Declared` hint ("declared in file") visible, not tooltip-only |
| Untrusted strings (filenames, strings) | Existing `.untrusted` treatment: mono, quoted, `--text` on `--raised` chip so they never look like UI copy |
| Absent / unknown | `—` plus reason text where available ("not analysed: step skipped") |

## 9. Iconography

- 16/20 px, 1.5 px stroke, square caps, drawn on a 24 grid. Monochrome `currentColor`.
- Set (≤ 16): project, sample/file, run, rules, tools, compare, export, copy, search,
  filter, chevron, close, external, pin, note, warning. Plus identity glyphs: compass-star,
  crosshair, centre-node, moon-phase ×5 (decorative only).
- Hand-built SVG in `frontend/src/icons.tsx` (no icon library). The `▚` brand glyph stays until branding is decided.

## 10. Charts

Only charts backed by existing data:

| Chart | Data source | Form | Accessible alternative |
|---|---|---|---|
| Section map | LIEF sections (offset, size, entropy) via `SectionMap.tsx` | Horizontal proportional bar of sections; entropy as a small 0–8 tick per section | Existing sections table |
| Per-section entropy | `measurement` per section | **Bar per section** (one value each) on a fixed 0–8 axis with gridlines at 2/4/6. **No** histogram across byte values | Table column |
| Run timeline | Step `started/finished`, `duration_ms` | Horizontal Gantt of steps with timeout markers | StepList |
| Function call map | Ghidra one-hop relationships (`FunctionRelationships.tsx`) | Existing SVG, restyled: nodes `--surface`, edges `--line-strong`, selected `--signal-400` | Existing table |
| Compare deltas | Compare API counts | Paired bars A/B per category with `+ − ~` labels | Existing diff list |

Style: axes and gridlines `--line`, labels mono 11 px `--text-muted`. Single-series
charts: ordinary marks `--text-faint`, the selected mark `--signal-400` with its value
labelled. Multi-series: series 1 `--signal-400`, series 2 `--magenta-400` hatched,
series 3 `--text-muted`, never more than 3 series, always labelled directly. Hover shows exact
value plus provenance (tool + version). Decorative instrumentation (corner brackets,
axis serial labels) sits outside the plot area and is `aria-hidden`. Every chart has
`role="img"` + `aria-label` summarising it, and a linked table.

## 11. Motion

| Token | Value | Use |
|---|---|---|
| `--dur-1` | 90 ms | Hover, press |
| `--dur-2` | 160 ms | Tabs, disclosure, popover |
| `--dur-3` | 240 ms | Drawer, dialog, palette |
| `--ease-out` | `cubic-bezier(.2,.7,.2,1)` | Enter |
| `--ease-in` | `cubic-bezier(.4,0,1,1)` | Exit |

Allowed: opacity and transform only. Atmospheric motion per ASCII_INTEGRATION §8.
`prefers-reduced-motion` and `data-atmosphere="off"` both zero all durations except focus.

## 12. Accessibility

- Target WCAG 2.2 AA (blueprint §7.4). Text ≥ 4.5:1 (all text tokens pass except
  `--text-faint`, which is decoration-only). Control boundaries ≥ 3:1 via `--control`.
- Focus: 2 px `--signal-300` outline + 2 px offset (replaces 3 px `--accent`). Measured ≥ 6.5:1
  against every surface it can land on (§2.3). The offset keeps the ring off the
  `--signal-500` fill, where it would only reach 1.99:1.
- Keep all existing ARIA patterns (tabs, live regions, `role="alert"` errors, labelled tables).
- Keyboard map: `⌘K` palette, `g p` projects, `g r` rules, `g t` tools, `/` focus the
  page filter, `[`/`]` previous/next in histories (pinned reviews already have prev/next).
  All shortcuts listed in the palette, none required.
- `forced-colors: active`: art hidden, borders `CanvasText`.

## 13. Responsive

| Width | Behaviour |
|---|---|
| ≥ 1440 | Rail expanded, inspector docked |
| 1024–1439 | Rail collapsed, inspector docked or overlay |
| 768–1023 | Rail collapsed, inspector as drawer |
| < 768 | Top bar, single column, tables scroll horizontally inside `.table-scroll`, no art in working screens |
| 360 | Hard floor; no page-level horizontal overflow (existing e2e) |

## 14. Token migration from current `styles.css`

| Current | New |
|---|---|
| `--bg/--surface/--surface-2` | `--bg/--surface/--raised` |
| `--border` | `--line-strong` (panels), `--control` (inputs) |
| `--accent` | `--signal-300` (text/links), `--signal-500` (fills), `--signal-400` (indicators) |
| `--accent-text` | `--text` |
| `--focus` | `--signal-300` |
| `--ok/--warn/--danger` + `-bg` | Same names, new values |
| `--radius 10px` | `4px` |
| `--font-sans/--font-mono` | Inter / JetBrains Mono stacks |

Old names are aliased during migration so that `styles.css` can be converted panel by panel.
