# Bytasm — Art Direction

Status: direction and Signal palette **approved** by the owner on 2026-11-01 (§5).
Branding (§9) stays provisional (D5). Written 2026-10-31.
Companion documents: [VISUAL_ASSET_GUIDE](VISUAL_ASSET_GUIDE.md) ·
[ASCII_INTEGRATION](ASCII_INTEGRATION.md) · [DESIGN_SYSTEM](DESIGN_SYSTEM.md) ·
[FRONTEND_ROADMAP](FRONTEND_ROADMAP.md).

## 1. Identity in one paragraph

Bytasm is a local-first lab notebook for static binary analysis: guarded intake,
SHA-256 identity, LIEF metadata, strings, YARA-X, capa, optional headless Ghidra,
evidence-linked findings, analyst annotations, pinned reviews, comparisons and
reproducible reports. It never executes a sample and never says "malicious" or
"safe" (blueprint §1.4, §7.5). The art direction has to carry that ethic. The
product is a **dark underground workstation**: a precise, quiet instrument with a
small amount of strange, engraved, binary-made imagery around its edges. The
precision is real (provenance, hashes, offsets). The strangeness is atmosphere
and never claims anything about a sample.

Working name for the direction: **Engraved Signal**. Antique engraving turned into
binary signal. A black instrument panel with one electric purple signal running through it.

## 2. Mood and emotional direction

| The user should feel | The interface does this by |
|---|---|
| Precision | 1 px rules, mono values, tabular numerals, exact provenance next to every value |
| Calm under uncertainty | Restrained colour, explicit "unknown / not analysed" states, no alarm styling for ordinary observations |
| Curiosity | One figure emerging from the dark per screen at most, progressive disclosure ("inspect next") |
| Independence / underground craft | Keyboard-first command palette, status bar, compact toolbars, terminal-style run log |
| Controlled danger | Black field, electric purple signal, engraved figures. Danger stays in the art; the data never carries it |

Emotional ceiling: *mysterious specialist tool*. Emotional floor: *a tool you can
work in for four hours*. Whenever the two conflict, the floor wins.

## 3. Influences and what each contributes

| Influence | Take | Leave |
|---|---|---|
| Late-90s / early-2000s scene tools (hex editors, PE viewers, IRC clients, cracktro NFOs) | Dense panels, status bars, bracketed labels `[01]`, ASCII as a craft, keyboard everything | Fake hacker tropes, green-on-black Matrix rain, skull logos |
| Contemporary security product UX (`fronted-features-raw/frontend-ref-1`, `-2`) | Faceted filters with counts, sticky table headers, chip filters, side rail | Risk gauges, "attack surface %", invented scores (ref-1's "Risk Score 70%") |
| Nordlys template (`frontend-ref-3` … `-13`) | Two typefaces, five colours, numbered section heads (`01 —`), mono micro-labels, metric strips with hairline dividers, arrow-cell split button, keyboard-toggled menu, giant wordmark footer | WebGL silk shader (GPU cost, not ours), marketing-scale type in the app |
| Antique woodcut / engraving (the eight raw characters) | Hatching texture, silhouettes, dark folklore symbolism | Literal medieval ornament around UI chrome |
| Gothic asset boards (`fronted-assets-goth/asset-1` … `-10`; asset-7 … -10 are the newest and the primary colour reference) | Electric purple on black at a measured 2–3 % of the area, grain, crosshair/compass glyphs, moon-phase sequence, thin rule with centre node, corner-bracket frames | Chains, banners, candles, castles in the app; gothic frames around every card |

## 4. Visual philosophy

1. **80 / 20.** 80 % contemporary product UI, 20 % identity. Count it per screen:
   if more than one region of a working screen is decorative, cut.
2. **One focal moment per screen.** A hero figure, or a chart, or a fragment in an
   empty state. Never two figures competing.
3. **Decoration never looks like data.** Decorative hex, coordinates and serials use
   the `--text-faint` tone and a `∷` / `//` prefix, carry `aria-hidden="true"`, and
   never appear inside a panel that shows real evidence. Real values always have
   provenance or a copy affordance; decoration never has either.
4. **Quiet surfaces, loud edges.** Panels are flat (`--surface`, 1 px `--line`).
   Identity lives at the edges: hero bands, section transitions, empty states,
   footer, status bar.
5. **Purple is signal, not paint.** Following Nordlys (ref-7: "violet appears
   only as light"), purple marks *focus, selection, the active path, primary actions,
   one data series and rare atmospheric moments*. It is never a panel fill and never
   a decorative gradient wash. Ordinary cards and buttons do not glow.
6. **Monochrome first.** Every screen must read correctly in grayscale. Purple adds
   rhythm. Semantic colours add state. Neither is the only carrier of meaning.

## 5. Colour strategy (summary; tokens in DESIGN_SYSTEM §2)

**D3 revised 2026-11-01.** The first proposal (lavender `#A0A2FF` with a deep
`#5B4FD6` fill) was rejected as too blue and too polite. The approved direction is a
saturated, electric purple with orchid highlights and a rare pink-magenta spark,
on deep blacks, charcoal, cool greys and a warm off-white. Visual comparison on real
components: the review page listed in DESIGN_SYSTEM §2.8.

Why these values:

- **The owner's references and the boards agree.** The owner's references
  (`#902EFD`, `#A454FC`, `#A050F8`, `#9442FC`, `#9627FF`) all sit at hue 266–271°.
  The brightest violet pixels measured on the newest boards land in the same place:
  `#922AFC` (asset-7), `#A04FF8` (asset-8), `#9443FB` (asset-9), `#9F3DFA` (asset-10).
  The palette is built around that hue rather than a compromise between purple and blue.
- **One hue, split by job.** No single purple passes every accessibility role. A fill
  that carries white text must be mid-dark; text and focus rings on black must be light.
  So the family has a fill (`--signal-500 #902EFD`, exactly the owner's first reference,
  white text 5.26:1), a highlight for graphics (`--signal-400 #A454FC`, exactly the
  owner's second reference, ≥ 4.33:1 on every surface, never small text), a readable
  purple for links, purple text and the focus ring (`--signal-300 #BC85FF`, ≥ 6.5:1
  everywhere), a pale tint for text on purple-tinted surfaces (`--signal-200 #D9BDFF`) and dark plum surfaces
  (`--plum-900 #170E26`, `--plum-800 #221338`) for selection and analyst interpretation.
- **Orchid and magenta are seasoning.** Orchid (`--orchid-400 #D46BF2`, hue 287°)
  matches the boards' rare pink-violet highlights (`#D163EA`, `#E351FE`) and lives
  inside purple compositions: art gradients, chart hover, brand glyph detail.
  Pink-magenta (`--magenta-400 #FF4FB8`, hue 324°) does not appear on the boards; it
  is a deliberate addition, kept to at most one element per screen (compare series B,
  the pinned-review marker, a rare atmospheric highlight) and never used for state.
- **The neutrals stay neutral.** Backgrounds measured on the boards are near-pure black
  (median value 3 %). Bytasm uses `--void #050507`, `--bg #0A0A0D`, charcoal surfaces
  with a faint cool bias, cool grey secondary text (`#A3A1AB`) and a warm off-white
  for primary text (`#EFEBE4`), which keeps long reading sessions from feeling clinical.

Restraint rule (the 80/20 balance in colour terms): saturated colour covers about
2–3 % of the boards, and Bytasm's working screens keep it at or below ~5 %. Most
surfaces stay black, charcoal or dark grey. Purple appears on interactive focus,
selected elements, primary actions, one chart series and distinctive graphical
compositions (hero art, section transitions). Glow (`--signal-glow`) is reserved for
focus halos, selected byte ranges and hero art. Cards, panels and secondary buttons never glow.

Semantic colours (`ok`, `warn`, `danger`, `info`) are reserved for **run/step/intake
state**. They are never used for a finding's supposed severity, because Bytasm has no
severity model. `danger` is shifted toward orange-red (`#FF6B57`) so it never reads as
magenta, and it always carries a glyph and a word: under tritan colour vision the two
are close (ΔE 13).

## 6. Typography philosophy

- **Sans for reading, mono for evidence.** Body, headings and controls use the sans.
  Every value that came out of a file or a tool (hashes, offsets, addresses, section
  names, rule IDs, strings, tool versions) uses the mono. This split is functional
  as well as visual: a user can tell measured values from Bytasm's own words at a glance.
- **Uppercase mono micro-labels** (11 px, +0.08em tracking) for field labels, panel
  eyebrows and section numbers, as in Nordlys and asset-4 (`FILE INFORMATION`).
- **No medieval or blackletter type** in the product. The boards' engraved serif
  wordmark ("BYTASM" in asset-4/-5, a Trajan-like capital) is a *branding* question
  (ART §9, open decision D5), not a UI typeface.
- Recommended pair: **Inter** (variable, tabular figures, `ss01`/`cv11` alternates)
  and **JetBrains Mono** (unambiguous `0 O`, `1 l I`, which matters for hex). Both
  OFL and self-hosted, because the CSP has no external `font-src` (see DESIGN_SYSTEM §3).

## 7. Underground hacker influence: how it shows up for real

| Motif | Bytasm form | Where |
|---|---|---|
| Status bar | Bottom 24 px bar: input policy, API health, version, keyboard hint | App shell, every screen |
| Command palette | `⌘K` / `Ctrl K`: jump to project, version, run, rule set; run commands that already exist (start run, export report) | Global |
| Bracket indices | `[01] Overview` style numbering for *ordered* things: run steps, inspection checks, section headings in long pages | Run steps, VersionPage sections |
| Terminal log | Existing run log (`.run-log`) restyled: timestamp column, level column, message | RunPage |
| Hex view | Existing `ByteViewer` with offset / hex / ASCII columns, `·` for non-printables (already in `asciiPreview`) | Evidence drawer, Ghidra function detail |
| NFO-style ASCII | The eight characters, plus small ASCII rules `─── ∷ ───` | Landing, empty states, footer |

What we do not do: blinking cursors on non-input text, typewriter effects on
real data, fake "ACCESS GRANTED" copy, invented log lines.

## 8. Medieval folklore influence

The characters are allegories of the analyst's posture, and the copy never says so
out loud. All eight are integrated organically: each one has a home in a specific
context (an empty state, a boundary, a failure state, the landing) instead of
appearing as a set, a gallery or a mascot. The mapping below is approved and decides
*where* a figure appears; it is never shown as labels in the UI. Rollout per
milestone is in ASCII_INTEGRATION §9.

| Character | Silhouette (from the raw engraving) | Symbolic fit | Natural placement |
|---|---|---|---|
| `wizard` | Hooded figure holding an armillary sphere, flame in other hand | Inquiry, instruments | Landing hero (primary candidate) |
| `crow` | Raven perched on two skulls and rubble | Watchfulness, memory, evidence | Empty "no findings" / pinned reviews |
| `nohead` | Headless armoured knight, long sword, lantern | Reading without a face: the unknown sample | Landing "evidence first" band, 404 |
| `mystic` | Sun-rayed halo figure, censer, raven on hand | Illumination, interpretation | Annotations / interpretation empty state |
| `scavenger` | Hunched figure, overloaded pack, rat, sickle | Collecting strings and fragments | Strings tab empty state |
| `automaton` | Crowned bell automaton with crossbow, chains | Machinery, tooling | Tools page, Ghidra-unavailable state |
| `executioner` | Hooded axe-bearer with wolf on a chain | Cut, rejection, refusal | Intake rejection page (small, very dim) |
| `muerte` | Hooded rider with scythe on a horse | Ending, timeouts | Run timed-out / cancelled state, footer |

Caution: `executioner`, `muerte` and `crow` (skulls) have the strongest death
imagery. They must never sit next to a specific sample's data, because placing them there would
imply a verdict. They belong in global or empty contexts only.

## 9. Branding (proposals only; do not implement)

Current mark: `▚` (U+259A) in `App.tsx`, set in text. It is already a two-cell
binary quadrant glyph, which is a promising seed.

| Direction | Description | Strengths | Risks |
|---|---|---|---|
| **B1 Quadrant** | Evolve `▚` into a 2×2 bit grid (`10/01`) drawn on a 4 px grid, with a fine compass cross through it | Pure binary, legible at 16 px, monochrome by nature, already in use | Can feel generic (many "pixel" logos) |
| **B2 Compass-star** | The 4-point star / crosshair isotype repeated on every board (asset-7/-8/-9 "Isotype") | Strongest continuity with the boards | Star marks are common; thin rays die at 16 px; reads occult |
| **B3 Engraved wordmark** | Trajan-like capitals `BYTASM` with hatched fill (asset-4/-5) | Most distinctive, ties to engravings | Feels like fantasy branding; hatching unreadable small; needs a separate small mark anyway |
| **B4 Binary wordmark** | `BYTASM` set in the mono, with the `A` replaced by a stacked `0/1` or the quadrant | Honest, technical, cheap to produce | Less memorable |

Recommendation: **B1 symbol + B4 wordmark** for the product (favicon, app icon,
rail, status bar). Keep **B3** for the landing hero only, if at all. Avoid skulls and
hoods in the mark. The boards' crow/skull app icons are art, not identity.

## 10. Do's and don'ts

**Do**
- Let a character bleed off a hero edge or a section boundary, faded with a mask.
- Keep data panels flat, 1 px bordered, with 8 px radius at most (the boards use near-square corners; propose 4 px).
- Use bracketed indices and mono micro-labels for ordered or technical structure.
- Show "not analysed", "partial", "unavailable" with the same care as success.
- Keep every real value selectable and copyable.

**Don't**
- Put a figure inside a card that shows sample data (asset-7 "Sample card" with a figure behind it: avoid).
- Use SAFE / SUSPICIOUS / MALICIOUS / CLEAN badges, "risk: high", "Medium risk",
  "Findings by severity" donuts, or "Behavior indicators". All appear in the boards
  (asset-4/-6/-7/-8/-9/-10) and all contradict blueprint §7.5.
- Show Mach-O, ARM64 or RAW format chips: intake accepts PE and ELF only (blueprint §1.4).
- Show growth deltas (`+12 %`) or time-range filters on a single-user local tool with no such data.
- Add a "Characters" or "Database" navigation item (both on the boards; neither is a product feature).
- Wrap cards in gothic frames, chains, banners or candles.
- Use the ribbed / glitch effect on anything a user needs to read.

## 11. Visual anti-patterns (seen in references, rejected)

| Anti-pattern | Source | Why rejected |
|---|---|---|
| Verdict badges and risk scores | asset-4…-10, ref-1 | Contradicts product honesty rules |
| Entropy histogram 0–8 with 30+ bars per sample | asset-4/-5/-6 | Bytasm measures **per-section** entropy (one number per section). A histogram would invent a distribution |
| Network/relationship graph with "Registry", "Child process", "Network" | asset-10 | Dynamic behaviour; Bytasm never runs samples |
| CSV / PDF export buttons | asset-10 | Exports are JSON, static HTML and pinned-review derivatives |
| Drop zone with "Mach-O (x86-64, ARM64)" | asset-5 | Unsupported formats |
| "High entropy detected … may indicate packing" alert in danger red | asset-4/-6 | An observation styled as an alarm. Existing UI correctly says entropy is a measurement |
| Figure behind metric cards | asset-7/-9 | Reduces contrast of numbers and implies a judgment |
| Neon outline on every panel | asset-4/-10 | Kills hierarchy |
| Glow on every card or button | asset-8/-9 | Purple stops meaning focus or selection when it is everywhere |

## 12. Reference hierarchy

1. This document and its companions.
2. The eight ASCII characters (`references/frontend-characters-ascii/`).
3. Gothic boards (`references/fronted-assets-goth/`): palette ratio, glyphs, composition.
4. Functional references (`references/fronted-features-raw/`): structure and UX.
5. Existing frontend conventions (`frontend/src/styles.css`, `components.tsx`) where compatible:
   semantics, a11y, wording rules and test IDs are kept; visual styling is not binding.
6. New ideas raised during implementation, reviewed against §4.

On a conflict, the product's honesty rules (blueprint §1.4, §7.5) override every
visual reference.
