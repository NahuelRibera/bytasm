# M1 frontend foundation — 2026-11-01

Base: main `476f955` (v0.9). Branch `feat/m1-frontend-foundation`, **not committed**.
Scope and decisions: `docs/design/FRONTEND_ROADMAP.md` §8 and §12 (D1–D7 approved by the
owner on 2026-11-01). Product behaviour, analysis semantics, API contracts and safety
policies are unchanged; no backend source file was modified. The parallel
`feat/v0.10-evidence-intelligence` worktree touches `FunctionReferences*` only, which M1
does not modify.

## Delivered

- **Character art pipeline.** `scripts/build_ascii_art.py` (stdlib only, deterministic)
  extracts committed sources from the untouched references, then builds `cutout` and
  `field` alpha masks for all eight characters, a manifest and a mask stylesheet.
  The `cutout` extraction was corrected after the owner's annotated screenshots: enclosed
  paper openings are now transparent and cream artwork touching the outside is kept
  (`docs/design/ASCII_INTEGRATION.md` §3.4). The mystic's raven gets a local rim of its
  own surrounding glyphs (§3.5); its interior detail was lost in the original conversion.
- **Signal tokens** (`frontend/src/styles/tokens.css`) with aliases for the old names; dark
  only; reduced-motion and reduced-atmosphere zero the motion tokens.
- **Self-hosted fonts:** Inter and JetBrains Mono variable, Latin subsets, 48 + 40 KB,
  bundled by Vite from Fontsource (OFL-1.1, `frontend/THIRD_PARTY_NOTICES.md`). CSP unchanged.
- **Primitives:** 32 px controls, primary fill with hover/pressed, arrow-cell forward
  buttons, mono micro-labels, pills with dot (✕ glyph for failed and timed-out states),
  sticky mono table headers, plum selected rows with a signal edge, tabs, notices, errors.
- **App shell:** navigation rail (top bar below 768 px), status bar with the input-policy
  pill, API state, version, a "Reduce atmosphere" toggle and an accessible "Limits"
  disclosure carrying the global safety text (D4).
- **ProjectsPage:** hero band, metric strip (counts from the API list), projects table and
  creation form; empty state with the `crow` and the creation form.
- **ProjectPage:** eyebrow header, metric strip, sample cards with version tables, activity;
  empty state with the `scavenger`.
- **RunPage (incremental):** bracketed run header, metric strip under the header, numbered
  sections, `[01]` step indices with tool-version badges, neutral findings with tool badges,
  evidence inspector docked beside the table at ≥ 1280 px. No character art.
- **404:** `nohead` in its original `field` polarity.

## Validation

| Check | Result |
|---|---|
| Frontend typecheck, ESLint | Clean |
| Vitest | 20 files, 123 tests passed (101 existing + 22 new: shell, placements, token contrast) |
| Playwright (real `bytasm serve` + worker) | 22 passed, including the new `m1-visual.spec.ts` and every existing axe and 360 px check |
| M1 screens at 1440, 1024, 390, 360 px | No page-level horizontal scroll; 0 axe violations (WCAG 2.0/2.1/2.2 A and AA tags); no request leaves Bytasm's origin |
| Reduced motion / atmosphere | Motion tokens are 0 under `prefers-reduced-motion`; the atmosphere toggle hides art and survives a reload |
| Backend ruff, mypy strict, pytest | Clean; 887 passed, 23 skipped (existing platform-specific skips) |
| Character art | 39 tests: outputs equal a fresh build, builds byte-identical, sources equal the references, only paper removed, retained glyphs identical to `field`, annotated openings transparent, restored artwork kept |

Screenshots are written to `frontend/test-results/m1/` by `m1-visual.spec.ts` (not
committed). They are review material, not pixel baselines.

## Not done in M1 / open

- **Owner review of the rendered screens** (FRONTEND_ROADMAP §11) is still required before
  M1 is accepted.
- The real-Ghidra browser lane (`scripts/check-ghidra-browser.mjs`) was not run; the Ghidra
  workspace styling changed only through shared tokens and primitives.
- VersionPage, Import, Rules, Tools, Compare and Report pick up the new tokens and primitives
  but were not redesigned (M2+).
- No 2x art masks yet (landing, M6). Branding stays provisional (D5).
- The Projects metric strip counts samples from the project list (`sample_count`); there is
  no cross-project activity API (X1).
