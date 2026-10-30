# Post-PR6: understandable, evidence-led review

## Inspected baseline and ownership

2026-10-30: clean `feat/v0.4-capa-reports` at `ef7566a`, tracking its origin
branch. Read-only PR metadata confirms PR6 merged at `97936e4` on main.
The checkout is deliberately retained: no pull, fetch, branch switch, reset,
staging, commits or publication. The implementation already contains PR6's
complete head, including the narrow-screen annotation fix. Logs/scratch for
this task stay inside the repository's ignored test cache.

## Requirements map

| Requested area | Verified existing behavior | P0 decision |
|---|---|---|
| Deterministic summary | Four reviewed paragraphs, step states, counts, comparison counts; no explanations of individual rules | Add a bounded reviewed explanation catalog, cautious hypotheses and exact evidence/provenance navigation; no AI. |
| File overview | Identity/header/tool provenance, section/import/export tables | Add labelled raw-section-size and 0–8 entropy bars with the existing exact table; disclose denominator and import provenance. No new parser fields or invented zeros. |
| Strings | ASCII / ASCII-subset UTF-16LE, >=6 chars, <=5,000 rows / 256 chars, query/encoding/paging/run scope | Add stable sorting, three conservative heuristic categories and counts, unique containing-section references; hide path-like values by default in UI. No URL auto-links or string exports in single-version JSON. |
| Findings/evidence | YARA byte ranges and capa virtual addresses, original JSON, rules snapshots, citations | Reuse exact records for a connected review panel and canonical-snapshot report explanation cards. Preserve truncation and missing states. |
| Reports | Immutable schema 2/3/4 JSON, schema 4 preview/escaped offline HTML | Keep all published schemas unchanged. Enrich new summary text within the existing string-list contract; old stored summaries remain authoritative when rendering historical HTML. |
| Isolation | Resource-limited subprocesses, minimal env, process-group cleanup; hardened non-root Compose worker with outbound network | Give Compose worker `network_mode: none` and verify it. Native workers and LIEF in the API remain outside a complete isolation boundary. No input-policy expansion. |
| SQLite/queue/license | SQLite and one claim-loop worker; ADR-0003 proposed; capa 10.0.0 + two Apache-2.0 rules | Preserve engine/queue/ADRs. No new dependencies/rules/fixtures. ida-settings license remains unresolved; no redistribution clearance inferred. |

P1 follow-ups: project-wide dashboard, broader corpus search, editable profiles,
backup/restore and extra parser metadata. Each requires a separate scoped API,
privacy, compatibility and performance review; none gets a placeholder control.
Long-term blueprint is unchanged. This is a product increment, not gate I1.

## Verification plan

First use focused unit/integration tests for explanation catalog hash gating,
unknown rules, incomplete states, literal string filters, sorting/grouping,
section ambiguity, path privacy, canonical HTML escaping and immutable reports.
Then frontend unit/build and the complete Playwright/axe 360 px workflow, serially
with lint to avoid generated-data cleanup races. Final: make check, make e2e,
make verify-fixtures, make audit, make compose-check, isolated Compose hardening
and demo; Linux ARM64 3.12/3.14 where available. Attempt AMD64 only with supported
execution; report failure rather than claiming coverage. Preserve all old fixture
bytes and reports. No real user database or volume is used for tests.

## Implemented contracts and interpretation policy

The P0 guide uses a self-authored catalog for the five existing Bytasm YARA-X
rules and two existing capa environment rules. An explanation is selected only
for its exact tool, installed version, rule identifier and pinned rules SHA-256.
Unknown combinations explicitly have no reviewed interpretation. The catalog
explains the actual matched condition: e.g. KERNEL32 text is not an import-table
assertion; a loader-path string does not verify PT_INTERP; an UPX-style declared
section name does not prove packing; a capa API feature does not prove execution.
Entries are ordered by tool/rule, not by a threat ranking. One example keeps the
four-paragraph summary concise; up to 12 linked observations and three locations
each are available in the guide, with explicit cap notices and original JSON
pointers. Tool/rule/adapter versions and the run/version scope stay visible.
Missing, failed or unavailable steps never supply an interpreted observation.
The glossary describes observations, offsets, virtual addresses and hypotheses.
No AI, score, verdict, behavior chain or external service is involved.

`RunOut.review` is an additive typed presentation field. The read-only
`GET /api/v1/reports/{id}/review` verifies a schema 4 stored snapshot and derives
the same bounded presentation without reading later live findings. Legacy
schemas get an explicit unsupported-view response, not an invented empty result.
The JSON report schema itself is unchanged: richer new summary paragraphs fit
its existing string-list contract. Historical JSON bytes are untouched. HTML
now renders the stored summary verbatim with escaping, rather than recomputing
old paragraphs using current templates. The explanatory view identifies template
version 1. Original filename provenance remains available behind a privacy
expander; basename display avoids exposing directory components by default.

Section charts use the sum of declared raw section sizes as their explicit
size denominator, not file coverage. Overlaps are not deduplicated. A zero or
unsafe denominator suppresses the size bars; entropy uses its exact 0–8 scale
and omits missing measurements. Only the first 24 sections are plotted, while
the existing table retains every exact record and permissions. Import invocation
and selected version identify the source. API display strings preserve exact
64-bit virtual addresses, sizes and header addresses beyond JavaScript numeric
precision. These remain header declarations, not verified loading addresses.

The strings explorer retains the stored <=5,000 / 256-character bounds and now
reads at most 5,001 rows before refusing an oversized/corrupt record set. It
supports offset, decreasing full length, displayed-prefix and category ordering,
with deterministic offset/encoding/id ties; it never sorts by an unrecorded full
truncated value. Three text-shape heuristics are deliberately small:

- URL-like: a value begins with an HTTP(S) prefix followed by non-whitespace.
- Path-like: an absolute POSIX, drive, UNC or ./ / ../ prefix is present.
- Other: no such prefix. This is not a finding or a meaningfulness classification.

Counts cover all stored strings in the explicitly selected run before filters;
category grouping is page-local and labelled. Filters are literal and local;
there is no regex/query-language or network lookup. Path-like values are hidden
by default in the UI and revealed only through a labelled checkbox. This is
visual privacy, not encryption/redaction of stored data: the local API and
existing explicit raw downloads retain bounded original values. No value is
an automatic link. A section reference is emitted only for one declared raw
section containing the entire stored string byte range, within the file size;
ambiguous, crossing or absent ranges say no unique containing section. No virtual
address is inferred. Links from a run pin its run_id, including older runs;
query scope rejects a run from another version/project. Source links open the
exact evidence panel, including after an in-page hash navigation.

## Isolation and compatibility

Compose worker now uses `network_mode: none`; configuration and live-container
checks require it. SQLite/file-backed jobs and heartbeat need no service network.
The API retains its loopback-published bridge interface, so LIEF import children
still have outbound access. Native processes retain their user's privileges and
network access. Existing minimal env, no shell, size/time/CPU/memory/process caps,
read-only per-step sample files/rules, process-group cancellation/recovery and
cleanup are preserved. macOS cannot enforce RLIMIT_AS and remains fixture-only.
The shared writable data volume, same-UID parser access and descendants escaping
a process group remain residual risks. This is not gate I1 or complete sandboxing.
No sample execution or dynamic-analysis entrypoint was added.

No migrations, database/queue changes, dependency changes, rule/fixture additions
or report-schema changes are required. Tests exercise unchanged migration head
and historical downloads. capa/rules versions and hashes are unchanged;
ida-settings redistribution uncertainty remains blocked. No license is inferred.

## Bounded follow-ups

P1 dashboard/corpus search/editable profiles/backup/restore remain deferred:
they need separate transactional/scoping/privacy and recovery contracts. Import
library-to-function grouping is also deferred: the inspected v0.1 adapter stores
flat imported names without library associations. No grouping is fabricated.
Resources, certificates, compiler/debug records and extra heuristic categories
require separately bounded extraction and reviewed semantics. No placeholder
buttons, crawling, network sample search or admission expansion were added.

The production CLI disables Uvicorn access logs so local search values in URLs
are not logged; API/worker startup messages omit the data directory. A real
server/worker subprocess test demonstrated the prior query/path leak and verifies
its absence after the change. Configured structured lifecycle logs stay intact.
The scripted demo adds a twelfth review/explorer check, and the new end-to-end
fixture journey covers chart → analysis → reviewed hypothesis → exact evidence →
run-pinned strings/category/privacy/grouping → section → snapshot/HTML at 360 px.

## Acceptance checklist

| Acceptance criterion | Status and review boundary |
|---|---|
| Deterministic summary: identity, actual step coverage, observations, cautious interpretation, limitations | Complete for existing stored records. Existing complete/partial/failed/cancelled/unsupported/unavailable/skipped/no-match templates remain covered. Reviewed hypotheses require exact rule provenance. |
| File overview, section sizes, entropy, exact locations, missing values, source scope | Complete for stored metadata. The new section map has labels, units, denominator, version/import source and a full table alternative. |
| Additional metadata and imports grouped by library | Deferred: current adapter does not retain import-to-library associations; no resource/signature/debug extraction is added. |
| Bounded string search/filter/sort/group, counts, caps, source run and exact section references | Complete for the three documented prefix categories. Missing/ambiguous section containment is explicit; groups are page-local. |
| Evidence navigation, exact tool/rule/run provenance, analyst separation | Complete using existing evidence/citation records and bounded explanation cards. Capa virtual addresses are never converted to file offsets. |
| Canonical report preview/export and historical preservation | Complete without a new schema or migration. Stored summaries and JSON bytes remain authoritative; explanations are a separately versioned view. |
| Practical process isolation and privacy | Partial: offline non-root Compose worker and checked limits; native worker/API import children still have host-user/network access. No complete sandbox claim. Production access logs no longer retain query values. |
| Connected fixture → analysis → evidence → strings → report workflow, comparison retained | Complete within P0. Existing comparison categories and explicit compatibility states remain available; new summary identifies both source runs. |
| P1 dashboard/search/editable profiles/backup-restore | Deferred as separately bounded follow-ups; no hidden or fake actions. |
| Broader admission, dynamic analysis, AI interpretation and risk scores | Deliberately excluded by the task's trust boundary. |
| Dependency redistribution | Blocked by the existing ida-settings license gap; this increment adds no dependencies or redistributed content. |

## Verification boundaries

Tests use temporary SQLite/blob/report directories, admitted repository fixtures,
and synthetic malformed test data. The Compose check uses only project
`bytasm-review-next-20261030`, its own image and its own named volume, forwarded
to loopback port 18841. The demo forwards Host as `127.0.0.1:8000` to preserve the
container request guard; no guard is relaxed. `make compose-down` and a final
project-scoped `down --volumes` remove only that test project. Existing containers
and data volumes are left running. Native demo data is created and deleted under
the ignored repository test cache.

The existing capa fixture was rebuilt twice from its self-authored source using
the already-cached toolchain, no network and read-only source. Both output files
were written only to ignored scratch directories and matched the committed bytes:
`aaea303376ac91c45074181f915cc6d479499865f7412ff572ff9b36984f52a5`.
The fixture was never launched. No existing fixture was overwritten. Full historic
fixture regeneration is not needed for this increment and was not performed.

The no-network property is verified from Docker's actual worker network mode;
this is not evidence of complete host isolation. Limits, malformed/crashing
children, cancellation, timeout/output floods, restart, concurrency and cleanup
are exercised by the existing full backend suite. No adversarial containment
proof or broader-input clearance is claimed. Native macOS cannot supply Linux
RLIMIT_AS or /proc controls. AMD64 launch fails with `exec format error`; no AMD64
backend tests execute on this machine.

## Executed verification (2026-10-30)

Final native commands use `TMPDIR="$PWD/backend/.pytest_cache/next-product/tmp"`
from the repository root. Focused tests earlier in development also used pytest's
ordinary temporary directories; no existing application database was supplied.
Logs and rebuild outputs are ignored scratch, not part of this change set.

| Exact command/check | Observed result |
|---|---|
| `make check` (with the TMPDIR above) | Exit 0: Ruff formatting/lint; mypy 125 source files; Python 3.14 backend 597 passed, 4 platform skips; frontend lint/types and 67 unit tests. One existing Starlette/httpx deprecation warning. |
| `make verify-fixtures` | Exit 0: all 10 manifest entries match. |
| `TMPDIR=... UV_CACHE_DIR="$PWD/backend/.pytest_cache/next-product/uv-cache" make audit` | Exit 0: pip-audit no known vulnerabilities; npm 0 vulnerabilities. Only dependency identities/versions are queried. |
| `make compose-check` | Exit 0: API and offline-worker settings accepted. |
| `make compose-up` with the isolated project/override described below | Exit 0: build, health, live non-root/capability/seccomp/readonly/tmpfs/resource/port/network assertions pass. |
| `make demo` (with TMPDIR above) | Exit 0: all 12 steps pass against a throwaway native server/worker; data removed. |
| Compose `run_demo` through the local forwarding client below | Exit 0: all 12 steps pass, including Full capa, canonical schema 4 HTML and selected-run review/strings. |
| `make compose-down`, then `docker compose down --volumes` with that same isolated project/override | Exit 0: only the dedicated test services/network/volume removed. |
| `./scripts/check-linux.sh linux/amd64 3.12` | Exit 255: `exec /usr/bin/sh: exec format error`; no AMD64 test ran. |
| `uv --directory backend run --no-sync python -m bytasm.reports.model` into ignored scratch, then `cmp schemas/report.schema.json <scratch-output>` | Identical; no published schema change. |
| Two cached-toolchain fixture builds and `cmp` against committed capa fixture | Identical bytes; source read-only, network none, no binary execution. |
| `git diff --check`, changed/new-file review and bounded secret/path/artifact scan | Clean; no detected secret signatures, personal absolute paths, generated/runtime files or unexpected fixtures in the proposed changes. Index stays empty. |

The first full check exposed one test fixture that still constructed a networked
worker; its baseline was updated to require the new offline property. The first
full E2E exposed two broad `/Evidence/` selectors after the explanatory region
was added; selectors now target the original `Evidence:` panel exactly. A new
244-character filename test reproduced 1,632 px of horizontal overflow at 360 px;
wrapping the run/report summary fixed it and its focused E2E passed. A live CLI
regression test reproduced search-query access logging before the fix and passed
afterwards. These intermediate failures are retained in ignored local logs;
only successful final runs are reported as passing.

Isolated Compose invocation prefix (the override sets both image names to
`bytasm-review-next:local` and replaces the API port with `127.0.0.1:18841:8000`):

```sh
COMPOSE_PROJECT_NAME=bytasm-review-next-20261030 \
COMPOSE_FILE="$PWD/compose.yaml:$PWD/backend/.pytest_cache/next-product/compose-override.yaml" \
TMPDIR="$PWD/backend/.pytest_cache/next-product/tmp" make compose-up
```

The same project/file prefix was used for shutdown and volume removal. The
container demo ran with `uv --directory backend run --no-sync python -`:

```python
import runpy
module = runpy.run_path('../scripts/demo.py')
Client = module['Client']
class ForwardedClient(Client):
    def request(self, method, path, body=None, headers=None):
        return super().request(method, path, body, {
            **(headers or {}), 'Host': '127.0.0.1:8000'
        })
module['run_demo'](ForwardedClient('http://127.0.0.1:18841'))
```

CI is not triggered or inspected as proof for this uncommitted increment. No
Windows run, full historical fixture rebuild, backup restore, external-sample
analysis, hostile-sample containment or image redistribution approval is claimed.
All added repository copy is English. Branch/head and upstream are unchanged;
Git use is read-only and all implementation changes remain unstaged/uncommitted.

Final successful UI/platform results already observed:

- `TMPDIR="$PWD/backend/.pytest_cache/next-product/tmp" make e2e`: exit 0,
  15 passed, including axe/keyboard, comparison, Full capa, report HTML, the new
  source-linked review journey, long filename and 360 px checks. Build succeeds.
- `./scripts/check-linux.sh linux/arm64 3.14`: exit 0; Python 3.14.8, aarch64,
  Ruff/mypy clean, 599 passed and 2 environment skips (repository Compose-file/
  Docker-CLI check and the non-Linux refusal test). One existing deprecation warning.
- The first concurrent `make check-linux PLATFORM=arm64` (Python 3.12.15) had
  598 passed, 2 skipped and one fixture-import timeout before the strings-timeout
  assertion. That test configures a one-second parser limit. This is not counted
  as a pass; a serial repeat without changing limits/code follows below.

## Changed-file map

- Backend presentation: new `review.py` and `string_review.py`; additive API
  changes in `api/analysis.py`, `api/reports.py`, `api/routes.py`, `api/schemas.py`
  and `api/views.py`; deterministic `plain_summary.py`, stored-summary rendering
  in `reports/html.py`, privacy in `cli.py`.
- Frontend: new `ReviewPanel.tsx` and `SectionMap.tsx`; typed API client and
  RunPage/VersionPage/ReportPage integration; narrow-layout styles. No new route
  with a placeholder action.
- Verification: new unit review/string tests, real integration review/privacy
  tests, frontend EvidenceReview tests and evidence-review E2E; existing API
  route allowlist, Compose tests and exact evidence selectors updated. E2E helper
  optionally supplies a long display filename while retaining the same fixture
  bytes. Demo and Compose configuration/live checks exercise actual behavior.
- Documentation: README, SECURITY, API/report/demo guides, the historical v0.4
  milestone cross-reference and this acceptance/verification record. Blueprint,
  ADRs, schema files, dependency locks, notices, migrations, tools/rules and fixture
  bytes remain unchanged.

Final serial ARM64/Python 3.12 result: `TMPDIR="$PWD/backend/.pytest_cache/next-product/tmp" make check-linux PLATFORM=arm64`
exited 0: Python 3.12.15, aarch64; formatting/lint and mypy 125 files clean;
599 passed, 2 environment skips, one existing deprecation warning in 164.28 s.
The earlier import timeout did not reproduce once other suites stopped. Resource
contention is a plausible explanation, not proven causality; the one-second test
limit and production code were not changed for the repeat.
