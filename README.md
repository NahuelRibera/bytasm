# Bytasm

Bytasm is a **local-first static binary-analysis workbench** for PE and ELF
files, **in early development**. It reads a binary's bytes and reports what the
file declares about itself (format, architecture, sections, imports) plus a few
measurements (such as per-section entropy). It never runs the file.

It is a local web app (on `127.0.0.1` only, natively or in a hardened Docker
container) and a command-line tool (`bytasm inspect`). You import a binary, see its SHA-256 and LIEF
metadata, export a reproducible JSON report, and (v0.2, in review) run an
analysis that extracts its strings and matches Bytasm's own YARA-X rules
against it, then inspect each match's byte evidence.

> **Status:** v0.1 milestones M0–M5 are implemented, with a hardened local
> Compose setup, a dependency audit and a scripted demo (see
> [`docs/milestones/v0.1-m2-m5.md`](docs/milestones/v0.1-m2-m5.md)). v0.1.0 is
> **not tagged**: the release gate still needs green hosted CI and a recorded
> demo. The v0.2 scope (strings extractor, YARA-X pattern matching, a
> background worker with multi-step runs, `partial` and cancel, findings in the
> JSON report) is implemented on branch `feat/v0.2-yara-x-rules`, not merged
> and not reviewed; see
> [`docs/milestones/v0.2-pattern-matching.md`](docs/milestones/v0.2-pattern-matching.md).
> Not suitable for real-world analysis.

## Supported inputs and security limits

Read this before using Bytasm.

- **Self-authored binaries only.** By default (`fixtures` mode) Bytasm accepts
  a file only if its SHA-256 is listed in
  [`fixtures/MANIFEST.sha256`](fixtures/MANIFEST.sha256). That check runs
  **before** any parser sees the file. A refused file is not parsed or stored.
- **Not for downloaded, received, third-party, or suspicious binaries.** Bytasm
  uses LIEF, a C++ parser, and has no isolation that would contain a parser
  exploit. No mode accepts such files. That would first need the isolation
  gate I1 and an independent security review (blueprint §5.4.3).
- **Bytasm never executes the files it imports.** It only reads them.
- **The parser process is not a security sandbox.** LIEF runs in a separate
  child process with resource limits (memory, CPU time, output size, a 30 s
  timeout). That limits the damage from parser *bugs* such as crashes, hangs,
  or memory blow-ups. The child runs as the same user with the same file and
  network access, so it does **not** contain a parser *exploit*.
- **The v0.2 analysis tools run the same way.** Before each step (strings,
  then YARA-X) the worker re-checks the input policy and the stored file's
  SHA-256, then runs the tool in a separate, resource-limited child process.
  That is not a sandbox either.
- **A rule match is not a verdict.** It means a rule's pattern was found in
  the bytes. It needs interpretation and does not show a file is malicious; no
  match does not show a file is safe.
- **Docker Compose is not a sandbox either.** The container runs as a
  non-root user with no capabilities, a read-only root filesystem, and memory,
  CPU and process limits. The parser still shares that container, its user,
  its data volume and its network with the API.
- **macOS:** the parser's memory limit (`RLIMIT_AS`) cannot be applied on
  macOS, so a native macOS run is for Bytasm's fixtures only. The CPU, file
  size, and timeout limits still apply. `/api/v1/health` reports
  `parser_memory_limit_enforced`.
- **Optional `self_built` mode** (off by default) also accepts binaries you
  compiled yourself from source you wrote. It is enabled **only** by local
  server configuration (`BYTASM_INPUT_POLICY=self_built`) and **only on
  native Linux** (the Compose container refuses it, see
  [ADR-0002](docs/adr/0002-v0.1-implementation-choices.md)). No API request,
  header, or UI control can enable it. While it is
  on, the UI shows a banner, and every imported version and report records
  `admitted_under: self_built_optin`. This rests on your word: it is a
  provenance rule, not a safety check.
- **Local only, no accounts.** Natively, the server refuses to bind to a
  non-loopback address; in Compose, the port is published on the host's
  `127.0.0.1` only. It answers only requests addressed to `127.0.0.1`,
  `localhost`, or `[::1]` on its port, refuses other origins, and requires a
  custom header on every change.

## Responsible use

Analyse only software you wrote or are clearly authorised to analyse. Each
import records an authorisation statement. That statement is a
**self-attestation** for your records. It is not proof of permission and not a
legal determination. See [`SECURITY.md`](SECURITY.md).

## Quick start

Requirements: [uv](https://docs.astral.sh/uv/) (it provides Python 3.12+),
Node.js 26 with npm, and, for the container, Docker with Compose v2.
Everything installs into the project (`backend/.venv`, `frontend/node_modules`)
from lock files. Nothing is installed globally.

```sh
make install       # backend/.venv from uv.lock, frontend/node_modules from package-lock.json
```

Then start Bytasm in **one** of two ways. Both serve http://127.0.0.1:8000/ in
fixtures-only mode.

```sh
make compose-up    # recommended: the hardened Linux containers (memory limit enforced)
make compose-down  # stop them; data stays in the `bytasm-data` volume

make serve         # or natively: server + worker (Ctrl+C stops both); on macOS without the memory limit
```

`make compose-up` builds the UI on the host, builds the image (its Python
dependencies come from `uv.lock`), checks the Compose settings, starts the
containers (`api`, and the v0.2 `worker`, which publishes no port) and checks
the settings the kernel applied.

Then open http://127.0.0.1:8000/ and follow these steps:

1. Create a project.
2. **Import a binary**: choose a fixture from `fixtures/bin/` (for example
   `hello_v1-x86_64.exe`) and write a short statement such as "I built this
   from Bytasm's fixtures/src". The statement is a self-attestation.
3. The sample overview shows the SHA-256, size, format, header metadata
   ("declared in file"), the input policy that admitted the file, sections with
   entropy, imports, and exports.
4. Click **Export JSON report** to download the report.
5. **Run pattern matching…**, confirm, and watch the run finish. Inspect a
   finding to see the matched bytes (offset, length, hex, printable text) and
   the exact rule text. **Rules** in the top bar shows the bundled rule set and
   validates it.

A file that is not in the manifest is refused with "The file was not parsed
or stored." A renamed ZIP is refused by its content.

**Data.** Native runs keep a SQLite database plus content-addressed files in
`./data/` (git-ignored, never served over HTTP); delete that folder to start
over. Compose keeps them in the `bytasm-data` volume; `docker compose down
--volumes` deletes it.

Configuration is read from the environment once, at start-up:

| Variable | Default | Meaning |
|---|---|---|
| `BYTASM_DATA_DIR` | `<repo>/data` | Database, stored files, reports, temp uploads |
| `BYTASM_HOST` | `127.0.0.1` | Must be loopback (`127.0.0.1`, `::1`, `localhost`) |
| `BYTASM_PORT` | `8000` | TCP port |
| `BYTASM_INPUT_POLICY` | `fixtures` | `fixtures`, or `self_built` (native Linux only) |

The image sets `BYTASM_CONTAINER=1` (container mode, see ADR-0002); it is
refused outside a container.

## Demo

```sh
make demo                                        # throwaway server on 127.0.0.1:8765
make demo DEMO_ARGS="--keep-running"             # ... and keep it up to look at the UI
make demo DEMO_ARGS="--url http://127.0.0.1:8000"   # against `make compose-up` or `make serve`
```

The script imports `fixtures/bin/hello_v1-x86_64.exe` (after checking its hash
against the manifest), shows the input-policy refusals, prints the metadata the
UI shows and its URL, and exports the JSON report and validates it against the
schema, then starts a YARA-X run and checks every reported byte range against
the fixture. It only reads the fixture; it never runs it and never calls an
external service. Cleanup and the 2-minute walkthrough are in
[`docs/demo.md`](docs/demo.md).

## Features in v0.1

- **Guarded import.** The file is sent as a raw request body (at most 64 MiB),
  hashed while it streams, and checked against the input policy before any
  parsing. Archives and other formats are refused. Imports are all or nothing:
  a refused, failed, timed-out, or interrupted import leaves no rows, stored
  file, temp file, or process behind.
- **Metadata.** LIEF metadata comes from the separate parser process:
  format, architecture, bitness, endianness, entry point, header fields,
  sections with per-section Shannon entropy (a measurement, not a verdict),
  imports, and exports.
- **Storage by hash.** Files are stored at `data/blobs/sha256/aa/bb/<sha256>`,
  read-only. Their hashes are re-verified before every report export.
- **Samples and versions.** A sample is a logical program, and each version is
  one exact file. Duplicate versions are refused. The same bytes in another
  sample reuse the stored file.
- **JSON report.** The report is versioned, schema-validated, and
  reproducible: two exports differ only in `generated_at`. See
  [`docs/report-format.md`](docs/report-format.md) and
  [`schemas/report.schema.json`](schemas/report.schema.json).

## Analysis runs (v0.2)

- **Steps.** A run of the default profile has two steps, in order: the
  built-in **strings** extractor (printable ASCII and UTF-16LE runs of at
  least 6 characters, with file offsets; at most 5,000 kept, each value cut
  to 256 characters) and **YARA-X** with the bundled rules. Header metadata
  comes from the import and is not repeated.
- **Statuses.** `queued → running → succeeded | partial | failed | cancelled`.
  `partial`: at least one step kept results and another did not (failed,
  timed out, or not run); the run page, the findings and the report say which.
  `failed`: no step kept results. Cancel stops the current step's process;
  steps that had finished keep their results. Processed by `bytasm worker`
  (one per data directory).
- **Bundled rules.** `rules/yara/` holds Bytasm's own descriptive rules (one
  rule per file, five today), shipped with the code and the image. They are
  read-only in the UI; changing them is a code change. Each rule set is
  identified by the SHA-256 of its exact text, and every run keeps a copy.
- **Findings and evidence.** Each matching rule is a finding with byte ranges
  (offset, length, up to 32 bytes) that Bytasm checks against the stored file.
  No severity, score, or verdict. Strings are observations, never findings.
- **Where to look.** The run page (steps, partial banner, technical log, a
  text search over findings, the raw JSON output of each finished step), the
  **Strings** tab of a sample version (search, encoding filter, paging), and
  the JSON report (schema version 2: findings with evidence, string counts).
- Details and API shapes:
  [`docs/milestones/v0.2-pattern-matching.md`](docs/milestones/v0.2-pattern-matching.md);
  decisions: [ADR-0003](docs/adr/0003-v0.2-pattern-matching.md) (proposed).

The HTTP API (`/api/v1/...`, OpenAPI at `/api/openapi.json`) is described in
blueprint §7.2 and, for v0.2, the milestone record. Errors are problem-details JSON with fixed messages. Text from
the parser process is never shown.

## `bytasm inspect` (CLI)

```sh
uv --directory backend run bytasm inspect ../fixtures/bin/hello_v1-aarch64.elf
```

It accepts only manifest fixtures and prints deterministic JSON (sorted keys,
no timestamps, no absolute paths). Since M2 it also parses in the separate,
resource-limited process; its output is unchanged from M1.

| Exit code | Meaning | Error codes |
|---|---|---|
| 0 | Report printed | — |
| 1 | Operational problem | `file_not_found`, `manifest_error` |
| 2 | Input refused or parsing failed (usage errors print to stderr) | `unknown_hash`, `empty_file`, `file_too_large`, `unsupported_format`, `malformed_input`, `parse_failed`, `parse_timeout`, `adapter_failed` |

**Entropy** is Shannon entropy in bits per byte (0–8), measured by Bytasm over
each section's bytes *in the file*. Sections with no file bytes (such as
`.bss`) get `null` ("no file data"). Bytasm applies no threshold and never
labels a file as good or bad.

## How it works

```
browser (SPA, same origin) ──HTTP──► bytasm serve (FastAPI, 1 process, 127.0.0.1)
                                      │ guards: loopback, Host, Origin, X-Bytasm-Request
                                      │ stream body → SHA-256 → manifest check → header checks
                                      ├─spawn/wait/kill─► python -I -m bytasm.adapters.metadata_lief
                                      │                   (own process group, rlimits, clean env,
                                      │                    re-hashes its input, writes result.json)
                                      ├─► SQLite (data/bytasm.sqlite3)
                                      └─► data/{blobs,outputs,reports}/sha256/…

bytasm worker (v0.2, same data directory, no port)
  claims a queued run; for each step: re-checks input policy and blob SHA-256
  ├─spawn/wait/kill─► python -I -m bytasm.adapters.strings_extract (same runner and limits)
  ├─spawn/wait/kill─► python -I -m bytasm.adapters.yara_x_scan     (+ rule-set SHA-256)
  └─► each step's validated rows (strings, or findings + evidence), one transaction per step
```

The adapter contract and the lifecycle are in blueprint §5.4.1 and §5.6. The
milestone record lists what each step does and which test proves it.

## Known limitations

These are the outcomes of the implementation questions Q1–Q8. Details are in
[`docs/milestones/v0.1-m2-m5.md`](docs/milestones/v0.1-m2-m5.md).

- **Not a sandbox.** A parser exploit would run as your user, with your files
  and network. That is why only self-authored files are accepted.
- **Process escape (Q4).** A process started by the parser that calls
  `setsid()` leaves the process group and is not killed by the timeout. If it
  keeps the output pipe open, the import fails. If it closes the pipe, it is
  not detected. In Compose, `pids_limit` bounds how many such processes can
  exist and `init: true` reaps them; stopping the container ends them.
- **Memory limit on macOS (Q5).** The parser memory limit is not applied on
  macOS, so native macOS runs are fixtures-only.
- **Disconnects (Q1/Q2).** An upload that is interrupted is rejected. If the
  browser goes away while the file is being parsed, the import still completes
  (verified with the pinned uvicorn and Starlette versions).
- **Same-user access (Q6).** On Linux the server hides its environment from the
  child (`PR_SET_DUMPABLE`), but a same-user process can still read the
  database and stored files.
- **One import at a time.** A second import (or a rule validation) gets
  "busy, try again" (HTTP 503).
- **v0.2 runs need the worker.** Without `bytasm worker`, runs stay queued; the
  run page warns about it. One run per sample version at a time.
- **SQLite holds the job queue** (ADR-0003, proposed): one worker per data
  directory, polling every 0.5 s. Tested for one local user; not designed for
  several workers or hosts.
- **Header values are declared, not verified.** Timestamps and other header
  fields can be forged or zeroed.
- **The container shares everything with the parser.** Inside it, the server
  listens on the container's own interface; the host-side binding to
  `127.0.0.1` is Docker's port publishing, and outbound network access is not
  restricted ([ADR-0002](docs/adr/0002-v0.1-implementation-choices.md)).
- **Single platform tested locally.** The containers and `make check-linux` were
  run on linux/arm64 only. linux/amd64 is covered by CI configuration, which
  has not run for the v0.2 branch yet.

## Troubleshooting

| Symptom | What to do |
|---|---|
| "The Bytasm UI is not built" | Run `make web-build` (or use `make serve` / `make compose-up`, which build it). |
| Port 8000 already in use | Stop the other process, or run natively with `BYTASM_PORT=8001 make serve`. For Compose, change both sides of `127.0.0.1:8000:8000` and `BYTASM_PORT`. |
| "Host not allowed" (400) | Open Bytasm as http://127.0.0.1:8000/ or http://localhost:8000/, not by another host name or IP. |
| "Refused by the input policy" (403) | Only files listed in `fixtures/MANIFEST.sha256` are accepted. Check with `make verify-fixtures`. |
| "Busy" (503) | Another import is being parsed. Wait a few seconds. |
| `self_built mode requires Linux` / `is refused in container mode` | Expected: `self_built` only works natively on Linux. |
| `make e2e` cannot find Chromium | Run `npx --prefix frontend playwright install chromium` once. |
| `make compose-up` fails on `docker compose` | Docker with Compose v2 must be running. `make compose-check` validates the file without starting anything. |
| A run stays "Queued" | No worker is running for this data directory: use `make serve` / `make compose-up`, or run `make worker` next to a separately started server. |
| `another bytasm worker is already using this data directory` | Expected: only one worker per data directory. |
| An error panel shows a request ID | Find that ID in the server output (`docker compose logs api` for Compose). Logs contain IDs, hashes and codes, never file contents. |


## Fixtures

Self-authored C programs in [`fixtures/src/`](fixtures/src) are compiled into
[`fixtures/bin/`](fixtures/bin). Toolchains, exact versions, and build commands
are in [`fixtures/BUILD_INFO.txt`](fixtures/BUILD_INFO.txt).

| Fixture | What it is |
|---|---|
| `hello_v1-aarch64.elf` | AArch64 ELF executable |
| `hello_v1-aarch64-stripped.elf` | The same, stripped |
| `entropy_blob-aarch64.elf` | AArch64 ELF with a 4 KiB high-entropy `.blob` section and a `.bss` array |
| `hello_v1-x86_64.elf` | x86-64 ELF executable (PIE, dynamically linked against glibc) |
| `hello_v1-x86_64-stripped.elf` | The same, stripped |
| `hello_v1-x86_64.o` | x86-64 ELF **relocatable object** (not a linked executable) |
| `hello_v1-x86_64.exe` | PE32+ x86-64 console executable (MinGW-w64) |
| `exports_v1-x86_64.dll` | PE32+ x86-64 DLL exporting two named functions |

Bytasm *parses* PE and ELF files of any architecture LIEF supports, but it is
*tested* only on these fixtures and on bytes the tests generate in memory.

## Development

```sh
make check             # backend: ruff, mypy, pytest; frontend: eslint, tsc, vitest
make e2e               # Playwright end-to-end tests against real local servers
make audit             # pip-audit (locked) over uv.lock, npm audit over package-lock.json
make compose-check     # assert compose.yaml's security settings (no container started)
make demo              # scripted demo (see above)
make worker            # only the analysis worker, next to a separately started `bytasm serve`
make verify-fixtures   # check fixture bytes against MANIFEST.sha256
make check-linux       # backend checks in a linux/arm64 container (PLATFORM=amd64 also)
make schemas           # regenerate schemas/report.schema.json
make fixtures          # rebuild fixtures (Docker + clang; never runs them)
make measure           # parse time and peak memory (see docs/measurements/)
```

`make e2e` uses the Chromium build pinned by `@playwright/test`. If it is
missing, run `npx --prefix frontend playwright install chromium` once.

CI (`.github/workflows/ci.yml`) runs the manifest check and the backend checks
on Python 3.12 and 3.14, the frontend checks with `npm audit`, and the
Playwright suite (with a worker), `make audit`, and a Compose job that checks
both containers and runs the demo against them. It never rebuilds fixtures.

Repository layout:

```
backend/src/bytasm/
  api/        FastAPI app, request guards, import, report, rule/run/finding endpoints, static UI
  jobs/       v0.2 run lifecycle, YARA-X step, background worker
  runner/     adapter child: limits, supervision, timeouts, cleanup
  adapters/   LIEF metadata and YARA-X adapters, entropy, result schemas
  rules.py    bundled rule set loader and snapshot
  intake/     manifest, input policy, identification, streaming upload, persistence
  db/         SQLAlchemy models and Alembic migrations
  reports/    report model (schema source) and generator
backend/tests/  unit, integration (runner, API, live uvicorn), fake adapters
frontend/       React + TypeScript UI (src/), Playwright tests (e2e/)
schemas/        report.schema.json
rules/yara/     Bytasm's own YARA-X rules (shipped in the image)
scripts/        Linux check, Compose and container checks, demo, measurements
compose.yaml, Dockerfile   the local container (fixtures-only)
fixtures/       self-authored sources, committed binaries, MANIFEST.sha256
docs/           blueprint, scope review, ADRs, milestone record, report format
```

## Roadmap

Next: close the v0.1 release gate (green hosted CI, a recorded demo), then
review v0.2 (ADR-0003, hosted CI on the branch). Deferred from v0.2:
`activity_event`, a findings review-state filter (review states need v0.3
annotations), and a positive fixture for the UPX-style rule. Everything beyond
that is possible, not promised (blueprint §3–§4).

## Licence

Not chosen yet. Licensing is an open decision in the blueprint (§13.2), so this
repository has no `LICENSE` file for now.

Third-party: [LIEF](https://lief.re) (Apache-2.0),
[YARA-X](https://virustotal.github.io/yara-x/) (BSD-3-Clause), FastAPI, Starlette, Uvicorn,
SQLAlchemy, Alembic, Pydantic, React, TanStack Query, Vite (see the lock
files for versions).
