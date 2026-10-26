# MVP Scope Review — decision record for `PROJECT_BLUEPRINT.md` revisions 0.2 and 0.3

> **Status: ACCEPTED AND APPLIED.**
> - Revision 0.2 decisions (§1–§9) were applied on 2026-10-26.
> - The revision 0.3 security correction (**§11**) was applied the same day. It limits v0.1 to self-authored inputs and adds gate I1.
> - The final v0.1 input-policy decision and the Q1 clarification (**§12**) were applied after that.
>
> This document is kept as the **decision record**. Where it differs from `PROJECT_BLUEPRINT.md`, **the blueprint is authoritative**: §3.4 for input policy, §5.4.1 for the v0.1 lifecycle, §5.4.3 for gate I1, and §12.1 for the release gate.
> Passages marked **⚠ Superseded (rev 0.3)** are kept for history only. §11 explains what replaced them and why.
> The long-term vision stays intact: the roadmap (blueprint §4), the hosted and dynamic-analysis safeguards (§8.3), and the data-science ideas (§10). Only the order of delivery changes.
>
> Labels: **Verified** means checked against official documentation on 2026-10-26 (sources in §10). **Recommendation** means an engineering judgement open to challenge. **Assumption** means it still needs evidence.

---

## 1. Recommended v0.1 in one paragraph

> **⚠ Superseded (rev 0.3):** "built or are authorised to analyse" is replaced by "self-authored only": Bytasm's fixtures by default, or programs the user compiled from their own source as an opt-in. See §11.

v0.1 is a single vertical slice. A user imports a PE or ELF file they built or are authorised to analyse, and records an authorisation self-attestation. Bytasm streams the upload under a size limit and computes SHA-256. It checks the file type by content, rejects archives, and parses the file with LIEF in a **separate, resource-limited subprocess** that the API waits for. The file goes into hash-addressed storage. The UI shows identity, header metadata, sections (with entropy as a *measurement*), imports, and exports, and the user can download a deterministic, schema-validated **JSON report**. Nothing else is in v0.1. YARA-X starts only after this slice has been released.

---

## 2. Included / deferred

| Capability | v0.1 | Deferred to | Why |
|---|---|---|---|
| Projects (create/list, name + description) | ✅ | — | Container for samples |
| Samples and versions (version label) | ✅ | — | Cheap now. Avoids a migration when comparison arrives. |
| Authorisation self-attestation (basis + statement) | ✅ (`owned_or_built` only, rev 0.3) | Other bases: gate I1 | Responsible-use record (§7) |
| Input policy: fixture-manifest allowlist (default), `self_built` opt-in | ✅ (added rev 0.3) | — | Keeps untrusted bytes away from a parser with no isolation boundary (§11) |
| Streaming upload, size limit, SHA-256, duplicate detection | ✅ | — | Core intake |
| Content-based PE/ELF validation, archive rejection | ✅ | — | Core safety |
| LIEF metadata: headers, sections, imports, exports | ✅ | — | The first useful view of a binary |
| Per-section entropy computed by Bytasm (measurement) | ✅ | — | Cheap, and teaches the concept honestly (§6) |
| Sample overview UI | ✅ | — | Shows the result |
| JSON report (schema + determinism test) | ✅ | — | The canonical, reproducible artefact |
| `analysis_run` + `tool_invocation` provenance rows | ✅ | — | Records what ran, which version, how long, and the outcome |
| Built-in strings extractor | — | v0.2 | Not needed to prove the slice |
| YARA-X + `finding`/`evidence` model + findings UI | — | v0.2 | Starts only after the v0.1 release gate passes |
| Background worker process, multi-step runs, cancel button, `partial` status | — | v0.2 (trigger-based, §3.1) | One fast step doesn't need them |
| Notes and annotations (all kinds, revisions, citations) | — | v0.3 | Not part of the import → metadata → report workflow (§3.3) |
| Version comparison | — | v0.3 | Needs two analysed versions and stable fingerprints |
| capa | — | v0.4 | Heaviest integration, with documented limitations to explain |
| HTML report + preview screen | — | v0.4 | A rendering of the JSON. It needs its own escaping and CSP work. |
| Tools/profile screen, editable profiles, activity log UI | — | v0.3+ | LIEF version already appears in the overview and the report |
| Hardening beyond §3.2 | — | Release gates in §3.2 | Proportional to a private local app |
| Ghidra headless, corpus search, function diffing, SARIF, teams, AI, dynamic analysis, hosting | — | Blueprint §4 (renumbered v0.5+) | Unchanged long-term vision |

---

## 3. Decisions

### 3.1 Analysis execution in v0.1 — **Decision: Option A (accepted)**

| Criterion | A. API waits for a limited subprocess | B. Minimal background worker process |
|---|---|---|
| Implementation complexity | Lowest. One subprocess runner module, no second process to deploy. | A second entrypoint and container, a job-claiming loop (`SELECT … FOR UPDATE SKIP LOCKED` on `analysis_run`), status polling in the UI |
| Request reliability | Bounded by the parse timeout (default 30 s). LIEF on a ≤ 64 MiB file is expected to be well under that (**assumption**: measure it in M1). | Request returns immediately, and the work survives client disconnects |
| Parser isolation | Separate OS process with rlimits, a clean environment, and a temp working directory. It **shares the API container's filesystem view**. | The same process-level limits, plus a separate container that can mount blobs read-only and hold fewer secrets |
| User experience | Import returns "validated" or "rejected" with metadata in one step, with no polling | "Queued → Running → Done" states. Better for slow steps, extra UI states otherwise. |
| Fit for local, single-user use | Good: one user, one fast step | More machinery than one fast step needs |

**Why A:** validation already requires a full parse (blueprint J3), so in v0.1 "import" and "extract metadata" are the same action. Making them asynchronous adds a process, a claim loop, polling, and new failure modes (stuck runs, a worker that is down), and none of these improve the slice. The subprocess runner and the adapter contract are what v0.2 reuses. Moving to B later changes *who calls* the runner, not the runner itself.

**Non-negotiable:** the untrusted parser never runs inside the API process. The API only spawns and supervises it.

> **⚠ Superseded (rev 0.3), framing only.** The decision for Option A stands, but the table above and the text below treated the subprocess as "parser isolation". It is **not** an isolation boundary: the subprocess shares the API container's user, filesystem view, reachable secrets, and network. It is a robustness control against parser bugs, and it is acceptable **only for self-authored inputs**. See §11.

**How the API supervises the subprocess** (as proposed. The applied, more detailed version is blueprint §5.4.1):

| Concern | Design |
|---|---|
| Launch | Use `python -m bytasm.adapters.metadata_lief --input <tmpfile> --out <tmpdir>/result.json` through an asyncio subprocess, so the event loop is not blocked. Pass `start_new_session=True` (or `process_group=0`), use the default `close_fds=True`, `cwd=<fresh tmpdir>`, and an **explicit minimal `env`** with no database URL or other secrets. Do not use `preexec_fn`: Python documents it as "NOT SAFE to use in the presence of threads" (**verified**). |
| Resource limits | The adapter entrypoint lowers its own limits with `resource.setrlimit` **before importing LIEF**: `RLIMIT_AS` (e.g. 1 GiB), `RLIMIT_CPU` (e.g. 20 s), `RLIMIT_FSIZE` (e.g. 32 MiB). A process may lower its own limits (**verified**, Python `resource` docs). A wall-clock timeout in the API is the backstop. |
| Process limit | Use `pids_limit` on the API container. The adapter has no reason to spawn children. `RLIMIT_NPROC` isn't used because Linux counts it per user (**to verify**: `setrlimit(2)`), and the API shares that user. |
| Output-size limit | stdout and stderr are read through bounded readers (e.g. 64 KiB each, kept only for diagnostics, control characters stripped). The result file is capped by `RLIMIT_FSIZE`, and its size is checked again before it is read. |
| Timeout | On timeout, `SIGTERM` the process group, wait 2 s, then `SIGKILL`. The user sees "The file could not be parsed within 30 s. It was not imported." *Corrected when applied:* the import is all-or-nothing, so a timed-out import persists **no** run or invocation rows. The outcome is recorded in structured logs (hash, size, reason code, duration). |
| Partial output | **Never parse output from a process that timed out, was killed, or exited non-zero.** Only a zero exit plus a result file that passes size and schema validation counts as success. |
| Client disconnect / request cancellation | Import is all-or-nothing. A `finally` block always kills the process group and deletes the temp directory. Database writes happen in one transaction, and the blob is moved into storage only after the transaction is ready to commit. If the request is cancelled mid-parse, the result is no sample version, no blob, no orphan process, and the user retries. (**To verify in M3**: how the chosen ASGI server signals client disconnects to handlers. The `finally` design is safe either way.) |
| Concurrency | *Accepted value:* **one** parser subprocess at a time (provisional; revisit after measuring resource use). Further imports get a clear "busy, retry" response (HTTP 503 with `Retry-After`) before their body is read. |
| Cleanup | Per-request temp directory under a non-served path, removed in `finally`. On startup, the API also deletes stale temp directories older than 1 h. |
| Provenance | Even in A, one `analysis_run` with one `tool_invocation` is recorded: tool and adapter versions, arguments, exit code, duration, status, and result hash. |

**Triggers to move to Option B** (any one is enough):

1. A step is added whose typical runtime on fixtures exceeds ~10 s, or which needs a timeout above 30 s. capa (v0.4) and Ghidra will.
2. Multi-step runs, a user-facing cancel button, or `partial` status are needed (planned with v0.2's strings + YARA-X).
3. Measured LIEF parse time at the 64 MiB limit gets close to the request timeout.
4. Before any configuration where the API container holds secrets or is reachable beyond localhost. B then lets the parser run in a container with a read-only blob mount and no credentials.

> **⚠ Superseded (rev 0.3):** "B … lets the parser run in a container with … no credentials" overstated what a worker gives. A worker that both claims jobs from PostgreSQL and parses still holds DB credentials. Separation from secrets and network requires **gate I1**: a distinct network-less analyzer container with a file-spool hand-off (blueprint §5.4.3).

### 3.2 Basic vs advanced hardening

Containers reduce blast radius. They are **not** a complete security boundary: Docker's documentation says default capabilities and mounts "may provide incomplete isolation" (**verified**).

**Must exist in v0.1:**

| Safeguard | Notes |
|---|---|
| Streaming upload size limit (default 64 MiB), enforced mid-stream; empty files rejected | Matches OWASP size-limit guidance (**verified**) |
| Content-based validation (magic bytes + full LIEF parse); extension and `Content-Type` recorded but never trusted | OWASP: Content-Type is "trivial to spoof", and signature checks shouldn't stand alone (**verified**) |
| Archive rejection (ZIP, gzip, 7z, RAR, tar signatures) | No extraction code means no archive bombs |
| Hash-derived storage paths; user filename stored only as display text; blob store outside any served path; downloads as `application/octet-stream` attachments via ID lookup | OWASP generated filenames and storage outside webroot (**verified**) |
| No automatic third-party submission of files or hashes | Product principle |
| Parser runs outside the API process with time, memory, CPU, output, and process limits (§3.1) | — |
| Safe rendering: React default escaping; lint rule banning `dangerouslySetInnerHTML`; filenames, section and symbol names, and diagnostics always shown as text; control characters stripped from logs; JSON report served as an attachment | OWASP XSS guidance on framework escape hatches (**verified**). Test: a generated fixture copy with an HTML-like section name renders escaped. |
| Localhost-only port binding (`127.0.0.1:…`) | OWASP notes published Docker ports can bypass UFW (**verified**) |
| **Host-header allowlist** (`localhost`, `127.0.0.1`) and a **required custom request header** on state-changing endpoints | Without it, any web page the user visits could POST a crafted file to the local, unauthenticated API (cross-site request) and reach the parser. A few lines of middleware. (Recommendation) |
| Containers run as non-root; **no Docker socket**; **no host-home or project-directory bind mounts**; only the named data volume | The Docker socket gives control of the host (**verified**, Docker + OWASP Docker CS rule 1) |
| `cap_drop: [ALL]` and `no-new-privileges:true` on the API container | Two lines each, and they are OWASP Docker rules 3–4 (**verified**). Pulled into v0.1 because they cost almost nothing. |
| Logs contain IDs, hashes, sizes, durations, and statuses only | No sample bytes or extracted names |
| Disclosure in README and on the import screen: *"Bytasm parses untrusted files. A crafted file could exploit a parser bug; Bytasm limits but cannot eliminate this risk. The authorisation field is a self-attestation, not proof of permission."* | **⚠ Superseded (rev 0.3):** this wording implied v0.1 was meant for untrusted files. Replaced by the "self-authored only; not safe for downloaded, received, third-party, or suspicious files; never executed; limits ≠ sandbox" disclosure (blueprint §2 J2, §8.2). |
| `SECURITY.md`, lock files, `pip-audit`/`npm audit` in CI | Cheap hygiene before the repository is public |

**Later release gates:**

| Gate | Safeguards added |
|---|---|
| **Before a public repository or demo video** | GitHub private vulnerability reporting enabled (**verified**: available for public repos), SBOM artefact (Syft), secret scanning, a CI check asserting the §3.2 compose settings |
| **Before multi-step / slow tools (v0.2+)** | Option B worker container: read-only blob mount, no credentials beyond what it needs, read-only root filesystem + tmpfs, `internal: true` network with no internet egress. **⚠ Superseded (rev 0.3):** the network and credential separation moved to gate I1, where the analyzer uses `network_mode: none`. `internal: true` still reaches other services on that network. |
| **Before any non-self-authored input (gate I1, rev 0.3)** | Analyzer container with no network, no secrets, and read-only inputs; boundary tests; threat model; independent review (blueprint §5.4.3) |
| **Before any non-localhost access** | Authentication, refusal to start on non-loopback without auth, a strict CSP for the SPA, CSRF tokens |
| **Before hosting** | Blueprint §8.3 unchanged: multi-user authorisation, TLS, quotas, encryption at rest, retention policy, independent security review, legal/privacy review. Production observability stack. Signed release artefacts and SLSA provenance. |
| **Before dynamic analysis** | Blueprint §8.3 unchanged: hardware-virtualised disposable guests, network containment, specialist review |

### 3.3 Plain-text notes — **Recommendation: out of v0.1, introduced in v0.3**

The v0.1 workflow (import → validate → inspect → report) is complete without notes. Adding a plain-notes table in v0.2 and then reshaping it in v0.3 is throwaway work. Notes arrive once, in v0.3, with the full annotation model (kinds, revisions, citations). They are stored separately from tool output, as before.

### 3.4 ARM64 fixture — **Recommendation: include one AArch64 ELF fixture in v0.1, with a strict fallback**

- **Two different architectures:** Bytasm's *host/container* architecture (e.g. `linux/arm64` on an M-series Mac, `linux/amd64` in CI) is independent of the *target* architecture recorded in the binary being inspected. LIEF reads headers and does not execute target code, so they don't need to match (Recommendation, from how static parsing works).
- **Why include it:** cross-compiling `hello_v1.c` for AArch64 needs one extra cross-compiler package in the pinned fixture-build image. CI never rebuilds fixtures. It only reads the committed bytes and checks `MANIFEST.sha256`. The fixture proves Bytasm doesn't assume x86-64.
- **Fallback:** if the AArch64 build takes more than about half a day to get working, drop it. v0.1 then states: *"Parses PE and ELF files of any architecture LIEF supports; tested on x86-64 PE and ELF fixtures. An AArch64 fixture is a later compatibility milestone."*
- **Wording rule:** say "tested architectures" (the fixtures) separately from "parsed architectures" (whatever LIEF reports). The UI shows the architecture **as declared in the file header**.

---

## 4. v0.1 data model, API, and report

- **Tables:**
  - `project`, `sample`, `sample_version`
  - `authorization_record` (with `terms_reference`)
  - `analysis_run` (statuses `succeeded`/`failed`, plus `failure_reason`)
  - `tool_invocation`
  - `section` (incl. `entropy`, `entropy_method`; `NULL` when the section has no file bytes)
  - `symbol` (imports and exports)
  - `report`
  - The `analyst`, `finding`, `evidence`, `annotation`, `rule_set`, `analysis_profile`, and `activity_event` tables come later.
- **Endpoints:**

  ```
  GET/POST /projects
  GET      /projects/{id}
  GET      /projects/{id}/samples
  POST     /projects/{id}/imports           (applied form: raw body + X-Bytasm-Import metadata header)
  GET      /sample-versions/{id}
  GET      /sample-versions/{id}/sections | /imports | /exports | /download
  POST     /sample-versions/{id}/reports
  GET      /reports/{id}/download
  GET      /health
  ```
- **JSON report:** a single document per sample version. It contains `schema_version`, `generated_at`, generator version and image ID, sample identity, an `authorization` block with `"type": "self_attestation"` and its notice text, the run/invocation with tool versions, metadata including per-section entropy objects (`value`, `unit`, `method`, `computed_by`), and a `limitations` list. It must validate against `schemas/report.schema.json`, and two exports must differ only in `generated_at`.

---

## 5. Milestones

| # | Outcome | Acceptance criterion | Why it comes before the next |
|---|---|---|---|
| **M0 Foundations** | Repository bootstrap, LICENSE, `SECURITY.md`, ADR-0001 (stack + Option A), CI lint, Compose with PostgreSQL | Clean clone → `docker compose up db` works, CI green | Reproducible base |
| **M1 Fixtures + inspect CLI** | Self-built fixtures (PE x86-64, ELF x86-64, AArch64 ELF per §3.4, high-entropy-section ELF), `MANIFEST.sha256`, `BUILD_INFO.txt`. `bytasm inspect` (LIEF + entropy) prints JSON. LIEF confirmed on `linux/arm64` and `linux/amd64`. | Unit tests assert metadata per fixture. Entropy matches an independent Shannon implementation. Parse time at the size limit is measured and recorded. | Learn PE/ELF before building around them |
| **M2 Subprocess runner** | Adapter launcher with self-applied rlimits, clean env, process-group kill, bounded output, schema validation | Fake-adapter tests: success, hang → `timed_out`, crash, invalid JSON, oversized output, memory blow-up → killed. No orphan processes. | The safety core every later tool reuses |
| **M3 Intake API** | Schema, streaming upload, validation, runner call, hash storage, all-or-nothing transaction, Host/custom-header middleware | API tests: accept PE/ELF, reject ZIP/empty/oversize/truncated header (generated), duplicate detected, cancellation leaves no blob or temp files | The UI needs stored, parsed samples |
| **M4 UI** | Projects, import form (basis options + disclosure), sample overview (identity, metadata, sections with entropy labelled as a measurement, imports, exports) | Playwright happy path. Hostile section name rendered escaped. Keyboard-only import possible. | Results must be visible before the report |
| **M5 JSON report → tag v0.1.0** | Report schema, generator, download | §5.1 gate passes | Completes the slice |
| M6 (v0.2) | Strings + YARA-X + findings/evidence; switch to Option B if §3.1 triggers fire | Every finding's evidence bytes match the file at the offset | — |
| M7 (v0.3) | Annotations (notes first) + version comparison | Known v1 → v2 diff reproduced exactly | — |
| M8 (v0.4) | capa + HTML report | XSS fixture escaped. capa limitations shown. | — |

### 5.1 v0.1 release gate

> **⚠ Superseded (rev 0.3):** the authoritative release gate is now blueprint §12.1. It adds input-policy checks, the disclosure wording, answers to Q1–Q8, the short-body check, and explicit container limits. The list below is kept for history.

- [ ] README quick start from a clean machine to the UI in < 15 minutes.
- [ ] All committed fixtures import with the expected metadata (asserted in tests).
- [ ] ZIP, empty, oversize, and generated truncated-header inputs are rejected with clear messages. The API keeps serving.
- [ ] A hanging fake adapter is killed at the timeout. No orphan process or temp directory remains.
- [ ] A cross-site POST without the custom header, or with a foreign `Host`, is refused.
- [ ] The hostile section-name test passes in the UI.
- [ ] The JSON report validates, and two exports differ only in `generated_at`.
- [ ] Compose file shows: localhost binding, non-root, no Docker socket, no home mounts, `cap_drop: [ALL]`, `no-new-privileges`, `pids_limit`.
- [ ] CI green: lint, types, unit + integration tests, one Playwright test, dependency audit.

---

## 6. Entropy: measurement in v0.1, and what YARA-X can and cannot do

**Verified (official YARA-X documentation, 2026-10-26):**

- The `math` module defines `entropy(offset, size)`, which "Returns the entropy for `size` bytes starting at `offset`". The result is a float from 0.0 to 8.0. `offset` "is a file offset in bytes, or a virtual address when scanning a running process". The page does **not** say what happens if the range extends past the end of the data.
- The PE module's `Section` structure exposes `name` (string), `raw_data_offset`, and `raw_data_size` (integers), among other fields. The ELF module's `Section` structure exposes `name` (string), `offset`, and `size` (integers), plus `type`, `flags`, and `address`.
- Neither module exposes a per-section entropy field.
- The ELF module page shows iteration with `for any section in elf.sections : ( … )`.

**What is technically possible (inferred from the documented features, not tested and not shown as a combined example in the docs):** a rule can pass a section's offset and size to the entropy function. For example: `for any section in pe.sections : ( math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2 )`. Behaviour for sections whose declared range is malformed or out of bounds is undocumented.

**Recommended v0.1 design:**

1. Bytasm's metadata adapter computes Shannon entropy (bits/byte) over each section's **in-file bytes** and stores it as a measurement with its method and adapter version.
2. Edge cases:
   - Sections with no file bytes (ELF `SHT_NOBITS` such as `.bss`, or PE sections with raw size 0) get `entropy = NULL` and the label "no file data".
   - Sections whose declared range runs past end-of-file get `NULL` plus a warning "declared range exceeds file size".
3. v0.1 produces **no finding** from entropy and applies **no threshold**. The UI and report say: *"Descriptive measurement. High values are common in compressed or encrypted data, and also occur in legitimate resources; a value alone does not show packing, encryption, or malicious intent."*
4. v0.2 YARA-X rules cover byte/string patterns and checks on documented fields, such as a section `name` of `UPX0`, labelled "UPX-style section name", not "packed". Bytasm does not duplicate entropy logic in YARA-X, to keep one source of truth. If a threshold is ever shown, it is a labelled heuristic with the threshold value visible.

---

## 7. Fixtures and authorisation

- **Default fixtures are compiled from C sources written for Bytasm** and committed with their build recipe. They carry basis `owned_or_built` and depend on no third party's terms.
- **A publicly downloadable file is not automatically authorised for analysis.** Licences and EULAs may restrict reverse engineering or redistribution.
- **Any external fixture** needs its licence or terms checked first, to confirm they permit the intended analysis and, if committed, redistribution. The reference is recorded in `terms_reference`.
- **Basis options:**
  - `owned_or_built`
  - `written_permission` (with a reference note, nothing uploaded)
  - `public_fixture_terms_permit` (requires a licence/terms reference)

  > **⚠ Superseded (rev 0.3):** only `owned_or_built` is offered in v0.1. The other two bases describe untrusted inputs and are enabled only after gate I1. External fixtures are likewise usable only after gate I1.
- **The authorisation field is a self-attestation for record-keeping.** Bytasm does not verify it, and it is not proof of permission or a legal determination. This wording appears in the import form, the sample overview, and every report.
- **⚠ Needs specialist legal review** before Bytasm is distributed for others' use (blueprint §8.4, unchanged).

---

## 8. Checklist of edits to `PROJECT_BLUEPRINT.md` (applied 2026-10-26)

All items below were applied. §10 of the blueprint (data-science opportunities) was intentionally left unchanged.

- [x] **Header / How to read:** add a pointer to the release plan (v0.1–v0.4) and to this review.
- [x] **§1.4:** change "Run a small, pinned set of static tools in background jobs" and "Export JSON and static HTML reports" to per-release wording.
- [x] **§1.6 A5:** re-baseline the estimate to the v0.1 slice (M0–M5).
- [x] **§2 J1:** remove the `activity_event` mention from v0.1.
- [x] **§2 J2:** replace the basis options with §7. Add `terms_reference`. Add the untrusted-file disclosure.
- [x] **§2 J3:** state that validation, parsing, and metadata extraction happen in one synchronous import (Option A), with the all-or-nothing behaviour.
- [x] **§2 J4–J9:** relabel "MVP/Later" as v0.1/v0.2/v0.3/v0.4. Note that J5's "Run analysis" button and run page arrive with v0.2.
- [x] **§3 table:** split into v0.1 vs later per §2. Replace the YARA-X entropy example with §6.
- [x] **§3.1:** update the "Many formats/architectures" row with the tested-vs-parsed wording (§3.4).
- [x] **§4:** insert v0.1–v0.4 rows. Renumber Ghidra headless → v0.5, profiles/corpus → v0.6, function diffing/SARIF → v0.7, teams → v0.8, AI → v0.9.
- [x] **§5.1:** reword boundary 1 to "the API never parses untrusted input in-process. In v0.1 it supervises a limited subprocess. From v0.2 (per triggers) a separate worker does." Mark the diagram as the v0.2+ target.
- [x] **§5.4:** record Option A for v0.1 and the triggers for B. Defer the Procrastinate vs hand-rolled claim-loop choice to v0.2.
- [x] **§5.6:** set YARA-X → v0.2, capa → v0.4. Add "metadata adapter computes section entropy". Add the self-applied rlimits and the no-`preexec_fn` rule to the adapter contract.
- [x] **§5.7:** note that `linux/arm64` verification is LIEF-only in v0.1.
- [x] **§5.9:** add a v0.1 summary line alongside the v0.2+ architecture.
- [x] **§6:** tag entities by release (§4). Add `entropy`, `entropy_method`, nullable rules. Add `terms_reference`. Remove "section with entropy > 7.2" as a finding example.
- [x] **§7.1–7.3:** tag screens and endpoints by release. The v0.1 states are loading/empty/error/rejected; `partial`/cancelled arrive with v0.2.
- [x] **§8.2:** add a "Release / gate" column per §3.2. Move `cap_drop` and `no-new-privileges` into v0.1. Add Host allowlist + custom header to v0.1. Move the worker-container items to the v0.2 gate.
- [x] **§9.1:** tag tests by release. Add the subprocess-runner tests (M2), the entropy cross-check, and the cross-site POST test.
- [x] **§9.2:** change "used for entropy rules" to "used to test the entropy measurement". Make the AArch64 fallback explicit. Generate the hostile-name fixture in tests rather than committing it (PE section names are limited to 8 bytes).
- [x] **§12:** replace M0–M11 with §5.
- [x] **§13.1:** remove the `untitled folder/` bullet. It no longer exists as of this review's inspection.
- [x] **§13.4–13.5:** update milestones and issues to match §5. The first issues are ADR-0001, bootstrap, fixtures + LIEF arm64/amd64 check, inspect CLI, runner, intake, UI, report.
- [x] **§13.8:** add a 2-minute v0.1 demo (import → rejection of a renamed ZIP → overview → JSON report → CI). Keep the 5-minute script as the v0.4 target.
- [x] **§14:** add the YARA-X `math`/`pe`/`elf` module pages and the Python `subprocess`/`resource` docs to the sources.

---

## 9. Decisions (accepted 2026-10-26) and refinements made while applying them

**Accepted decisions:**

| # | Decision | Where in the blueprint |
|---|---|---|
| D1 | **Option A:** the API may wait for LIEF, but LIEF always runs in a separate, resource-limited subprocess. It never runs in the API process. No persistent job queue in v0.1. | §5.1, §5.4.1 |
| D2 | **FastAPI** (Django not chosen). The API runs as a single server process in v0.1. | §5.3 |
| D3 | **Provisional defaults**, to be reviewed after measuring the M1 fixtures: 64 MiB upload limit, 30 s parser timeout, 1 GiB parser memory limit (`RLIMIT_AS`) | §5.4.1, §12 M1 |
| D4 | **One analysis subprocess at a time.** Concurrency is revisited after measuring resource use. | §5.4.1 |
| D5 | **AArch64 ELF fixture** included only if it can be built and tested within half a day. Otherwise it is documented as a later compatibility milestone. | §3.3, §9.2 |
| D6 | All agreed basic upload and local-processing safeguards are preserved in v0.1 | §8.2 (Release / gate column) |
| D7 | Notes and annotations are out of v0.1 and arrive together in v0.3 | §2 J7, §6 |
| D8 | Entropy is a Bytasm measurement with no threshold or finding. The YARA-X capability is documented, but YARA-X is not used for entropy. | §3.2 |

**Refinements made while applying them** (not new scope, but corrections or precision that the proposal lacked):

1. **Raw-body upload instead of multipart.**
   - The import endpoint is `POST /projects/{id}/imports`, with the binary as `application/octet-stream` and the metadata in an `X-Bytasm-Import` header (≤ 8 KiB). The header doubles as the required custom header.
   - Reason: FastAPI/Starlette form parsing is expected to receive the whole body before the handler runs, which would defeat a mid-stream size limit (*to verify in M3*).
   - With this design, metadata is validated before any file bytes are read.
2. **The parser slot is checked before reading the body.** A busy server answers 503 without receiving the upload.
3. **Rejected imports persist nothing.** Revision 2 said a timed-out import records a failed run. That contradicted "all-or-nothing", and the contradiction is resolved in favour of all-or-nothing. Rejections are logged with hash, size, reason code, and duration.
4. **Fixed reason codes.** The adapter exits with code 2 plus one code from a fixed list for rejected input. The API shows only its own messages, never adapter text.
5. **Integrity re-checks.** The upload is re-hashed before it is stored, and blobs are re-verified on download and report export. A compromised parser runs as the same user and could otherwise tamper with files. **⚠ Superseded (rev 0.3), framing only:** the re-checks catch accidental modification. They are not a defence against a compromised same-user parser, which could also alter the database.
6. **Accepted residual risks stated explicitly** (blueprint §5.4.1, "Known limitations"):
   - DB and filesystem are not atomic together (mitigated by a startup sweep).
   - The parser shares the API's user, container, and network. Outbound network access is not restricted in v0.1.
   - Orphaned children if the API dies (mitigated by `init: true`).
   - Resource limits are guaranteed only in the Linux container.
   - No syscall filtering.

   Option B (the v0.2 worker container) removes the user, container, and network sharing. **⚠ Superseded (rev 0.3):** only gate I1 removes them (§11). These risks are acceptable in v0.1 only because inputs are self-authored.
7. **Client disconnects described precisely.**
   - During upload, a disconnect means nothing is persisted.
   - During parsing, the disconnect is not relied upon. A successful parse is committed even if the browser left.
   - If the server cancels the handler, the `finally` cleanup runs. Server-specific behaviour is to be verified in M3.
8. **The `analyst` entity moved to v0.3** with annotations, consistent with the v0.1 table list in §4.

**Still open, assigned to milestones (not blocking):**

- The *to verify* items in blueprint §5.4.1 and §14.3: Starlette buffering, disconnect signalling, cancellation-safe cleanup, `/proc/<pid>/environ` and `PR_SET_DUMPABLE`, `RLIMIT_NPROC`, macOS `RLIMIT_AS` (M2/M3).
- Measured parse time and peak memory, and the review of D3/D4 (M1).
- The background-worker library for v0.2 (Procrastinate vs a hand-rolled claim loop).

---

## 10. Sources (consulted 2026-10-26)

| Source | Supports |
|---|---|
| https://virustotal.github.io/yara-x/docs/modules/math/ | `entropy(offset, size)`, 0.0–8.0 range, offset semantics. Out-of-range behaviour not documented. |
| https://virustotal.github.io/yara-x/docs/modules/pe/ | PE `Section` fields: `name`, `raw_data_offset`, `raw_data_size`, …. No entropy field. |
| https://virustotal.github.io/yara-x/docs/modules/elf/ | ELF `Section` fields: `name`, `offset`, `size`, `type`, `flags`, `address`. `for any section in elf.sections` example. |
| https://virustotal.github.io/yara-x/docs/api/python/ | (v0.2) `pip install yara-x`, `Scanner.set_timeout()`, match `offset`/`length` |
| https://docs.python.org/3/library/subprocess.html | `preexec_fn` "NOT SAFE … in the presence of threads". `start_new_session`, `process_group` (3.11+). `close_fds=True` default. |
| https://docs.python.org/3/library/resource.html | `RLIMIT_AS`, `RLIMIT_CPU` (SIGXCPU), `RLIMIT_FSIZE`, `RLIMIT_NPROC`. Processes may lower their own limits. |
| https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | Content-Type untrusted, signature checks insufficient alone, generated names, size limits, storage outside webroot, ZIP caution, CSRF on upload |
| https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html | Framework escape hatches, safe sinks |
| https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html | Rules 1–4 (socket, user, capabilities, no-new-privileges), 5a (ports vs UFW), 7–8 (limits, read-only) |
| https://docs.docker.com/engine/security/ | Daemon control = host control. Default isolation "may provide incomplete isolation". |
| https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository | Private vulnerability reporting for public repos |

**Not verified here:** how the chosen ASGI server propagates client disconnects; Linux `RLIMIT_NPROC` per-user accounting (`setrlimit(2)`); LIEF wheel availability on `linux/arm64`; actual LIEF parse times. Each is assigned to a milestone above.

---

## 11. Revision 0.3 security correction (accepted and applied 2026-10-26)

### 11.1 The gap

Revision 0.2 ran LIEF in a separate subprocess with resource limits, inside the API container. Its known-limitations table admitted that a parser exploit would run as the API's user, with the API container's filesystem view, reachable secrets, and network access. Yet the import screen still invited users to import "untrusted files", and three bases (`written_permission`, `public_fixture_terms_permit`) described third-party inputs. In practice, v0.1 would have parsed arbitrary binaries without any isolation boundary. **A subprocess with resource limits is not a security sandbox.**

### 11.2 Options considered

| | **A. Keep Option A, limit v0.1 to self-authored inputs** (chosen) | **B. Add a separate analysis worker/container to v0.1 and accept other binaries** |
|---|---|---|
| What it protects | Parser *bugs* on trusted-origin input. Untrusted bytes never reach the parser in the default mode. | Parser *exploits* partly contained: no network, no secrets, read-only inputs. Still a shared kernel. |
| v0.1 effort | Small: hash allowlist + config flag + UI/README wording + tests | Large: a second and third container, spool protocol, orchestrator, boundary tests, review. Roughly the v0.2 worker plus gate I1 pulled into v0.1. |
| Honesty of claims | Easy to state truthfully: "self-authored only, not a sandbox" | Requires an independent review before any "suitable for third-party binaries" claim |
| Learning curve | Keeps v0.1 focused on PE/ELF basics and a working slice | Front-loads container-security work before the product exists |
| Product value of v0.1 | Lower: fixtures and own programs only | Higher, if the boundary is sound |
| Risk of silently broadening the MVP | None | High |

**Decision:** A. **v0.1 is a self-authored-input prototype for local learning and demos.** Option A remains appropriate for that scope. B's design is kept as **gate I1** (blueprint §5.4.3), which must pass before any non-self-authored input is accepted.

### 11.3 What changed in the blueprint (revision 0.3)

| Blueprint section | Change |
|---|---|
| Header, glossary, §1.1, §1.4 | v0.1 stated as self-authored only; "safe import" wording removed; new terms *self-authored input*, *untrusted input*, *sandbox / isolation boundary* |
| §2 J2, J3 | Input-policy disclosure. Only the `owned_or_built` basis in v0.1. A policy check before parsing. The subprocess described as not a sandbox. |
| §3, §3.3, §3.4 (new) | Gate I1 in the release table. Third-party and potentially malicious binaries listed as deferred. Trust tiers T0/T1/T2 and the four rules that hold in every tier. |
| §4 | Gate I1 row added to the roadmap |
| §5.1 | Boundary 1 is "what gets parsed at all". The subprocess is explicitly not an isolation boundary. |
| §5.4.1 | Scope condition. Documented platform behaviour (verified). Input-policy step (5) before parsing. Explicit kill on `wait_for` timeout. Short-body check. Limitations tied to the self-authored scope. Gate I1 required before wider inputs. Q1–Q8 implementation-time questions. |
| §5.4.2, §5.4.3 (new) | v0.2 worker shaped for I1. Full gate I1 design, requirements, what it still doesn't provide, and exit criteria. |
| §5.7, §5.9 | `fixtures` default. `analyzer` service at I1. Architecture summary per phase. |
| §6, §7 | `admitted_under` field. `owned_or_built` only in v0.1. 403 `input_policy` response and its UI state. |
| §8.1–§8.3 | A "does / does not" table for v0.1. Input policy as the primary control. I1 gate column. T1/T2 prerequisites. Corrected network reasoning (`internal: true` vs `network_mode: none`). |
| §9 | Input-policy tests, extra runner tests (Q3–Q5), disconnect tests (Q1/Q2), CORS test (Q8), isolation-boundary tests (I1). The manifest doubles as the allowlist. External fixtures only after I1. |
| §12, §12.1 (new) | Milestones updated. Gate I1 milestone. The authoritative v0.1 release gate moved into the blueprint. |
| §13 | Issues, README sections, and demos updated. The "sandboxed subprocess" claim in the v0.4 demo corrected. |
| §14 | 15 new official sources. Q1–Q8 and gate I1 listed as unverified. |

### 11.4 Verified facts that drove the correction (official docs, 2026-10-26)

- **Starlette:**
  - `request.stream()` yields chunks without storing the whole body.
  - Uploaded form files are spooled to temporary storage and not limited by `max_part_size`.
  - `ClientDisconnect` is **not** documented on the requests page.
  - https://starlette.dev/requests/
- **ASGI spec:**
  - Disconnects are reported via `http.disconnect` on `receive`.
  - The server is **not required** to cancel the app.
  - https://asgi.readthedocs.io/en/latest/specs/www.html
- **Uvicorn:**
  - Reading is flow-controlled.
  - The docs are **silent** on cancelling the app task.
  - https://uvicorn.dev/server-behavior/
- **Python:**
  - `Popen.communicate(timeout)` does **not** kill the child. `run(timeout)` kills the child only.
  - asyncio `communicate()`/`wait()` have no timeout, and the docs are **silent** on whether `wait_for` kills the child.
  - https://docs.python.org/3/library/subprocess.html, https://docs.python.org/3/library/asyncio-subprocess.html
- **Docker:**
  - No resource constraints apply by default.
  - `network_mode: none` / `--network none` leaves only loopback.
  - A Compose `internal: true` network is "externally isolated" but still reaches services on it.
  - The default seccomp profile is "moderately protective" (~44 of 300+ syscalls blocked).
  - Docker Desktop runs containers in a Linux VM.
  - None of these pages claims containers are a sufficient boundary for hostile code.
  - https://docs.docker.com/engine/containers/resource_constraints/, https://docs.docker.com/engine/network/drivers/none/, https://docs.docker.com/reference/compose-file/networks/, https://docs.docker.com/reference/compose-file/services/, https://docs.docker.com/engine/security/seccomp/, https://docs.docker.com/security/faqs/containers/

### 11.5 Statements the documents now make explicitly

1. v0.1 does not execute uploaded programs, and no planned release before the dynamic-analysis research track does.
2. Self-attestation is not proof of authorisation and not a legal determination.
3. Subprocess and container resource limits reduce some risks (hangs, exhaustion, crash propagation) but do not make parsing untrusted files safe.
4. Accepting unknown or potentially malicious files requires a separate isolation design and review: gate I1 for authorised third-party files (T1), and more for potentially malicious ones (T2).

### 11.6 Still open

- **Q1–Q8** (blueprint §5.4.1): to be answered by tests in M2/M3, or recorded as known limitations in the README before v0.1 ships.
- **Gate I1:** not prototyped. It needs re-verification against current Docker documentation when built, and an independent reviewer. **⚠ Needs specialist security review.**
- ~~Whether `self_built` mode should exist at all in v0.1, or whether v0.1 should be strictly fixtures-only.~~ **Resolved in §12.**

---

## 12. Final v0.1 input-policy decision (accepted and applied 2026-10-26)

**Decision:**

1. **Fixtures-only during initial development and M0–M1.** The SHA-256 must be in the committed `MANIFEST.sha256`, checked before any parsing.
2. **`self_built` is kept as an optional, local-only mode** for binaries the author compiled from source code they authored.
   - Disabled by default.
   - Enabled only through explicit local server configuration.
   - Never through a public or remote user control: no endpoint, header, or UI toggle.
   - The server refuses to start with it on a non-loopback binding.
3. **`self_built` may be enabled only after the M1 acceptance tests pass.**
   - It is a **provenance restriction based on operator self-attestation**.
   - It is **not** a security sandbox, and **not** proof that a file is safe.
4. **v0.1 continues to reject third-party, downloaded, received, or suspicious binaries.** Accepting them requires passing isolation gate I1 **and** the required independent security review. Enabling `self_built` never does this.

**Rationale:**

- Fixtures-only keeps M0–M1 focused on learning PE/ELF with known inputs.
- The fixture manifest makes the default policy enforceable, not just documented.
- Delaying `self_built` until M1 passes ensures the adapter and the entropy measurement are proven on known bytes first.
- Making it local-config-only and loopback-only ensures no visitor or web page can widen the policy.

**Q1 clarification (applied to blueprint §5.4.1, §9.1, §12.1, §14.3):**

- The implementation must consume the ASGI request body **to its completion signal** (`more_body` false). It must handle disconnect and cancellation according to the **pinned** Starlette and Uvicorn versions, and must test interrupted uploads.
- Comparing received bytes with `Content-Length` is an **additional consistency check, not proof** that the request completed. The header may be absent, and the completion signal is what counts.
- This behaviour is **not verified** until the interrupted-upload test exists and passes against the pinned versions. It supersedes refinement 7 in §9 and the Q1 wording in §11.4, where the byte-count check was presented as the fallback.

**Blueprint sections updated:** header; §3.1 table rows; §3.4 (new "Final v0.1 input policy" block, T0 row); §5.4.1 steps 4–5, client-disconnect text, Q1 row; §5.7; §8.2 input-policy row; §9.1 input-policy and upload tests; §9.2 generated-fixture note; §12 M1; §12.1 release gate; §13.5 ADR-0001; §13.7 README; §14.3.
