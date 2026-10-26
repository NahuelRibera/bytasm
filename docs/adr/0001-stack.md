# ADR-0001: Backend stack, v0.1 input policy, and v0.1 analysis execution

- **Status:** Accepted (decisions taken 2026-10-26; recorded 2026-10-26)
- **Sources:** [`PROJECT_BLUEPRINT.md`](../PROJECT_BLUEPRINT.md) revision 0.3 (authoritative) and its decision record [`MVP_SCOPE_REVIEW.md`](../MVP_SCOPE_REVIEW.md) (§3.1, §9, §11, §12)
- **Scope:** v0.1 (milestones M0–M5). Later releases need their own ADRs.

> An **ADR** (Architecture Decision Record) is a short document that explains one decision: what was chosen, why, what else was considered, and what follows from it. This ADR **records** decisions that were already accepted. It does not reopen them. If this file and the blueprint ever disagree, the blueprint wins and this file should be corrected.

---

## 1. Context

Bytasm is a local, single-user web app for static analysis of PE and ELF binaries. v0.1 is a thin vertical slice: import → validate → SHA-256 → LIEF metadata → UI → JSON report. It is built by one developer who is new to reverse engineering.

Three questions had to be settled before writing code:

1. **Which backend framework?** The analysis libraries Bytasm needs (LIEF now; yara-x and capa later) are Python packages.
2. **Which files may Bytasm parse at all?** LIEF is a C++ parser. A crafted file could trigger a parser bug or, in the worst case, an exploit.
3. **How does an import run?** In v0.1, validating a file already requires parsing it, so "import" and "extract metadata" are the same action.

Key term: a **security sandbox** (isolation boundary) is something designed to contain hostile code. A **resource limit** (memory, CPU time, timeout) only stops a program from running too long or using too much. v0.1 has resource limits. It does **not** have a sandbox.

---

## 2. Decisions

### D1. Backend: Python + FastAPI

- Python 3.12+ with **FastAPI**, **SQLAlchemy 2.x**, and **Alembic** migrations. **`uv`** locks dependencies.
- One Python package, `bytasm`, with an `api` entrypoint in v0.1 (a `worker` entrypoint is added from v0.2).
- In v0.1 the API runs as a **single server process**. The one-parser-at-a-time limit (D4) is an in-memory counter, so it only holds within one process.

### D2. Input policy for v0.1

| Phase | What Bytasm may parse | How it is enabled |
|---|---|---|
| Initial development and **M0–M1** | **Fixtures only:** Bytasm's own committed test binaries. The file's SHA-256 must be listed in the committed `MANIFEST.sha256`, checked **before** any parsing. | Default, and the only mode |
| After the **M1 acceptance tests pass** | Fixtures, plus optional **`self_built`**: binaries the author compiled from source code they wrote | Off by default. Enabled **only** by explicit local server configuration (environment variable or config file read at start-up) |
| Before **gate I1** and its **independent security review** pass | **Never:** third-party, downloaded, received, or suspicious binaries, whatever the claimed authorisation | — |

Rules for `self_built`:

- **Local control only.** No API endpoint, UI toggle, request header, or other remote control can enable it or skip the fixture check.
- **Loopback only.** The server refuses to start with `self_built` on if it is bound to anything other than loopback (`127.0.0.1`).
- **Visible and recorded.** A persistent UI banner is shown while it is on. Each sample version records `admitted_under = self_built_optin`, and reports include it.
- **It is a provenance restriction based on the operator's own word**, not a sandbox and not proof that a file is safe. Bytasm cannot verify that a file is self-authored.
- **It is never a path to third-party files.** Only gate I1 plus its review can open that path.

### D3. v0.1 analysis execution ("Option A")

- The import request **waits** for LIEF to finish.
- LIEF **always** runs in a **separate, resource-limited subprocess**. It never runs inside the API process. The API only starts, supervises, and if needed kills it.
- There is **no background worker and no persistent job queue** in v0.1.
- **The subprocess is not a security sandbox.** It runs as the same OS user, in the same container, with the same filesystem view and network access as the API. It reduces the impact of parser *bugs* (crashes, hangs, runaway memory or CPU). It does not contain a parser *exploit*.
- Only output from a subprocess that exited with code 0 and produced a valid, size-checked, schema-validated result is used. Imports are all-or-nothing.

The step-by-step request lifecycle is in blueprint §5.4.1.

### D4. Provisional limits

These are **starting values, subject to measurement after M1**. M1 measures parse time and peak memory on the fixtures and on a synthetic file at the size limit, and then these values are reviewed.

| Setting | Value |
|---|---|
| Upload size limit | **64 MiB** |
| Parser wall-clock timeout | **30 s** |
| Parser memory limit (`RLIMIT_AS`) | **1 GiB** |
| Concurrent analyses (parser subprocesses) | **1** (others get HTTP 503 with `Retry-After` before their upload is read) |

Blueprint §5.4.1 also lists smaller values derived from these (25 s CPU limit, 32 MiB result-file limit, 64 KiB captured output, and so on). They are provisional in the same way.

### D5. When this design must change

- **Move to a background worker** (v0.2, or earlier) if any one of these happens: a step needs more than 30 s or typically takes more than ~10 s; multi-step runs, a cancel button, or `partial` status are needed; measured LIEF parse time at the size limit approaches the timeout; or before the API container holds secrets worth protecting or is reachable beyond localhost.
- **Pass gate I1** (blueprint §5.4.3) plus an independent security review before accepting any input that is not self-authored. A worker alone is **not** enough if it both parses and holds database credentials.

---

## 3. Alternatives considered

| Question | Alternative | Why it was not chosen |
|---|---|---|
| Backend | **Django + DRF** | Heavier. Its admin and auth add little to a single-user, API-first app. |
| Backend | **Spring Boot** or **Rails** (both already known to the author) | The analysis libraries are Python, so either would need a Python sidecar and a second backend language. |
| Execution | **Option B: minimal background worker in v0.1** | Adds a second process, a job-claiming loop, status polling, and new failure modes (stuck runs, worker down) for one fast step. It does not improve the slice. Kept for v0.2. |
| Execution | **Parse inside the API process** | Rejected outright: a parser crash or hang would take down the API. |
| Input scope | **Add an isolated analysis container to v0.1 and accept third-party binaries** | Large effort (extra containers, spool protocol, boundary tests, review) before the product exists, and a high risk of quietly broadening v0.1. Its design is kept as gate I1. |
| Input scope | **Strictly fixtures-only for all of v0.1** | Not chosen. `self_built` is kept, but only as a local opt-in after M1, so the adapter and entropy measurement are proven on known bytes first. |

---

## 4. Trade-offs

- **One language (Python) for API and analysis:** less glue code, at the cost of not reusing the author's Java or Ruby experience.
- **Waiting for the parse (no queue):** fewer moving parts and an immediate "imported" or "rejected" answer. The cost is that one slow upload blocks other imports, and the parser shares the API's container. That is acceptable only for one local user with self-authored inputs.
- **Subprocess per parse:** a little extra latency, in exchange for crash containment, uniform timeouts, and a runner that v0.2 can reuse unchanged.
- **Narrow input policy:** v0.1 is less useful (fixtures and the author's own programs only), but its safety claims can be stated honestly.
- **Provisional limits:** values may change after M1. Choosing them now lets M2/M3 build and test the limit-handling code.

---

## 5. Security implications

- **The input policy is the main v0.1 security control.** Safety comes from *what Bytasm agrees to parse*, not from containment.
- **What v0.1 protects against:** parser crashes, hangs, and memory/CPU/output exhaustion caused by bugs; oversized uploads; unknown files reaching the parser in the default mode; remote changes to the input policy.
- **What v0.1 does not protect against:** a crafted file that exploits LIEF. Such code could read what the API can read, reach PostgreSQL, tamper with stored files, and make outbound network connections. This is why third-party files are refused.
- **Resource limits are not containment.** They bound exhaustion. They say nothing about file, secret, or network access. They are expected to hold only in the Linux container. Running the API natively on macOS is for development with fixtures only.
- **No execution.** Bytasm never runs the programs it imports.
- **Self-attestation is not authorisation.** The authorisation statement is a record, not proof of permission and not a legal determination.
- **Gate I1 is not enough for potentially malicious files** (tier T2). Those would also need a dedicated, disposable environment and their own threat model and specialist review. ⚠ Needs specialist security review.

---

## 6. Consequences

- M0 can start: repository bootstrap, an empty `bytasm` Python package managed with `uv`, CI lint, and the M0 Compose setup.
- The README and import UI must say plainly: self-authored inputs only, no execution, limits are not a sandbox, self-attestation is not authorisation.
- The fixture manifest (`MANIFEST.sha256`) is both a test asset and the enforcement mechanism of the default policy.
- The implementation questions Q1–Q8 in blueprint §5.4.1 (upload disconnects, handler cancellation, process-group cleanup, rlimit enforcement, `/proc/<pid>/environ`, form buffering, CORS) must be answered by tests in M2/M3, or recorded as known limitations before v0.1 ships. Until then they are unknowns, not guarantees.
- After M1, the limits in D4 are reviewed against measurements. Any change is recorded in the blueprint (and in a new ADR if the change is significant).
- Moving to a worker in v0.2 changes *who calls* the subprocess runner, not the runner itself.

---

## 7. Not decided by this ADR

These are recommendations, working assumptions, or explicitly deferred choices in the blueprint. They are **undecided** here and need their own decision:

| Topic | Current status in the blueprint |
|---|---|
| Frontend framework and libraries | **Undecided.** React + TypeScript + Vite, TanStack Query/Table, and React Aria or Radix are a *Recommendation* (§5.2). |
| Styling approach | **Undecided.** Plain CSS with design tokens or Tailwind (§5.2). |
| Database | **Undecided as a formal decision.** PostgreSQL is the planned database (§5.4) and the M0 milestone includes "Compose with PostgreSQL", but it is not marked as an accepted decision. |
| Local orchestration and container hardening | **Undecided as a formal decision.** Docker Compose on localhost and the container settings are *Recommendations* (§5.7, §8.2). |
| Blob storage layout | **Undecided.** Local content-addressed directory is a *Recommendation* (§5.5). |
| Background worker library (v0.2) | **Deferred to v0.2:** Procrastinate or a hand-rolled PostgreSQL claim loop (§5.4.2). |
| Gate I1 design | **Not prototyped.** A *Recommendation* to re-verify when built, with an independent reviewer (§5.4.3). |
| Licence | **Undecided.** Apache-2.0 is a *Recommendation* (§13.2). |
| Final values of the D4 limits | **Open until measured after M1.** |
