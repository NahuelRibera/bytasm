# Bytasm — Project Blueprint

> Status: planning document, version 0.3 (2026-10-26). No application code exists yet.
> Audience: the author (a developer new to reverse engineering), future contributors, and reviewers of the portfolio.
>
> **Revision 0.2** applied the accepted scope decisions recorded in [`MVP_SCOPE_REVIEW.md`](MVP_SCOPE_REVIEW.md):
> - **v0.1** is a thin vertical slice: import → validate → SHA-256 → LIEF metadata → UI → JSON report.
> - Capabilities then arrive in releases v0.2–v0.4 (see [§3](#3-release-scope)).
> - The stack is FastAPI.
> - In v0.1 the API waits for LIEF, but LIEF always runs in a separate, resource-limited subprocess ([§5.4.1](#541-v01-execution-model-option-a)).
>
> **Revision 0.3** closes a security gap in that design ([`MVP_SCOPE_REVIEW.md` §11](MVP_SCOPE_REVIEW.md)):
> - **v0.1 is a self-authored-input prototype for local learning and demos.** It accepts only Bytasm's own committed fixtures, checked by hash **before** any parsing. This fixtures-only mode is the only mode during initial development and M0–M1.
> - An optional, local-only `self_built` mode for binaries the author compiled from source they wrote may be enabled **after the M1 acceptance tests pass**. It is off by default and can be enabled only through explicit server configuration ([§3.4](#34-input-policy-and-trust-tiers)).
> - **v0.1 is not safe for arbitrary, third-party, or potentially malicious binaries, and must not be used with them.**
> - The parser subprocess and its resource limits reduce the impact of parser *bugs*. They are **not a security sandbox**.
> - Accepting any other binary requires the **isolated analysis boundary (gate I1, [§5.4.3](#543-isolated-analysis-boundary-gate-i1))** plus a review.
> - Bytasm never executes the programs it imports, in any planned release before the dynamic-analysis research track.
>
> "MVP" in older wording means the v0.1–v0.4 sequence as a whole.

## How to read this document

Each statement in this blueprint falls into one of three categories, and the text labels the ones that matter:

- **Verified**: checked against a primary source during research on 2026-10-26. The source is listed in [§14](#14-research-sources-and-verification-status).
- **Recommendation**: an engineering judgement made for this project. It can be revisited and is recorded so it can be challenged.
- **Assumption**: a belief that still needs evidence, such as who the users are or what they need.

Where specialist review is needed (legal, licensing, security), the text says **⚠ Needs specialist review**.

### Glossary (terms used throughout)

| Term | Meaning |
|---|---|
| **Binary** | A compiled executable or library. For example, a Windows `.exe`/`.dll` or a Linux executable/`.so`. |
| **PE** (Portable Executable) | The file format Windows uses for executables and DLLs. |
| **ELF** (Executable and Linkable Format) | The file format Linux and most Unix-like systems use for executables, shared libraries, and object files. |
| **Architecture** | The CPU instruction set the code targets, such as x86-64 or AArch64 (ARM 64-bit). |
| **Section** | A named region inside a binary, such as `.text` (code) or `.data` (initialised data). |
| **Import / export** | Functions a binary uses from other libraries (imports) or offers to others (exports). |
| **Static analysis** | Examining a file without running it. This is the only kind Bytasm's MVP performs. |
| **Dynamic analysis** | Running a program, usually in an isolated environment, and observing what it does. Deferred. |
| **Disassembly** | Translating machine code back into human-readable assembly instructions. |
| **Decompilation** | Producing C-like pseudo-code from machine code. The result is an approximation, **not** the original source code. Names, comments, and structure are usually lost or guessed. |
| **Hash (SHA-256)** | A fixed-length fingerprint of a file's bytes. Identical bytes give identical hashes, and any change gives a different hash. |
| **Entropy** | A 0–8 bits-per-byte measure of how random data looks. High entropy *can* suggest compression or encryption, but it proves nothing by itself. |
| **Packing** | Compressing or encrypting a binary so its real code is only revealed when it runs. Packing hampers static analysis. |
| **Rule (YARA / capa)** | A human-written pattern describing bytes, strings, or code features. A "match" means the pattern was found, not that a conclusion is proven. |
| **Finding** | In Bytasm, one machine-generated observation from one tool invocation, linked to evidence. |
| **Evidence** | The concrete data that supports a finding: a byte range, an address, a section, an import, or a pointer into raw tool output. |
| **Annotation** | A human-written note, interpretation, or conclusion. Always stored and shown separately from findings. |
| **Provenance** | The record of where a result came from: which file, which tool and version, which run, and which inputs. |
| **Self-authored input** | A binary compiled from source written by the Bytasm user or for Bytasm (the committed fixtures). The only kind of input v0.1 supports (§3.4). |
| **Untrusted input** | Any binary not self-authored: downloaded, received, third-party, or of unknown origin, whatever the authorisation. It may have been crafted to exploit a parser. |
| **Sandbox / isolation boundary** | A mechanism designed to stop compromised code from reaching resources outside it (files, credentials, network, other processes). A subprocess with resource limits is **not** one. |

---

## 1. Product definition

### 1.1 One-paragraph description

Bytasm is a local-first workbench for documenting static binary analysis. You import a compiled program you own or are authorised to analyse. Bytasm stores it with basic file-handling safeguards, fingerprints it, and runs a small set of established open-source analysis tools against it, without ever executing it. It keeps every tool's raw output, turns that output into findings linked to concrete evidence, and lets you add your own interpretations alongside them, clearly labelled as yours. It can compare two versions of the same program and export a report another person can inspect and reproduce.

This paragraph describes the product after v0.4 **and** after the isolation gate I1 (§5.4.3). **v0.1** delivers the foundation for **self-authored binaries only**: guarded import, identification, SHA-256, LIEF metadata (including per-section entropy as a measurement), a sample overview, and a reproducible JSON report.

### 1.2 The problem

**Assumption (needs validation):** analysts who use tools like Ghidra often end up with results scattered across tool databases, terminal output, screenshots, and personal notes. Several things are then hard to answer later:

- Which exact file (by hash) was examined?
- Which tool *and version* produced this observation, with which rules?
- Was this statement observed by a tool, or inferred by a person?
- What changed between version 1.2 and 1.3 of this binary?
- Could a colleague re-run the same analysis and get the same result?

The underlying tools are excellent at *analysis*. Bytasm's hypothesis is that the *record-keeping, provenance, and reporting around analysis* is under-served for learners and small teams.

### 1.3 Potential users (hypotheses, not established facts)

| Persona | Likely workflow | What they might want from Bytasm |
|---|---|---|
| **Security learner** | Compiles small programs, studies how they look in Ghidra, writes notes. | A structured notebook that ties notes to evidence, plus diffing to see the effect of code changes. |
| **Engineer investigating software they own** | Checks a build artefact or a third-party library their company licenses. For example: "which libraries does this binary import? Did the new build add network calls?" | Quick metadata, imports, a diff against the previous build, and a shareable report. |
| **Incident-response analyst** | Triages a suspicious file under authorisation and needs a defensible record. | A reviewable record of who looked at what, with which tools, and what was concluded. |
| **Reviewer / auditor** | Receives an analysis and must judge it. | A report that separates evidence from opinion and lists tool versions. |

**There is no market-demand data behind these personas.** §1.6 lists how to test them.

### 1.4 What Bytasm will and will not do

| Will (release in brackets) | Will not (any early release, and possibly ever) |
|---|---|
| Store binaries with basic file-handling safeguards, identified by SHA-256 (v0.1) | Execute uploaded binaries |
| Accept only self-authored binaries (v0.1). Accept authorised third-party binaries only after the isolation gate I1 and its review. | Treat a subprocess, resource limits, or a container as making untrusted parsing safe |
| Identify format, architecture, and metadata for PE and ELF (v0.1) | Decompile or disassemble better than Ghidra. It does not try. |
| Run a small, pinned set of static tools: LIEF (v0.1), strings + YARA-X (v0.2), capa (v0.4) | Upload samples or hashes to third-party services by default |
| Keep raw tool output (v0.1) and link findings to evidence (v0.2) | Declare a file "malicious" or "safe" |
| Separate tool findings from human annotations (v0.3) | Recover original source code |
| Compare two versions at the metadata, import, string, and finding level (v0.3) | Help remove licence checks, bypass DRM, or redistribute software |
| Export JSON reports (v0.1) and static HTML reports (v0.4) | Serve as a multi-tenant cloud service |

### 1.5 Relationship to Ghidra and similar tools

Ghidra (NSA, Apache-2.0, **verified**), Binary Ninja, IDA, Cutter/Rizin, and radare2 are *analysis engines and interactive environments*. They do disassembly, decompilation, cross-references, type recovery, and scripting, and they do it far better than a solo project could.

Bytasm sits *around* such tools:

```
            ┌───────────────────────── Bytasm ─────────────────────────┐
 binary ──► │ checked intake → hash → identify → run pinned tools → store │ ──► report
            │      ▲                       │                           │
            │      │              raw outputs + findings + evidence    │
            │  analyst annotations ◄───────┘                           │
            └─────────────────────────┬────────────────────────────────┘
                                      │ (later) headless Ghidra / capa / diffing
                                      ▼
                        Ghidra GUI for deep manual work
```

**Plain-language version:** Ghidra is the microscope. Bytasm is the lab notebook, the sample register, and the report template. You still use the microscope for the hard looking. Bytasm makes sure you can later show *which slide* you looked at, *with which lens*, and *what you wrote down*. You might use it alongside Ghidra because Ghidra projects are excellent working state but are not designed as a concise, reviewable, tool-agnostic record of an investigation across multiple tools and file versions.

### 1.6 Assumptions that still need validation

| # | Assumption | Cheap way to test |
|---|---|---|
| A1 | People who analyse binaries find provenance and reporting painful enough to adopt another tool. | Talk to 5–8 people (CTF players, security students at UOC, IR practitioners). Ask how they document analyses today. |
| A2 | Metadata-, import-, and string-level diffing is useful before function-level diffing exists. | Demo the diff on your own two builds. Ask whether it answers a real question. |
| A3 | A local-first web UI is preferable to a CLI or a Ghidra plugin for this audience. | Show a CLI report and a UI mock side by side and ask. |
| A4 | capa and YARA-X findings are understandable to learners when shown with their evidence. | Usability test with two learners using the findings screen. |
| A5 | The author can deliver the v0.1 slice (M0–M5 in §12) part-time within a few months, before starting v0.2. | Track milestone velocity against §12 and re-plan after M2. |

---

## 2. User journeys and use cases

Each journey states **what the user sees**, **what happens behind the scenes**, and **which release** delivers it (v0.1–v0.4, see §3).

### J1. Create a project

- **User sees:** A "New project" button on the projects dashboard and a short form with a name and an optional description. They land on an empty project page with a single clear call to action: "Import a binary".
- **Behind the scenes:** A `project` row is created.
- **v0.1:** name and description. **v0.2:** an `activity_event` (`project.created`) audit record. **Later:** an "analysis purpose" field, project templates, default analysis profiles, members.

### J2. Import a binary the user owns or is authorised to analyse

- **User sees:**
  - A file picker / drop zone with the size limit stated up front ("Up to 64 MiB. PE and ELF files only").
  - An input-policy disclosure (v0.1): *"This version is for Bytasm's test fixtures and programs you compiled yourself from your own source. Do not import downloaded, received, third-party, or suspicious files. v0.1 has no isolation boundary for them, and a crafted file could exploit a parser bug. Bytasm never runs the files it imports."* In the default `fixtures` mode, the form also states that only files listed in Bytasm's fixture manifest are accepted.
  - A required **authorisation self-attestation**, made of a basis and a free-text statement. In v0.1 the only basis offered is *I built this binary from source I wrote or control* (`owned_or_built`). The other bases appear only after gate I1 (§5.4.3):
    - `written_permission`: explicit written permission from the rights holder, with a reference note. Nothing is uploaded.
    - `public_fixture_terms_permit`: a publicly available file whose licence or terms permit the intended analysis. It requires a **licence/terms reference**.
  - A choice of a new sample name ("my-cli-tool") or an existing sample to add a new *version* to, with an optional version label ("v1.3.0").
- **Behind the scenes:** The upload is streamed to a temporary file outside any served directory, with a hard byte limit enforced *while streaming*. SHA-256 is computed during the stream. See J3 and §5.4.1.
- **v0.1:** single-file upload with the self-attestation. **Later:** batch import, CLI import, and archive import (only after the archive threat model in §8 is implemented).

> The authorisation statement is a **self-attestation** recorded for accountability. Bytasm does not verify it. It is **not proof of permission** and not a legal determination that the analysis is lawful. A publicly downloadable file is **not** automatically authorised for analysis: its licence or EULA may restrict reverse engineering or redistribution. This wording appears on the import form, the sample overview, and in every report. **⚠ Needs specialist review** before Bytasm is offered to anyone besides the author.

### J3. Validate the file and calculate its hash

- **User sees:**
  - A progress indicator during upload and parsing (typically seconds, bounded by the 30 s parser timeout).
  - On success, a validation card: format, architecture, size, and SHA-256 in monospace with a copy button.
  - On failure, a clear rejection, for example: "This file is a ZIP archive. Archives are not supported in this version." or "The file could not be parsed within 30 s. It was not imported."
  - If identical bytes already exist in the sample, they see "This exact file is already in this project as *my-cli-tool v1.2*."
- **Behind the scenes (v0.1, Option A: one synchronous request, all-or-nothing; full lifecycle in §5.4.1):**
  1. The byte limit is enforced while streaming. Oversized or empty uploads are aborted and their temp file deleted.
  2. SHA-256 is computed during the stream.
  3. **Input-policy check, before any parsing (§3.4):**
     - In the default `fixtures` mode, the SHA-256 must appear in the committed fixture manifest. Otherwise the file is rejected and no parser ever sees it.
     - In the opt-in `self_built` mode, the hash check is skipped. The operator's attestation that the file is self-authored is the only control, and it is recorded.
  4. **Content-based identification**:
     - Magic bytes are checked: `MZ` plus a valid `PE\0\0` header offset for PE, `\x7fELF` for ELF. Archive signatures are rejected.
     - The file is then fully parsed by the LIEF metadata adapter in a **separate, resource-limited subprocess** that the API waits for. LIEF never runs inside the API process. The subprocess contains parser crashes, hangs, and memory blow-ups. It is **not** a security sandbox.
     - The filename extension and the browser's `Content-Type` are recorded but **never trusted**, following OWASP (**verified**).
  5. Only if the parser exits cleanly and its output passes size and schema validation: the database rows are written in one transaction (`sample_version`, `authorization_record`, `analysis_run`, `tool_invocation`, sections, symbols), and the file is moved to content-addressed storage (`blobs/sha256/ab/cd/<sha256>`, read-only).
  6. Otherwise nothing is persisted. The temp files are deleted, and the reason is logged (hash, size, reason code) without file content.
- **v0.1:** all of the above. **Later:** Mach-O, .NET-specific metadata, and fuzzy hashes (ssdeep/TLSH) for similarity.

### J4. Identify format, architecture, size, and useful metadata

- **User sees:**
  - The **Sample overview** screen.
  - An identity panel: SHA-256, size, and the declared filename labelled "as uploaded, untrusted".
  - A two-column metadata panel: format, architecture *as declared in the header*, bitness, endianness, entry point, compile timestamp *as declared in the header*, subsystem/ELF type, linked-library count.
  - A sections table: name, file offset, virtual size, raw size, flags, and **entropy**. Entropy is shown as a *measurement* in bits/byte, or "no file data" for sections without bytes in the file.
  - Tabs for Imports and Exports.
- **Behind the scenes:** This metadata comes from the import-time metadata adapter (J3). Header fields are shown **as declared**: a compile timestamp can be forged or zeroed, and the UI says so in a tooltip. Entropy is computed by Bytasm's own adapter, not by a rule engine, and carries no verdict or threshold (§3.2).
- **v0.1:** PE and ELF via LIEF. **v0.2:** Strings tab. **Later:** Rich header details, signatures and certificates, debug-info summaries.

### J5. Run static analysis without executing the file (v0.2+)

> In v0.1, the only analysis step (LIEF metadata) runs during import (J3), so there is no "Run analysis" button or run page. This journey describes v0.2 onwards, when strings and YARA-X add further steps.

- **User sees:** A "Run analysis" button with the profile shown ("Default static profile: metadata, strings, YARA-X (Bytasm rules v0.1), capa"). After clicking, a run page shows each step as a row: *Queued → Running → Succeeded / Failed / Timed out / Skipped*. It shows elapsed time, a plain-language status ("capa is analysing code features. This can take a few minutes for larger files."), and a collapsible "Technical log".
- **Behind the scenes:** An `analysis_run` row is created with a *snapshot* of the profile, tool versions, and rule-set hashes. A job is handed to a background worker (introduced in v0.2, §5.4.2). The worker runs each tool as a **subprocess** with a timeout and resource limits, captures stdout/stderr to files, records a `tool_invocation`, then normalises output into `finding` + `evidence` rows. The run's final status is `succeeded`, `partial` (some steps failed), `failed`, or `cancelled`.
- **v0.2:** sequential steps, per-step timeout, run-level cancel, `partial` status. **v0.4:** capa step. **Later:** parallel steps, custom profiles, Ghidra headless step.

### J6. Review findings and their supporting evidence (v0.2)

- **User sees:** A **Findings** table with filter chips (tool, category, review state) and a search box. Selecting a row opens a right-hand **evidence drawer**. It shows the tool and version, the rule ID and rule text (for YARA-X/capa), the evidence items (for example "bytes 0x1A40–0x1A52 in section `.rdata`" with a hex/ASCII excerpt, or "import `ws2_32.dll!connect`"), and a link to the raw output file.
- **Behind the scenes:** Findings are read-only once the run completes. Each evidence row points to its originating `tool_invocation` and, where possible, a byte offset/length or virtual address plus a JSON pointer into the raw output.
- **v0.2:** table, filters, drawer, raw output download. **Later:** cross-run finding history ("first seen in v1.2"), deep links to open the address in Ghidra.

### J7. Add human annotations and conclusions (v0.3)

- **User sees:** In the evidence drawer and on the sample overview, an "Add note" control with a *kind* selector:
  - **Note**: neutral observation ("This string is the CLI's help text").
  - **Interpretation**: "I think this function implements the update check".
  - **Conclusion**: a reasoned statement that must cite at least one finding or evidence item, with a confidence label (*tentative / likely / well-supported*).

  Annotations render with an author badge and a different visual treatment from tool findings (§7.5).
- **Behind the scenes:** `annotation` rows are linked to a target (sample version, finding, or evidence). Edits create a new revision (append-only), so history is reviewable.
- **v0.3:** the three kinds, linking, revision history, citation requirement. There are no notes before v0.3, to avoid building a throwaway notes model. **Later:** review/approval by a second analyst, threaded discussion.

### J8. Compare two versions of a binary (v0.3)

- **User sees:** A **Compare** screen with two selectors (A and B, defaulting to the two most recent versions). It shows a summary strip ("+3 imports, −1 section, 14 new strings, 2 new findings, 1 finding gone") and tabs for Metadata, Sections, Imports/Exports, Strings, and Findings, each with added/removed/changed rows. Colour is never the only signal: rows also carry `+`, `−`, and `~` markers and text labels.
- **Behind the scenes:** A comparison is computed from the latest *successful or partial* run of each version. It is a set-based diff on normalised keys: section name + flags, import `library!symbol`, string value, and finding `tool + rule_id`. It warns if the two runs used different tool or rule versions, because then differences may come from the tooling rather than the binary.
- **v0.3:** structural diff as described. **Later:** function-level diffing via Ghidra-based tools (ghidriff, BSim), see §4.

### J9. Export a report another person can inspect and reproduce

- **User sees:**
  - **v0.1:** an "Export JSON report" button on the sample overview, which downloads one sample version's report as an attachment.
  - **v0.4:** a **Report preview** that renders exactly what will be exported, a choice of scope (one version, or a comparison), and JSON or HTML output.
- **Behind the scenes:** The report generator builds a canonical JSON document, validated against a published JSON Schema in the repo (`schemas/report.schema.json`).
  - **v0.1 contents:**
    - `schema_version`, `generated_at`, and the generator (Bytasm version, git commit, image ID)
    - Sample identity: SHA-256, size, and the declared filename marked untrusted
    - An `authorization` block with `"type": "self_attestation"`, its notice text, basis, statement, and `terms_reference`
    - The run and its tool invocation: adapter and LIEF versions, status, duration, result hash
    - Metadata, with per-section entropy objects (`value`, `unit`, `method`, `computed_by`)
    - A `limitations` list: static only, not executed; header values as declared; entropy is a descriptive measurement
  - **Later releases** add findings with evidence (v0.2), annotations and comparisons (v0.3), and an HTML version rendered **from that JSON** with an auto-escaping template and no JavaScript (v0.4, §8).
  - Output is deterministic: stable ordering, and only `generated_at` varies between two exports of the same data.
- **v0.1:** JSON. **v0.4:** HTML + preview. **Later:** SARIF export for tool findings (§4, §14), PDF, signed reports.

---

## 3. Release scope

**Design rule:** ship one thin, complete vertical slice first (**v0.1**), with safe defaults. Then add capability in small releases, each usable on its own. Every feature either serves the core loop (import → analyse → review → annotate → compare → report) or makes it trustworthy (tests, safety, docs). The decision record for this ordering is [`MVP_SCOPE_REVIEW.md`](MVP_SCOPE_REVIEW.md).

| Release | Theme | Contents | Usable on its own because… |
|---|---|---|---|
| **v0.1 Vertical slice** (self-authored inputs only) | Know what you imported | Input policy (`fixtures` by default, `self_built` opt-in), projects, samples/versions, authorisation self-attestation, validated streaming upload, SHA-256, duplicate detection, LIEF metadata (headers, sections + entropy measurement, imports, exports), sample overview, JSON report | You can catalogue Bytasm's fixtures and your own compiled programs, and hand someone a reproducible, hash-anchored metadata report |
| **v0.2 Pattern matching** | First findings with evidence | Built-in strings extractor, YARA-X with a small self-written rule set, `finding` + `evidence`, findings table + evidence drawer, background worker with multi-step runs, `partial` status, cancel | Rule matches point to exact bytes |
| **v0.3 Compare & annotate** | What changed, and what do I think | Structural comparison of two versions. Annotations: note / interpretation / conclusion, revisions, citation requirement. | Supports the build-to-build investigation workflow |
| **v0.4 Deeper analysis & sharing** | Capabilities and readable reports | capa adapter with limitations surfaced, HTML report (auto-escaped, no JS, CSP), report preview | Reports suitable for a non-technical reviewer |
| **Gate I1 Isolated analysis boundary** | Accept authorised third-party binaries | Separate analysis container with no network, no secrets, and read-only inputs, plus boundary tests and an independent review (§5.4.3) | The prerequisite for importing anything that is not self-authored. Not tied to a version number; it builds on the v0.2 worker. |
| v0.5+ | Long-term roadmap | See §4 | — |

Until gate I1 passes, v0.2–v0.4 also accept only self-authored inputs.

### 3.1 Feature table

| Feature | What it does | Why it matters | Release | Demo moment |
|---|---|---|---|---|
| Local run with Docker Compose | One command starts DB, API, and UI on `localhost` (worker from v0.2) | Reviewers can run it. Shows DevEx discipline. | **v0.1** | "`docker compose up`, open localhost" |
| Projects | Group samples | Basic organisation | **v0.1** | Create "Demo: my CLI tool" |
| Samples & versions | A logical program with multiple file versions | Avoids a migration when comparison arrives | **v0.1** | Upload v1 |
| Input policy | `fixtures` mode (default): only hashes in the committed fixture manifest are accepted, checked before parsing. `self_built` mode (explicit opt-in): programs the user compiled from their own source, on the operator's attestation. | Keeps untrusted bytes away from a parser that has no isolation boundary | **v0.1** | Import a fixture, then show that a non-fixture file is refused before parsing |
| Authorisation self-attestation | Required basis + statement per import. Only `owned_or_built` in v0.1; the other bases come after gate I1. | Responsible-use posture, visible in reports | **v0.1** | Show the required statement and its "not proof of permission" notice |
| Upload validation & storage safeguards | Streaming size limit, content identification, archive rejection, content-addressed read-only storage | Basic file-handling hygiene (not an isolation boundary) | **v0.1** | Upload a renamed `.zip` and see it rejected with a clear reason |
| SHA-256 & duplicate detection | Fingerprint and detect duplicates | Identity and provenance | **v0.1** | Re-upload the same file and see "already exists" |
| Metadata adapter (LIEF) | Format, arch, headers, sections (+ per-section entropy measurement), imports, exports | The first useful view of any binary | **v0.1** | Sample overview |
| JSON report | Reproducible, schema-validated export | The canonical artefact another person can inspect | **v0.1** | Download and show tool versions + self-attestation block |
| Strings extractor (built-in) | ASCII and UTF-16LE strings with offsets, min length 6 | Cheap, evidence-friendly, teaches basics | v0.2 | Search strings for a URL in the fixture |
| YARA-X + Bytasm rule set | Self-written descriptive rules on byte/string patterns and documented module fields: "references a URL", "PE section named `UPX0`/`UPX1`" (labelled "UPX-style section name", not "packed") | Rule-based matching with precise byte offsets (**verified**: YARA-X exposes offset/length per match) | v0.2 | Click a match and see the highlighted bytes |
| Background worker, multi-step runs, cancel | Status, logs, per-step timeout, cancel, failure capture | Async orchestration, a data-engineering skill | v0.2 | Watch steps progress, then cancel a run |
| Findings + evidence | Normalised findings linked to invocation and evidence | Core product principle | v0.2 | Evidence drawer |
| Annotations | Notes, interpretations, conclusions with revisions and citations | Separates human from machine | v0.3 | Add a conclusion citing two findings |
| Version comparison | Structural diff of two versions | Strong, visual demo value | v0.3 | v1 vs v2: "+ `getenv` import, + new string" |
| capa | Capability detection mapped to ATT&CK/MBC (**verified**) | Integration with a mature external tool, JSON output (`-j`, **verified**) | v0.4 | "capa reports this can create a TCP socket. Here's the evidence address." |
| HTML report + preview | Rendering of the JSON report | Readable deliverable | v0.4 | Open the HTML report offline |
| Tool availability screen, activity log UI | Installed versions, rule-set hashes, audit events | Transparency | v0.3+ | — |
| Tests, CI, fixtures, docs, security policy | See §9 and §13 | Credibility | **v0.1** onwards | Show the green CI badge and the fixture build script |

### 3.2 Entropy is a measurement, not a rule result

- **v0.1 design (Recommendation):**
  - Bytasm's metadata adapter computes Shannon entropy (bits/byte, 0–8) over each section's **in-file bytes**. It stores the value with its method and adapter version.
  - Sections without file bytes (ELF `SHT_NOBITS` such as `.bss`, or PE sections with raw size 0) get `NULL` ("no file data"). Sections whose declared range runs past the end of the file get `NULL` plus a warning.
  - v0.1 creates **no finding** from entropy and applies **no threshold**.
- **What YARA-X documents (verified, 2026-10-26):**
  - The `math` module provides `entropy(offset, size)`, returning 0.0–8.0 for `size` bytes from a file `offset`.
  - The `pe` module's sections expose `name`, `raw_data_offset`, and `raw_data_size`. The `elf` module's sections expose `name`, `offset`, and `size`.
  - Neither module has a per-section entropy field.
  - Behaviour for ranges beyond the end of the data is not documented.
- **Technically possible, but not used:** inferred from the documented features (not tested, and not shown as a combined example in the docs), a rule could pass a section's offset and size to `math.entropy`. Bytasm deliberately does not do this. One source of truth (the adapter) avoids turning a measurement into a "match".
- **Limitation:** any entropy threshold is only a heuristic. High values are common in compressed or encrypted data and also occur in legitimate resources. A value alone does not prove packing, encryption, or malicious intent. If a threshold is ever displayed, it is labelled as a heuristic with its value visible.

### 3.3 Explicitly deferred (and why)

| Deferred feature | Reason |
|---|---|
| **Dynamic execution** | Needs strong isolation (VMs, not just containers), network containment, and a threat model of its own. See §4 and §8.3. |
| **Multi-tenant SaaS / hosted public instance** | Raises authentication, data protection, abuse handling, legal exposure, and storage costs. |
| **Team collaboration** (multi-user, roles, review) | Adds auth complexity before the single-user value is proven. |
| **Arbitrary third-party plugins** | Executing untrusted plugin code is a security problem of its own. Use a fixed set of adapters instead. |
| **AI-generated conclusions** | Risk of confident-sounding guesses. If ever added, it must be evidence-cited and clearly labelled (§4). |
| **Many formats/architectures** | v0.1 *parses* PE and ELF files of any architecture LIEF supports, but is *tested* only on the committed fixtures: x86-64 PE and ELF, plus AArch64 ELF if it can be built within half a day (§9.2). The binary's target architecture is independent of the host/container architecture Bytasm runs on. LIEF *can* parse Mach-O (**verified**), but supporting it means fixtures, tests, and UI work. |
| **Cloud analysis / automatic sample or hash submission** | Breaks the privacy principle. Even a hash-only lookup reveals interest in a file. |
| **Headless Ghidra** | It requires JDK 25 (**verified** for Ghidra 12.x), a large install, and long analysis times. It is the first integration after v0.4 (v0.5). |
| **Function-level diffing** | Depends on Ghidra integration. ghidriff is GPL-3.0 (**verified**), so licensing needs review. |
| **Archive import** | Archive bombs and path traversal. Archives are rejected. |
| **Third-party or unknown binaries** (even when authorised) | v0.1–v0.4 have no isolation boundary for parsing untrusted input. Accepted only after gate I1 (§5.4.3) and its review. |
| **Potentially malicious binaries** | Not planned. Beyond gate I1, this requires a separate design: a dedicated disposable environment and specialist security review (§3.4, §8.3). |

### 3.4 Input policy and trust tiers

Bytasm's protection in v0.1 comes mainly from **what it agrees to parse**, not from containment. The subprocess and container settings in §5.4.1 and §8.2 limit the damage from parser *bugs* on well-formed or test-generated input. They are not designed to contain a parser *exploit*, because the parser runs as the API's user, in the API's container, with the API's filesystem and network access.

| Tier | Inputs | Allowed from | Primary control | Status |
|---|---|---|---|---|
| **T0: self-authored** | Bytasm's committed fixtures (`fixtures` mode). Programs the author compiled from source they wrote (`self_built`, local-config opt-in after M1 acceptance tests). | v0.1 | Hash allowlist (`fixtures`). Operator attestation (`self_built`). Bytasm cannot verify the latter. | Committed (v0.1) |
| **T1: authorised third-party** | Binaries the user is authorised to analyse but did not write, and has no reason to suspect | After gate I1 + review | Isolated analysis container (§5.4.3), plus everything in T0 that still applies | Planned gate, not scheduled |
| **T2: potentially malicious** | Suspected malware, incident samples, files from unknown sources | Not planned | Gate I1, **plus** a dedicated, disposable analysis environment with no sensitive data, plus a separate threat model and specialist review | Not committed. ⚠ **Needs specialist security review.** |

**Final v0.1 input policy (decision of 2026-10-26, recorded in [`MVP_SCOPE_REVIEW.md` §12](MVP_SCOPE_REVIEW.md)):**

| Phase | Allowed inputs | How enabled |
|---|---|---|
| Initial development, **M0–M1** | **Fixtures only.** The SHA-256 must be in the committed `MANIFEST.sha256`. | Default and only mode |
| After the **M1 acceptance tests pass** (and through v0.1–v0.4, until gate I1) | Fixtures, plus optionally `self_built`: binaries the author compiled from source code they authored | `self_built` is **disabled by default**. It is enabled **only** through explicit server configuration on the local machine (an environment variable or config file read at start-up). |
| Before **gate I1** and its independent security review pass | **Never:** third-party, downloaded, received, or suspicious binaries, whatever the authorisation basis | — |

Constraints on `self_built`:

- **Local control only.** There is no API endpoint, UI toggle, request header, or other remote or user-facing control that can enable it or bypass the fixture check.
- **Loopback only.** The server refuses to start with `self_built` enabled unless it is bound to loopback.
- **Visible and recorded.** While enabled, the UI shows a persistent banner. Each sample version records `admitted_under = self_built_optin`, and reports include it.
- **What it is:** a **provenance restriction based on operator self-attestation**. Bytasm cannot verify that a file is self-authored.
- **What it is not:** a security sandbox, or proof that a file is safe. It does not change the parser's lack of isolation (§5.4.1).
- **Not a path to third-party files.** Accepting third-party, downloaded, received, or suspicious binaries requires gate I1 (§5.4.3) **and** its independent security review. It is never done by enabling `self_built`.

Rules that hold in every tier:

- **No execution.** Bytasm never executes imported programs (static analysis only).
- **Attestation is not authorisation.** The authorisation statement is a self-attestation for record-keeping. It is not proof of permission and not a legal determination.
- **Limits are not containment.** Subprocess and container resource limits reduce some risks: hangs, memory or CPU exhaustion, crash propagation. They **do not make parsing untrusted files safe.**
- **Wider inputs need a separate design.** Accepting unknown or potentially malicious files requires a separate isolation design and review, not a configuration change.
- **Provenance records the policy.** Each sample version records which policy admitted it (`admitted_under`: `fixture_manifest` or `self_built_optin`), and reports include it.

---

## 4. Roadmap toward a mature version

These phases are **possible directions, not commitments**. Each has a gate: the evidence that would justify building it.

| Phase | User value | Skills / infrastructure | New risks | Evidence that justifies it |
|---|---|---|---|---|
| **v0.1 Vertical slice** | Guarded import, identification, metadata, JSON report on **self-authored** PE/ELF | §5 stack, input policy (§3.4), subprocess runner (§5.4.1) | Parser bugs. Misuse with untrusted files despite the policy. | — (committed) |
| **v0.2 Pattern matching** | Strings, YARA-X findings with byte-level evidence | Background worker (§5.4.2), finding/evidence model | Rule false positives misread as verdicts | v0.1 released and its gate passed |
| **v0.3 Compare & annotate** | Version diff, annotations with revisions and citations | Stable fingerprints, append-only modelling | Diffs caused by tool-version drift | v0.2 in use on at least two builds of the same program |
| **v0.4 Deeper analysis & sharing** | capa capabilities, HTML reports | capa CLI integration, auto-escaping templates, CSP | capa limitations misunderstood, report XSS | Findings model stable. Someone wants to read reports without running Bytasm. |
| **Gate I1 Isolated analysis boundary** | Import authorised third-party binaries (tier T1) | Separate network-less, secret-less analysis container. File-spool hand-off without a Docker socket. Boundary tests. Written threat model. Independent review. (§5.4.3) | A false sense of safety if the boundary is weaker than claimed. Container escapes through kernel bugs are not prevented by containers alone. | A real need to analyse third-party binaries. The v0.2 worker exists. Someone qualified is available to review the design. |
| **v0.5 Ghidra headless step** | Function inventory, symbol names, call counts, and decompiler excerpts as *evidence*. "Open in Ghidra" hand-off. | PyGhidra 3.x (**verified**: `pyghidra.start()`, `open_project`, `analyze` with a timeout, requires Ghidra ≥ 12.0), JDK 25, large container image, per-file analysis timeouts (`-analysisTimeoutPerFile`, **verified**) | Memory and CPU exhaustion, very long runs, image size | MVP users ask "which function is this in?" A4 validated. |
| **v0.6 Profiles & repeatable pipelines** | Saved profiles ("quick triage", "deep"), re-run a profile on a new version, rule-set versioning UI | Schema evolution, profile snapshots | Profile drift makes runs incomparable. Mitigation: snapshots plus diff warnings. | Users re-run the same steps repeatedly. |
| **v0.6 Corpus search** | Search across *your own* samples: "which of my binaries import X / contain string Y / matched rule Z?" | PostgreSQL full-text or trigram indexes, maybe DuckDB for analytics | Performance with large string tables | ≥ 20 samples in real use |
| **v0.7 Function-level diffing** | "Which functions changed between builds?" | Ghidra Version Tracking via ghidriff (GPL-3.0) or BSim | GPL obligations if bundled (**⚠ licensing review**), long runtimes | A2 shows structural diff is insufficient. |
| **v0.7 Standards-based export** | SARIF 2.1.0 export of tool findings for interoperability | Mapping findings to `result`, evidence to `physicalLocation.region.byteOffset/byteLength` or `address` (**verified**: SARIF supports binary regions and addresses) | Lossy mapping of annotations | A consumer exists, such as GitHub code scanning or a SARIF viewer. |
| **v0.8 Team workspaces & review** | Multiple analysts, roles, "request review" of a conclusion, sign-off | Auth (OIDC or local accounts), RBAC, audit hardening | Authorisation bugs, data leakage across projects | Someone actually wants to share a workspace. |
| **v0.9 Evidence-grounded AI assistance (optional)** | Draft summaries that cite finding/evidence IDs and are labelled "machine-generated draft, unverified" | Retrieval over a project's own findings, eval harness, local model option | Hallucination, prompt injection *from binary strings*, data leaving the machine | A measurable eval shows citations are correct and useful, *and* users want it. |
| **v1.x Dynamic analysis (research track)** | Observe runtime behaviour | Disposable VMs (for example Firecracker microVMs on a Linux KVM host, **verified** Linux/KVM-only), or integrating an established sandbox such as CAPE and *ingesting its reports* (capa can read CAPE reports, **verified**) | Escape, network abuse, legal exposure, operational cost | Strong isolation design reviewed by a specialist. **⚠ Needs specialist security review.** |
| **Hosted deployment** | Access from anywhere | TLS, auth, backups, encryption at rest, abuse handling, privacy policy | Hosting other people's possibly malicious or confidential files | Clear demand, plus legal and privacy review. **⚠ Needs specialist review.** |

---

## 5. Architecture options and recommendation

### 5.1 Logical components

**v0.1 (Option A, §5.4.1):** there is no worker. The API streams the upload and applies the input policy (§3.4). For admitted files only, it spawns and supervises one resource-limited parser subprocess per import, and waits for it. The subprocess is inside the API container's trust boundary: it shares the API's user, filesystem view, and network. That is acceptable only for self-authored inputs.

```
┌──────────┐  HTTP/JSON  ┌────────────────── API container ──────────────────┐   SQL   ┌────────────┐
│ Frontend │ ──────────► │ FastAPI process ──spawn/wait/kill──► LIEF adapter │ ──────► │ PostgreSQL │
│ (SPA)    │             │  (never parses)     JSON result ◄── (subprocess,  │         │   (data)   │
└──────────┘             │                                     rlimits)      │         └────────────┘
                         └──────────────┬────────────────────────────────────┘
                                        │ write after validation
                                        ▼
                                 ┌─────────────┐
                                 │ Blob store  │
                                 └─────────────┘
```

**v0.2+ target** (introduced when a §5.4.1 trigger fires; planned with strings + YARA-X). The diagram below shows the worker. Before untrusted input is accepted, gate I1 (§5.4.3) additionally splits parsing out of the DB-connected worker into a network-less analysis container.

```
┌──────────┐  HTTP/JSON  ┌──────────┐   SQL   ┌────────────┐
│ Frontend │ ──────────► │   API    │ ──────► │ PostgreSQL │◄──┐
│ (SPA)    │             │ (FastAPI)│         │ data + jobs│   │ jobs (LISTEN/NOTIFY + polling)
└──────────┘             └────┬─────┘         └────────────┘   │
                              │ write (intake only)            │
                              ▼                                │
                       ┌─────────────┐   read-only mount  ┌────┴─────┐  subprocess  ┌──────────────┐
                       │ Blob store  │ ─────────────────► │  Worker  │ ───────────► │ Tool adapters│
                       │ (local dir) │                    │          │ ◄─────────── │ LIEF/strings │
                       └─────────────┘                    └──────────┘  JSON stdout │ YARA-X/capa  │
                                                                                    └──────────────┘
```

Boundaries that matter **from day one**:

1. **What gets parsed at all**: the input policy (§3.4) decides which bytes may reach a parser. In v0.1 this is the main security control.
2. **API process ↔ parsing**: the API process never parses in-process. In v0.1 it spawns and supervises a limited subprocess and waits for it. From v0.2 (or earlier if a trigger in §5.4.1 fires), a separate worker process does this. **Neither is an isolation boundary.** Gate I1 introduces the first one (§5.4.3).
3. **Caller ↔ tool**: every tool runs as a **subprocess** with a timeout, resource limits, and a JSON contract, whether the caller is the API (v0.1) or the worker (v0.2+). This holds for the in-house strings extractor too. A crash or hang in a parser (for example a C++ parser fed a malformed file) then kills one step, not the caller. This is a robustness boundary, not a security one.
4. **Untrusted data ↔ rendering**: everything derived from a sample (strings, section names, symbol names, tool messages) is treated as untrusted text everywhere it is displayed.

Boundaries that **can wait**: separate services per tool, object storage (S3/MinIO), a message broker, horizontal scaling.

### 5.2 Frontend

| Option | Pros | Cons |
|---|---|---|
| **React + TypeScript + Vite SPA** (recommended) | Huge ecosystem for data-dense UIs (TanStack Table/Query), accessible headless component libraries (React Aria, Radix), a typed client generated from OpenAPI, familiar from bootcamp-style JS | You assemble pieces yourself |
| Next.js | Conventions, SSR | SSR adds little for a local tool, and its server runtime is another component |
| Rails views + Hotwire | You know Rails, fewer moving parts | Two backend languages (Ruby UI, Python analysis). DataCheck already demonstrates Rails. |
| SvelteKit | Small, pleasant | Smaller ecosystem for complex tables and accessible components |

**Recommendation:** React + TypeScript + Vite, TanStack Query for server state, TanStack Table for findings, strings, and diffs, and React Aria Components (or Radix) for accessible primitives. Use plain CSS with design tokens (CSS custom properties) or Tailwind. Pick one and keep it.

### 5.3 Backend / API

| Option | Pros | Cons |
|---|---|---|
| **Python + FastAPI** (recommended) | The analysis ecosystem is Python (LIEF, pefile, pyelftools, yara-x, capa, PyGhidra all have Python packages, **verified**), Pydantic schemas produce OpenAPI automatically, async file streaming | Less "batteries included" than Django: you choose ORM and migrations |
| Django + DRF | Admin, auth, mature ORM. Procrastinate has a Django integration (**verified**). | Heavier. The API-first SPA pattern needs DRF. |
| Spring Boot | You used it in Repair | Analysis libraries are Python, so you would need a Python sidecar |
| Rails | You used it in DataCheck | Same as above |

**Decision (accepted 2026-10-26, to be recorded as ADR-0001):** Python 3.12+ with **FastAPI**, SQLAlchemy 2.x, and Alembic migrations, with `uv` for dependency locking. A single Python package (`bytasm`) has an `api` entrypoint in v0.1, plus a `worker` entrypoint from v0.2. The API runs as a **single server process** in v0.1: the in-memory parser-slot limit (§5.4.1) only holds within one process. Django was considered and not chosen. Its admin and auth add little to a single-user, API-first SPA.

### 5.4 Database and job queue

**Database:** PostgreSQL (you already know it from Repair and DataCheck). Relational tables cover the entities in §6. Use `JSONB` for tool-specific normalised details. Raw tool outputs live **as files** referenced by hash, not as huge DB values.

#### 5.4.1 v0.1 execution model (Option A)

**Decision (accepted 2026-10-26, scope-limited in revision 0.3):** in v0.1 the import request waits for the LIEF metadata adapter, which **always runs in a separate, resource-limited subprocess**. There is no background worker and **no persistent job queue** in v0.1. Rationale and the rejected alternative are in [`MVP_SCOPE_REVIEW.md` §3.1 and §11](MVP_SCOPE_REVIEW.md).

**Scope condition.** Option A is appropriate **only for self-authored inputs (tier T0, §3.4)**.

- **What it protects against:** parser crashes, hangs, and runaway memory/CPU/output caused by bugs. It also keeps the API process itself from running LIEF.
- **What it does not protect against:** a parser *exploit* by a crafted file. Such an exploit would run with the API container's user, filesystem view, secrets reachable by that user, and network access (see "Known limitations" below).
- **Consequence:** widening the input policy is not a configuration change. It requires gate I1 (§5.4.3).

**Provisional defaults.** These are starting values, to be reviewed after measuring the M1 fixtures and a synthetic file at the size limit:

| Setting | Value | Status |
|---|---|---|
| Upload size limit | 64 MiB | Accepted, provisional |
| Parser wall-clock timeout | 30 s | Accepted, provisional |
| Parser memory limit (`RLIMIT_AS`) | 1 GiB | Accepted, provisional |
| Concurrent parser subprocesses | **1** | Accepted, provisional. Revisit after measuring resource use. |
| Parser CPU limit (`RLIMIT_CPU`) | 25 s | Derived, provisional (below the wall-clock timeout) |
| Parser output file limit (`RLIMIT_FSIZE`) | 32 MiB | Derived, provisional |
| Captured stdout / stderr | 64 KiB each | Derived, provisional |
| Metadata header size (`X-Bytasm-Import`) | 8 KiB | Derived, provisional |
| `SIGTERM` → `SIGKILL` grace | 2 s | Derived, provisional |
| Stale temp / orphan blob age for startup sweep | 1 h | Derived, provisional |

**Documented platform behaviour this design relies on** (verified 2026-10-26 against official docs; §14):

- **Starlette `request.stream()`** yields body chunks "without storing the entire body to memory". After that, `.body()`, `.form()`, or `.json()` raise an error. `request.is_disconnected()` exists.
- **Starlette `request.form()`** spools uploaded files to temporary storage, and they are "not limited by `max_part_size`". For whole-body limits, the docs point to `max_body_size` / `RequestBodyLimitMiddleware`.
- **FastAPI `UploadFile`** is a `SpooledTemporaryFile`. Bodies read directly from `Request` are not validated or documented by FastAPI.
- **ASGI spec:** the server is **not required to cancel** the application when a client disconnects. The app learns of it when `receive` returns `http.disconnect`, or (spec 2.4+, "not guaranteed") when `send` raises an `OSError` subclass.
- **Uvicorn:** pauses reading from the transport when the buffered body reaches a high-water mark, and resumes when the app calls `receive`. After a response is sent, later `receive` calls return `http.disconnect`. The docs do **not** say whether the app task is cancelled on disconnect.
- **asyncio subprocesses:**
  - `communicate()` and `wait()` have no timeout parameter; use `wait_for()`. The docs do **not** say the child is killed when `wait_for` times out, so Bytasm must kill it explicitly.
  - `wait()` "can deadlock" with `PIPE` if output fills the OS buffer.
  - `kill()` sends `SIGKILL` to *the child*.
  - Extra keyword arguments (such as `start_new_session`) are passed through to `subprocess.Popen`.
- **`subprocess`:**
  - `Popen.communicate(timeout=…)` does **not** kill the child on timeout.
  - `run(timeout=…)` kills and waits for *the child*. The docs say nothing about grandchildren, which is why Bytasm kills the whole process group.
  - `env` replaces the inherited environment.

The design depends on several things the docs **do not establish**, so each is a test case (see "Implementation-time questions" below):

- When or whether Starlette raises a disconnect exception while streaming.
- Whether uvicorn cancels handlers.
- Whether killing the process group leaves no survivors.

**Request lifecycle for `POST /api/v1/projects/{id}/imports`** (Recommendation; items marked *to verify* are checked in M2/M3):

1. **Request guards (before reading the body).**
   - Middleware rejects requests whose `Host` is not `localhost`/`127.0.0.1` (with the configured port).
   - It also rejects state-changing requests that lack the required custom header.
   - The import metadata travels in that header: `X-Bytasm-Import`, a base64url-encoded JSON document of at most 8 KiB. It holds the sample name or ID, version label, declared filename, authorisation basis, and statement.
   - Because the header is non-standard, browsers must send a CORS preflight before any cross-origin page could set it, and Bytasm allows no foreign origins. *To verify in M3:* the preflight behaviour against the actual CORS configuration.
   - The metadata is validated **before any file bytes are read**: schema, and basis must be `owned_or_built` in v0.1. Invalid metadata returns 422.
2. **Early size check.** If `Content-Length` is present and exceeds 64 MiB, respond 413 without reading the body.
3. **Parser slot.**
   - The handler tries to acquire the single parser slot **without waiting**. If it is taken, it responds 503 with `Retry-After`, and the body is never read.
   - The slot is held for the rest of the request (upload + parse). A slow upload therefore blocks other imports, which is acceptable for a single local user.
   - The slot is an in-process semaphore, so it is valid only because the API runs as a single server process (§5.3).
4. **Bounded streaming upload.**
   - The file is sent as the **raw request body** (`application/octet-stream`).
   - The handler reads the body chunk by chunk (`request.stream()`) into `data/tmp/<uuid>/upload.bin`. It must consume the ASGI request body **to its completion signal**: the final `http.request` message with `more_body` false (**verified**, ASGI spec), surfaced by Starlette as the end of the stream. Only a stream that ended this way counts as a complete upload. The directory has mode `0700`, sits on the same volume as the blob store, and is never served.
   - It updates SHA-256 and a byte counter on every chunk.
   - Once the counter exceeds 64 MiB, it stops reading and responds 413.
   - The first bytes are checked early, and archive signatures and non-`MZ`/non-`\x7fELF` inputs are rejected with 415.
   - An empty body is rejected with 422.
   - The endpoint deliberately does **not** use FastAPI `UploadFile`/form parsing. Starlette documents that uploaded form files are spooled to temporary storage and are not limited by `max_part_size` (**verified**). Raw-body streaming lets Bytasm hash, count, and stop at the limit itself. *To verify in M3:* whether `form()` consumes the whole body before returning (not stated in the docs), and what Starlette's documented `max_body_size` / `RequestBodyLimitMiddleware` options do, as a possible defence-in-depth layer.
5. **Input-policy check (before any parsing, §3.4).**
   - In `fixtures` mode (default): if the streamed SHA-256 is not in the committed fixture manifest, respond 403 (`input_policy`), delete the temp file, and never spawn the parser.
   - In `self_built` mode (local server configuration only, and only after M1 acceptance tests pass, §3.4): the check is skipped, and the sample version records `admitted_under = self_built_optin`.
   - The policy is read from local server configuration at start-up only. It cannot be changed through the API, the UI, or any request. The server refuses to start in `self_built` mode on a non-loopback binding.
6. **Duplicate check.** If the same SHA-256 already exists for this sample, respond 409 with a link to the existing version, and do not parse. The same bytes in a *different* sample are parsed again: the blob is reused, and the new version gets its own run.
7. **Spawn the adapter.**
   - Command: `[sys.executable, "-m", "bytasm.adapters.metadata_lief", "--input", "upload.bin", "--out", "result.json"]`, as an argv list with no shell. It is started through an asyncio subprocess.
   - Process settings: `cwd` = the request temp directory, `stdin` = `/dev/null`, `start_new_session=True` (own process group), and the default `close_fds=True`.
   - The `env` is explicit and minimal, with no database URL, tokens, or other secrets.
   - `preexec_fn` is **not** used. Python documents it as unsafe with threads (**verified**).
   - The adapter's first action, **before importing LIEF**, is to lower its own limits: `RLIMIT_AS` 1 GiB, `RLIMIT_CPU` 25 s, `RLIMIT_FSIZE` 32 MiB, `RLIMIT_CORE` 0. A process may lower its own limits (**verified**).
8. **Supervise with a timeout.**
   - stdout and stderr are drained concurrently through bounded readers: the first 64 KiB is kept, the rest discarded, and control characters are stripped before logging.
   - The deadline is enforced with `asyncio.wait_for` around draining and waiting. `wait_for` does **not** itself stop the child (the docs don't say it does), so the timeout path always kills explicitly.
   - On the 30 s wall-clock timeout: `SIGTERM` to the process group (`os.killpg`), wait 2 s, then `SIGKILL` to the group, then await the process so no zombie is left. *To verify in M2:* that no process from the group survives, including a fake adapter that forks or calls `setsid()` itself. A process that leaves the group escapes `killpg`; `pids_limit` and `init: true` are the backstop.
   - The user gets a fixed message: "The file could not be parsed within 30 s. It was not imported."
9. **Classify the outcome. Partial output is never used.**
   - **Success** requires all of: exit code 0, `result.json` present and ≤ 32 MiB, valid JSON, and schema validation passed.
   - **Rejected input:** the adapter exits with code 2 and prints one reason code from a fixed list (for example `not_pe_or_elf`, `malformed_headers`). The API maps that code to its own message. It never shows adapter-generated text to the user.
   - **Every other case is a failure, and `result.json` is not read:** any other exit code, death by signal (including `SIGXCPU`/`SIGKILL` from limits), timeout, or a missing, oversized, or invalid result file.
10. **Persist all-or-nothing.**
   1. Re-hash `upload.bin` and compare it with the streaming hash. This catches accidental modification. It is **not** a defence against a compromised parser, which runs as the same user and could alter other files or the database directly (see limitations).
   2. Open one DB transaction and insert `sample` (if new), `sample_version`, `authorization_record`, `analysis_run`, `tool_invocation`, `section`, and `symbol` rows.
   3. Place the blob atomically on the same filesystem: `os.replace` to `blobs/sha256/aa/bb/<hash>` if it doesn't exist, otherwise discard the temp copy, since identical bytes are already stored. Then set mode `0400`.
   4. Commit. If the commit fails and this request created the blob, delete the blob before responding 500.
11. **Cleanup (`finally`, on every path including errors and cancellation).**
    - Kill the process group if it is still alive and reap it, release the parser slot, and delete `data/tmp/<uuid>/`.
    - *To verify in M2:* awaiting the child during task cancellation needs shielding (or a bounded synchronous `waitpid`), so the cleanup itself isn't cancelled.
12. **Respond** 201 with the new sample version and its metadata summary.

**Client disconnects, stated precisely:**

- **During upload:** per the ASGI spec, the app learns of a disconnect when `receive` yields `http.disconnect` (**verified**). Starlette's request documentation does not describe what `request.stream()` does in that case.
  - **Required:** the upload counts as complete **only** if the body was consumed to its ASGI completion signal (`more_body` false).
  - **Required:** disconnect and cancellation must be handled according to the behaviour of the **pinned** Starlette and Uvicorn versions. That behaviour must be confirmed by reading the installed versions' source and by test, not assumed.
  - Any other outcome (disconnect, exception, cancellation, or a stream that ends without the completion signal) means rejection and cleanup, with nothing persisted.
  - **Additional consistency check:** when `Content-Length` was sent, the received byte count must equal it. This catches some truncation, but it is **not** proof that the request completed. The header may be absent, and a matching count does not replace the completion signal.
  - **Status:** unverified until the interrupted-upload test (Q1) exists and passes against the pinned versions. The documents must not describe this behaviour as verified before then.
- **During parsing:** the handler does **not** rely on noticing the disconnect, and the ASGI spec does not require the server to cancel it (**verified**). The parse runs to completion or timeout (≤ 30 s). If it succeeds, the import **is committed even though the browser has gone**. It appears in the project list, and a re-upload is reported as a duplicate. This is a deliberate trade-off, not an error.
- **If the server cancels the handler anyway** (uvicorn's docs don't say whether it does; *to verify in M3*): the `finally` block kills the process group and deletes temp files. The transaction rolls back unless the commit had already completed, in which case the import stands. If cancellation-safe cleanup can't be made reliable in M2, record it as a limitation and rely on the startup sweep and `init: true`.

**Known limitations of Option A in v0.1.** These are accepted risks, not solved problems. They are acceptable **only because v0.1 accepts self-authored inputs only (§3.4)**:

| Limitation | Consequence | Mitigation now | Removed by |
|---|---|---|---|
| Filesystem + DB are not one atomic unit | A crash between step 10.3 and 10.4 can leave an **orphan blob**. A crash mid-request can leave a temp directory. | On startup the API deletes temp directories and unreferenced blobs older than 1 h | — (sweep remains) |
| Parser runs as the **same OS user in the same container** as the API | A parser exploit could read files the API can read, potentially including the API's environment via `/proc/<pid>/environ` (*to verify*). It could also connect to PostgreSQL, and tamper with stored blobs or temp files. | Clean env for the child; non-root container; `cap_drop: [ALL]`; `no-new-privileges`; no Docker socket; no host mounts; re-hash before storage; **blob hash re-verified on download and report export**. *Candidate, to verify in M2:* mark the API process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`) to block same-user `/proc/<pid>/environ` reads. **Primary mitigation: the input policy keeps untrusted bytes out.** | Gate I1: a separate analysis container with no DB credentials, read-only inputs, and no network (§5.4.3). The v0.2 worker alone does **not** remove this if it both parses and holds DB credentials. |
| Parser has the API container's **network access** | A parser exploit could make network connections | Ports bound to `127.0.0.1` limit inbound access only. Outbound access is **not** restricted in v0.1. | Gate I1: analysis container with `network_mode: none` (only loopback, **verified**) |
| Orphaned subprocess if the API process dies abruptly | A child in its own session survives its parent | Run the API as the container's main process with `init: true`, so container exit kills all processes. `RLIMIT_CPU` bounds busy loops. | — |
| Resource limits are expected to hold only on **Linux** | `RLIMIT_AS` enforcement on macOS hosts may be unreliable (*to verify*) | Run v0.1 in its Linux container, where limits are tested. Docker Desktop runs containers inside a Linux VM (**verified**). Running the API natively on macOS is for development with fixtures only. | — |
| Container resource limits are not containment | Docker applies **no** resource constraints by default (**verified**). Memory, CPU, and pid limits bound exhaustion but say nothing about file, secret, or network access, or kernel attack surface. | Set `mem_limit`, `cpus`, `pids_limit` explicitly. Default seccomp profile kept: an allowlist blocking "around 44 system calls out of 300+", described as "moderately protective" (**verified**). | Gate I1 for separation. A stronger runtime or VM is considered at T2 (§3.4). |
| No custom seccomp/Landlock filtering of the parser | Kernel attack surface is the container default | Accepted for self-authored inputs | Reconsidered at gate I1 (§5.4.3) |

**Triggers to move to a background worker (Option B)**, for workflow and reliability reasons. Any one is enough:

1. A step needs a timeout above 30 s or typically takes more than ~10 s on fixtures. capa (v0.4) and Ghidra will.
2. Multi-step runs, a cancel button, or `partial` status are needed (v0.2 strings + YARA-X).
3. Measured LIEF parse time at the size limit approaches the timeout.
4. Before the API container holds secrets worth protecting, or before Bytasm is reachable beyond localhost.

**Gate I1 is required, not just a worker,** before any of the following:

- Accepting any input that is not self-authored, i.e. enabling the `written_permission` or `public_fixture_terms_permit` bases, or any other policy mode.
- Describing Bytasm as suitable for third-party binaries.

A worker that both parses and holds DB credentials does not satisfy this.

**Implementation-time questions** (answer by test in M2/M3. Until then, treat these as unknown, not as guarantees):

| # | Question | How to test | If the answer is bad |
|---|---|---|---|
| Q1 | With the **pinned** Starlette/Uvicorn versions, what does `request.stream()` do when the client aborts mid-upload: raise `ClientDisconnect`, end early, or something else? Does the handler reliably tell "consumed to the completion signal" apart from "interrupted"? | Interrupted-upload integration tests: a client sends part of a body, then closes. Repeat with and without `Content-Length`, and with a body shorter than the declared length. Assert nothing is persisted and no temp file or process remains. | Treat any upload not consumed to its completion signal as failed. The `Content-Length` comparison is only an additional check. Document the observed behaviour per pinned version, and re-run the test whenever the pins change. |
| Q2 | Does uvicorn cancel the handler task on disconnect during parsing? | Test that closes the connection mid-parse and checks for orphans and DB state | Keep the `finally` cleanup, startup sweep, and `init: true`. Document the behaviour. |
| Q3 | Is cleanup itself cancellation-safe? | Inject cancellation during the kill/reap path | Shield the cleanup or use bounded synchronous `waitpid`. Otherwise record as a limitation. |
| Q4 | Does `killpg` (`SIGTERM` → `SIGKILL`) leave no survivors, including children that fork, ignore `SIGTERM`, or call `setsid()`? | Fake adapters that do each of these | `pids_limit` + `init: true` as a backstop. Document that a process escaping the group is not covered. |
| Q5 | Are `RLIMIT_AS`, `RLIMIT_CPU`, and `RLIMIT_FSIZE` enforced in the Linux container (amd64 and arm64)? Unreliable on macOS? | Fake adapters that exceed each limit | Rely on container `mem_limit`/`cpus`. Never use the native macOS run for anything but fixtures. |
| Q6 | Can a same-user child read the API's `/proc/<pid>/environ`, and does `PR_SET_DUMPABLE=0` prevent it? | Test inside the container | Keep secrets out of the API environment where possible (e.g. a local-only DB password with low value). Record as a limitation. |
| Q7 | Does `form()` consume the whole body before returning, and what does `RequestBodyLimitMiddleware`/`max_body_size` do? | Read the installed Starlette source and test | Keep the raw-body design (no change). |
| Q8 | Does the CORS configuration really block a cross-origin request carrying the custom header? | Browser-level Playwright test from a second origin | Fix the CORS configuration before v0.1. |

#### 5.4.2 Background worker and job queue (v0.2+)

| Option | Broker | Fit |
|---|---|---|
| Procrastinate | PostgreSQL only (**verified**: PG 13+, Python 3.10+, MIT). Retries, cancellation, locks, and async are all **verified**. | One fewer service. Jobs are transactional with your data. Ideal for low volume. |
| Hand-rolled claim loop on `analysis_run` (`SELECT … FOR UPDATE SKIP LOCKED`) | PostgreSQL | Small and educational. Retries and cancellation must be written by hand. |
| Celery | Redis/RabbitMQ | Powerful but heavyweight. Many concepts for a beginner. |
| RQ / Dramatiq / arq | Redis | Simpler than Celery, but adds Redis |

**Decision deferred to v0.2:** Procrastinate or a hand-rolled claim loop. Both keep jobs in PostgreSQL, so creating an `analysis_run` and its job can happen **in one transaction**. The v0.1 subprocess runner is reused unchanged. Only its caller moves from the API to the worker.

**Cancellation design (v0.2, Recommendation):** the worker checks a `cancel_requested` flag between steps. During a step, it polls the flag and sends `SIGTERM` then `SIGKILL` to the tool's process group. The step is recorded as `cancelled` and the run as `cancelled`.

**Shape the v0.2 worker for gate I1 (Recommendation):** keep the code that talks to PostgreSQL (job claiming, result insertion) separate from the code that invokes adapters, behind a small "run this adapter on this input, return this result file" interface. Gate I1 can then move adapter execution into its own container without a redesign. v0.2 still accepts self-authored inputs only.

#### 5.4.3 Isolated analysis boundary (gate I1)

**Purpose:** the minimum design that must exist, be tested, and be reviewed **before** Bytasm accepts any binary that is not self-authored (tier T1, §3.4). It is a planned gate, not a scheduled release. Everything below is a **Recommendation** to be re-checked against current documentation when it is built.

**Design:**

```
 API (no parsing) ──► PostgreSQL ◄── Orchestrator worker (DB access, never parses)
                                          │ writes job dir: input path (ro), adapter, limits
                                          ▼
                              spool volume: jobs/<id>/  ──►  Analysis container ("analyzer")
                                          ▲                   network_mode: none
                                          │                   no secrets, no DB credentials
                              results/<id>/result.json ◄──    blobs mounted read-only
                         (validated as untrusted output)      read_only rootfs + tmpfs
```

| Requirement | Why | Documentation basis |
|---|---|---|
| Parsers run **only** in the analyzer container. The API and the orchestrator worker never parse. | Separates code that handles untrusted bytes from code that holds credentials | Recommendation |
| Analyzer uses `network_mode: none` | "Turns off all container networking", leaving only loopback | Docker Compose services reference and `none` driver (**verified**) |
| No DB credentials, tokens, or other secrets in the analyzer's environment or filesystem. It communicates only through a spool directory. | A compromised parser has nothing valuable to read and no channel except the result file | Recommendation |
| **No Docker socket** anywhere, so no per-job container spawning through the socket | Access to the daemon is effectively host control | Docker security docs, OWASP Docker CS rule 1 (**verified**) |
| Blob store mounted **read-only**. Each job writes only to its own results directory. | A compromised parser cannot alter stored samples or other jobs' results | OWASP Docker CS rule 8 (**verified**) |
| `read_only: true` root filesystem + `tmpfs` scratch, non-root `user`, `cap_drop: [ALL]`, `no-new-privileges:true` | Least privilege inside the container | Compose services reference, OWASP Docker CS rules 2–4, 8 (**verified**) |
| Explicit `mem_limit`, `cpus`, `pids_limit`, plus per-process rlimits and timeouts inside | Docker applies no limits by default. Limits bound exhaustion, not access. | Docker resource-constraints docs (**verified**) |
| Default seccomp profile kept (never `unconfined`). Evaluate a tighter custom profile. | The default profile is "moderately protective" | Docker seccomp docs (**verified**) |
| Orchestrator treats `result.json` as hostile: size cap, schema validation, fixed reason codes, no adapter text shown to users | The analyzer may be compromised | Recommendation |
| Optionally run the analyzer under gVisor (`runsc`) where available, and record compatibility and performance | Reduces kernel attack surface. gVisor's stated goal is to *minimise*, not eliminate, escape risk. | gVisor docs (**verified**) |

**What gate I1 still does not provide:** a guarantee against container escape. Containers share the host kernel. On macOS and Windows, Docker Desktop runs containers inside a Linux VM, which adds a boundary between containers and the host (**verified**), but Bytasm should not rely on that as its only layer. I1 is therefore sufficient for **T1** (authorised, not suspected) inputs **only after review**. It is **not** sufficient for **T2** (potentially malicious) inputs. T2 additionally requires running Bytasm in a dedicated, disposable VM or host that holds no sensitive data, plus its own threat model and specialist review (§8.3).

**Exit criteria for gate I1:**

1. A written threat model for the analyzer boundary in `docs/threat-model.md`.
2. Automated boundary tests run in CI. From inside the analyzer:
   - No non-loopback network interface exists, and outbound connections fail.
   - No DB credentials or other secrets are readable.
   - Writing to the blob mount fails.
   - Each resource limit triggers a controlled failure.
   - The orchestrator rejects malformed or oversized result files.
3. Compose settings asserted by a CI check.
4. An independent review of the design and tests by someone with container-security experience. **⚠ Needs specialist security review.**
5. The README and the import UI are updated to describe T1 support and its limits.

Only then may the `written_permission` and `public_fixture_terms_permit` bases be enabled.

### 5.5 Binary-file storage

**Recommendation:** a local directory in a Docker volume, content-addressed: `data/blobs/sha256/<aa>/<bb>/<full-hash>`. No extension, file mode `0400`, never under any web-served path. The API serves downloads only via an endpoint that looks up an ID, sets `Content-Disposition: attachment` and `Content-Type: application/octet-stream`, re-verifies the blob's SHA-256 before serving it, and logs the access. Upload temp files live in `data/tmp/` on the same volume, so placing a blob is an atomic rename (§5.4.1). Raw tool outputs go in `data/outputs/<run_id>/<invocation_id>/{stdout.json,stderr.log}`, also referenced by hash.

Object storage (MinIO/S3) can wait until a hosted phase.

### 5.6 Integration with analysis tools

| Tool | Role in Bytasm | License (verified) | Integration | Release |
|---|---|---|---|---|
| **LIEF** | Parse PE/ELF: headers, sections, imports/exports, entry point. The adapter also computes per-section entropy itself (§3.2). | Apache-2.0 | Python package `lief`, wrapped in an adapter subprocess emitting JSON | **v0.1** |
| **Built-in strings extractor** | ASCII/UTF-16LE strings with file offsets | Bytasm's own | Small Python module (good learning exercise, fully testable) | v0.2 |
| **YARA-X** | Rule matching with byte offsets | BSD-3-Clause. Legacy YARA is in maintenance mode (**verified**). | `pip install yara-x`. `Scanner.set_timeout()` and per-match `offset`/`length` (**verified**). | v0.2 |
| **capa** | Capability detection, ATT&CK/MBC mapping | Apache-2.0 | CLI with `-j` JSON output, run as subprocess. Pin the capa and capa-rules versions in the image. | v0.4 |
| pefile | PE parsing (MIT) | MIT | Optional cross-check for LIEF in tests | Later / tests |
| pyelftools | ELF + DWARF parsing (public domain, Python ≥ 3.11) | Public domain | Optional cross-check or DWARF details | Later |
| FLOSS | Obfuscated/stack/decoded strings | Apache-2.0 | CLI `-j`. Its documentation is PE-oriented, and ELF support was not confirmed in research. | Later |
| Ghidra (headless / PyGhidra) | Functions, decompiler excerpts | Apache-2.0 | PyGhidra 3.2.0 (Oct 2026), Ghidra 12.2, JDK 25 | v0.5 |
| ghidriff | Function-level diff | **GPL-3.0** | Separate CLI/container | v0.7, after licensing review |

**Adapter contract (Recommendation).**

- **Invocation:** `python -m bytasm.adapters.<name> --input <path> --out <result.json>`, as an argv list with no shell. The child gets an explicit minimal environment with no secrets, its own process group, and no `preexec_fn`.
- **First action:** the adapter lowers its own resource limits with `resource.setrlimit` **before importing any parsing library**. §5.4.1 lists the v0.1 values.
- **Exit codes:**
  - `0`: success. `result.json` conforms to the adapter schema (`tool`, `tool_version`, `adapter_version`, `status`, `metadata`, `warnings[]`; `findings[]` from v0.2).
  - `2`: input rejected. Exactly one reason code from a fixed list is printed on stdout.
  - Anything else: failure.
- **Caller checks:** the caller (the API in v0.1, the worker from v0.2) validates the result's size and its schema with Pydantic **before** inserting anything. It never uses output from a process that timed out, was killed, or exited non-zero.
- **External CLIs (capa, v0.4):** the adapter calls the CLI, keeps its raw JSON untouched as the raw output, and maps it to the Bytasm schema.

**Why capa comes last (v0.4):** capa does real code analysis (its default backend analyses functions), so it is the slowest and heaviest step, and it needs the background worker. It also has documented limitations: packed files, installers, and wrapper functions can give "misleading or incomplete" results (**verified**). These limits should appear in the UI next to capa findings.

### 5.7 Local-first developer experience

- `docker compose up` starts `db`, `api`, and `web` (Vite dev server, or the built static bundle served by the API in "demo" mode). A `worker` service is added in v0.2, and an `analyzer` service at gate I1. The API container uses `init: true`, which runs an init process that "forwards signals and reaps processes" (**verified**, Compose reference), so child processes don't outlive it.
- The input policy defaults to `fixtures`, which is the only mode during M0–M1. After the M1 acceptance tests pass, `self_built` may be enabled by an explicit local server setting, documented next to its risk. It cannot be enabled remotely, and the server refuses it on a non-loopback binding.
- v0.1 runs its parser in the Linux container, where the resource limits are tested (§5.4.1 Q5). Running the API natively on the host is for development with fixtures only. Neither setup is suitable for untrusted files.
- Everything binds to `127.0.0.1` only. OWASP notes Docker-published ports can bypass host firewalls like UFW (**verified**).
- `make fixtures` rebuilds test binaries in a pinned compiler container (§9.2).
- `make test`, `make lint`, `make e2e`.
- **Apple Silicon note (assumption to verify early):** check that LIEF wheels exist for `linux/arm64` and `linux/amd64` (M1), since Docker on an M-series Mac runs ARM Linux containers. yara-x is checked at the start of v0.2, and capa at the start of v0.4. This is the *host/container* architecture, which is independent of the architecture of the binaries Bytasm inspects.

### 5.8 Portfolio demo deployment

**Recommendation:** do **not** host a public upload endpoint. Instead:

1. Provide a one-command local run.
2. Record a 3–5 minute screen capture.
3. Optionally publish a **read-only static demo**: pre-generated HTML reports and a static UI build with fixture data baked in, hosted on GitHub Pages. There are no uploads, no backend, and no attack surface for strangers' files.

### 5.9 Recommended architecture (summary)

> **v0.1 (self-authored inputs only):** React/TypeScript SPA → FastAPI (single process) → input policy check (fixture-manifest hash by default) → one resource-limited LIEF adapter subprocess per admitted import, awaited by the request (one at a time) → PostgreSQL (data) + local content-addressed blob store. Everything runs with Docker Compose on localhost.
>
> **v0.2+:** the same, plus a separate worker container (PostgreSQL-backed jobs) that runs the subprocess adapters (LIEF, strings, YARA-X, later capa). Inputs remain self-authored.
>
> **Gate I1:** parsing moves into a network-less, secret-less analyzer container with read-only inputs (§5.4.3). Only then are authorised third-party binaries accepted.

Trade-offs in plain English:

- **One language for backend and analysis** (Python) means less glue, at the cost of not reusing your Java/Ruby work.
- **No queue in v0.1** means fewer moving parts and no stuck jobs. The cost is that the parser shares the API container (see the limitations in §5.4.1), which is acceptable only for self-authored inputs on a private, local install.
- **PostgreSQL as queue (v0.2+)** means one less service and transactional job creation, at the cost of not scaling to thousands of jobs per second (irrelevant here).
- **Subprocess adapters** cost a little latency per step, but you get crash isolation, uniform timeouts, uniform provenance, and a clean place to add Ghidra later.
- **No microservices.** The API and worker share one codebase and are separate *processes*, which is enough.

### 5.10 Do the frontend references support the product?

All three reference images exist and were inspected. They are third-party screenshots kept as local-only references under `docs/design/references/` and are omitted from the repository because redistribution rights have not been confirmed. What is actually visible:

**`frontend-ref-1.png` ("vexa", light theme, 1860×1246).** A monitoring/network dashboard. It has a top bar with a logo, a wide search field with a `⌘ + S` "quick search" hint, a dark-mode toggle, and an avatar. A left sidebar groups navigation ("Main tools": Monitoring with sub-items like Distributed tracing, Performance stability, Errors; plus Data base with a count badge, Terminal with a lock icon, Integrations), and at the bottom it has "Get the Info" links and an onboarding card. The main area has a back-link breadcrumb and a large title (an IP address) with a green check status and "Checked every 30 seconds". Two-column **key/value detail blocks** ("IP details", "Payload information") have muted labels and darker values. A line chart card ("Response time") has Day selector, chart-type toggles, and a legend. A **right-hand panel** ("IP conflicts report") has radio cards, a "Conflict log" list of IDs with coloured shape markers (triangle, circle, square) and expandable rows showing explanatory text, a hover tooltip, and a **format selector (CSV) + Download button**. Lots of whitespace, rounded cards, and a blue/purple accent.

**`frontend-ref-2.png` ("Fortexa", dark purple, 1356×962).** A marketing-style photo of a tablet at an angle, with a dark UI. It shows tabs (Dashboard, Findings, Attack Surface), KPI cards with large percentages ("125% Total Threats", "17% Video file risk", "46% Image file risk", "29% Docs file risk") and decorative mini charts, a large **"Risk Score 70%" radial gauge**, and an "Attack Surface Overview" table (checkbox, name, connector with cloud logos, workload, "Security Score" segmented bars with percentages, date, permissions icons). Glow effects and low-contrast small text.

**`frontend-ref-3.png` ("PD — Detections", dark navy, 1236×908).** A detections table on a laptop. It has an icon-only left rail, a page title with a count badge ("2579 Files"), a Filters button and a search box with a "Standard Search / Similar ID Search" toggle, **removable filter chips** (PII Type, Status "Complete +2", File Type JPEG, "+ ML Labels", "+ Labels", "Clear Filters"), and an open multi-select dropdown with searchable, grouped options and counts. The data table has columns ID, Title, File type, Ingested, **Status pills with a dot plus text** (Flagged, Complete, Incomplete, Discarded), Detections tags, and a truncated "PII Reasoning" column with a tooltip. Row checkboxes allow bulk selection.

**What translates well to Bytasm:**

| Visible idea | Bytasm use |
|---|---|
| Ref 1 key/value two-column detail blocks | Sample overview metadata (format, arch, entry point, hashes) |
| Ref 1 right-hand detail panel with expandable log rows | **Evidence drawer** next to the findings table, and the run log |
| Ref 1 back-link breadcrumb + title + status line | "← Project / my-cli-tool v1.3", "Last analysed 10:42 · Partial (capa timed out)" |
| Ref 1 format selector + Download | Report export (JSON / HTML) |
| Ref 1 grouped sidebar with labelled items | Project navigation: Overview, Runs, Findings, Compare, Report |
| Ref 1 quick search with a keyboard hint | Search strings, imports, and findings within a project |
| Ref 3 filter chips + searchable multi-select with counts | Findings filters: tool, category, review state, with counts |
| Ref 3 status pills with dot **and** text | Run/step states: Queued, Running, Succeeded, Partial, Failed, Cancelled |
| Ref 3 dense table, monospace-friendly IDs, count badge | Findings, strings, imports, diffs |
| Ref 2 tab bar (Dashboard / Findings) | Sample-level tabs |
| Ref 2/3 dark theme | Offer dark **and** light themes. Many analysts prefer dark, but readability comes first. |

**What should not be copied:**

- **Ref 2's "Risk Score 70%" gauge and percentage KPI cards.** A single risk score implies a verdict Bytasm explicitly does not make (§10). Use **counts with provenance** instead ("12 findings from 3 tools; 4 reviewed").
- **Ref 2's glow, perspective, and low-contrast small text.** These are marketing-render effects that hurt legibility and WCAG contrast.
- **Ref 2's decorative mini-charts without axes.** Every Bytasm chart must have labelled axes and an accessible table alternative.
- **Ref 3's icon-only rail without labels.** Use labelled navigation, or icons with visible labels on hover *and* focus plus `aria-label`.
- **Ref 3's truncated "reasoning" text.** Evidence must be fully reachable (drawer), not hidden in hover-only tooltips, which keyboard and touch users can't use.
- **Ref 1's coloured shapes as the only status signal.** Always pair them with text.
- **Ref 3's "ML Labels" / "Similar ID Search".** These imply ML features Bytasm doesn't have.

---

## 6. Initial data model

This section describes the full model. Each entity is tagged with the release that introduces it, so the v0.1 schema stays small: `project`, `sample`, `sample_version`, `authorization_record`, `analysis_run`, `tool_invocation`, `section`, `symbol`, `report`.

Plain-language overview: a **project** holds **samples** (logical programs). Each sample has one or more **sample versions** (concrete files, identified by SHA-256), each with an **authorisation record**. Running an **analysis profile** on a version creates an **analysis run**, made of **tool invocations**. Each invocation produces **findings**, and each finding has **evidence**. Humans add **annotations** to versions, findings, or evidence. **Reports** are exported snapshots.

```
analyst 1─* project 1─* sample 1─* sample_version 1─1 authorization_record
                                        │
                                        1
                                        *
analysis_profile 1─* analysis_run *─1 sample_version
                          │1
                          *
                    tool_invocation 1─* finding 1─* evidence
                          │                 ▲            ▲
                    rule_set (snapshot)     │            │
                                       annotation (target: version | finding | evidence)
report *─* analysis_run           activity_event (append-only, per project)
```

| Entity | Release | Key fields | Notes |
|---|---|---|---|
| **project** | v0.1 | `id`, `name`, `description`, timestamps | `purpose` and `created_by` are added later. |
| **sample** | v0.1 | `id`, `project_id`, `name` | A logical program, such as "my-cli-tool". |
| **sample_version** | v0.1 | `id`, `sample_id`, `version_label`, `sha256` (indexed), `size_bytes`, `declared_filename` (untrusted, display only), `detected_format` (`pe`/`elf`), `blob_path`, `admitted_under` (`fixture_manifest` / `self_built_optin`), `imported_at` | Unique on (`sample_id`, `sha256`). The same bytes can appear in two projects; the blob is stored once. Created only by a fully successful import (§5.4.1). `admitted_under` records which input policy let it in (§3.4). |
| **authorization_record** | v0.1 | `sample_version_id`, `basis`, `statement`, `terms_reference`, `recorded_at` | `basis`: `owned_or_built` only in v0.1; `written_permission` / `public_fixture_terms_permit` only after gate I1. `terms_reference` is unused in v0.1; after I1 it is required for `public_fixture_terms_permit` and holds a reference note for `written_permission`. Immutable once written. **Self-attestation for record-keeping, not proof of permission or a legal determination.** |
| **analysis_run** | v0.1 | `id`, `sample_version_id`, `profile_snapshot` (JSONB; a constant single-step profile in v0.1), `status`, `failure_reason`, `started_at`, `finished_at`, `bytasm_version`, `image_digest` | v0.1 statuses: `succeeded` only. A failed import persists nothing, so the reason is logged instead (§5.4.1). v0.2 adds `queued`/`running`/`partial`/`failed`/`cancelled`, `queued_at`, and `cancel_requested`. |
| **tool_invocation** | v0.1 | `id`, `run_id`, `step_index`, `tool_name`, `tool_version`, `adapter_version`, `args` (JSONB), `status`, `exit_code`, `duration_ms`, `raw_output_path`, `raw_output_sha256`, `warnings` (JSONB) | The provenance anchor. v0.2 adds `rule_set_id`, `stderr_path`, `peak_rss_kb`, and the statuses `skipped`/`timed_out`. |
| **section** | v0.1 | `id`, `invocation_id`, `index`, `name` (untrusted text), `file_offset`, `raw_size`, `virtual_address`, `virtual_size`, `flags`, `entropy` (nullable float, bits/byte), `entropy_method`, `entropy_note` (`no_file_data` / `range_exceeds_file`) | Entropy is a **measurement** computed by Bytasm's adapter (§3.2). |
| **symbol** | v0.1 | `id`, `invocation_id`, `direction` (`import`/`export`), `library`, `name` (untrusted text), `ordinal`, `address` | |
| **report** | v0.1 | `id`, `sample_version_id` (v0.1 scope), `format` (`json`), `sha256`, `generated_at`, `generator_version`, `path` | v0.3+ adds a JSONB `scope` for comparisons. v0.4 adds `html`. |
| **analysis_profile** | v0.2 (seeded, read-only) | `id`, `name`, `steps` (JSONB: ordered tool + params + timeout) | Editing comes later. |
| **finding** | v0.2 | `id`, `invocation_id`, `kind` (`string`/`yara_match`/`capability`/…), `title`, `rule_id`, `tool_reported_attributes` (JSONB: ATT&CK/MBC IDs, namespaces), `fingerprint` (stable key for diffing) | No "severity" or "malicious" field. Tool-reported attributes are kept *as reported*. |
| **evidence** | v0.2 | `id`, `finding_id`, `kind` (`byte_range`/`virtual_address`/`section`/`import`/`export`/`string`/`raw_pointer`), `file_offset`, `length`, `virtual_address`, `section_name`, `excerpt_hex` (capped, e.g. 256 bytes), `raw_json_pointer` | `raw_json_pointer` (RFC 6901 style, e.g. `/rules/create TCP socket/matches/0`) points into the raw tool output. |
| **rule_set** | v0.2 | `id`, `tool` (`yara-x`/`capa`), `name`, `version`, `sha256`, `source` (`bytasm-repo`/`upstream@tag`) | Lets reports say exactly which rules matched. |
| **activity_event** | v0.2 | `id`, `project_id`, `actor_id`, `type`, `payload` (JSONB, no file contents), `at` | Audit trail. |
| `string_occurrence` | v0.2 | `invocation_id`, `offset`, `encoding`, `value` (untrusted text) | |
| **analyst** | v0.3 (one row) | `id`, `display_name`, `created_at` | Local single user. Introduced with annotations, so they have an author. |
| **annotation** | v0.3 | `id`, `target_type`, `target_id`, `kind` (`note`/`interpretation`/`conclusion`), `body` (plain text or a restricted Markdown subset), `confidence` (conclusions only), `cites` (array of finding/evidence IDs, required for conclusions), `author_id`, `revision`, `supersedes_id`, `created_at` | Append-only revisions. |
| comparison | v0.3 (computed on the fly) | `version_a`, `version_b`, `run_a`, `run_b`, `summary` | Persist only if it gets slow or needs to be cited in reports. |
| workspace / membership / role | Later | | Team features. |
| corpus index tables | Later | | Search across samples. |

**Sections, symbols, and (from v0.2) strings** are normalised rows tied to the invocation that produced them. They power the overview and the diff, and they are good material for SQL practice. They are *observations*, not findings. From v0.2, only selected observations become findings, for example a YARA-X match or a "writable + executable section" check. Entropy stays a measurement and is never turned into a finding automatically (§3.2).

---

## 7. API and frontend design

### 7.1 Screen map

| Screen | Release | Purpose |
|---|---|---|
| **Projects dashboard** | v0.1 | List projects with sample count and "New project". (Last activity from v0.2.) |
| **Project detail** | v0.1 | Samples and their versions. (Latest run status per version and recent activity from v0.2.) |
| **Import & validate** (dialog or page) | v0.1 | Upload, input-policy disclosure (self-authored only, current mode shown), authorisation self-attestation (`owned_or_built`), validation result or rejection. |
| **Sample version overview** | v0.1 | Identity (hash, size, declared filename marked untrusted, admitted-under policy), metadata key/value panel, sections table with entropy measurement, Imports / Exports tabs, "Export JSON report". (Strings tab and run history from v0.2.) |
| **Analysis run** | v0.2 | Steps with states, durations, plain-language messages, collapsible technical log, cancel. |
| **Findings & evidence** | v0.2 (annotations v0.3) | Filterable table + evidence drawer. |
| **Compare** | v0.3 | A vs B structural diff. |
| **Report preview & export** | v0.4 | Exact preview, format choice, download. |
| **Tools & profile** (read-only) | v0.3+ | Installed tool versions, rule-set hashes, default profile steps and timeouts. |
| Profile editor | Later | |
| Corpus search | Later | |

### 7.2 API surface

REST, JSON, versioned under `/api/v1`, described by the OpenAPI document FastAPI generates. A typed TypeScript client is generated from it.

**v0.1:**

```
GET    /api/v1/projects
POST   /api/v1/projects
GET    /api/v1/projects/{project_id}
GET    /api/v1/projects/{project_id}/samples
POST   /api/v1/projects/{project_id}/imports               (raw body: application/octet-stream;
                                                            metadata in X-Bytasm-Import header, see §5.4.1)
GET    /api/v1/sample-versions/{id}
GET    /api/v1/sample-versions/{id}/sections | /imports | /exports
GET    /api/v1/sample-versions/{id}/download                (attachment, octet-stream, hash re-verified)
POST   /api/v1/sample-versions/{id}/reports                 (JSON report)
GET    /api/v1/reports/{id}/download
GET    /api/v1/health
```

**Added later:**

```
v0.2  GET  /api/v1/sample-versions/{id}/strings?query=&offset=&limit=
v0.2  POST /api/v1/sample-versions/{id}/runs                ({ "profile_id": "default-static" })
v0.2  GET  /api/v1/runs/{run_id}                            (status + steps)
v0.2  GET  /api/v1/runs/{run_id}/log?after=<cursor>
v0.2  POST /api/v1/runs/{run_id}/cancel
v0.2  GET  /api/v1/runs/{run_id}/findings?tool=&kind=&review=&q=
v0.2  GET  /api/v1/findings/{finding_id}                    (with evidence)
v0.2  GET  /api/v1/invocations/{id}/raw                     (attachment)
v0.3  GET  /api/v1/annotations?target_type=&target_id=
v0.3  POST /api/v1/annotations
v0.3  POST /api/v1/annotations/{id}/revisions
v0.3  GET  /api/v1/compare?a=<version_id>&b=<version_id>
v0.3+ GET  /api/v1/tools                                    (availability + versions)
v0.4  POST /api/v1/reports                                  ({ scope, format })
```

Representative v0.2+ response, `GET /api/v1/runs/{id}`:

```json
{
  "id": "run_01J…",
  "sample_version_id": "sv_01J…",
  "status": "partial",
  "failure_reason": null,
  "started_at": "2026-11-03T10:41:02Z",
  "finished_at": "2026-11-03T10:44:51Z",
  "steps": [
    {"tool": "metadata", "tool_version": "lief 1.0.0", "status": "succeeded", "duration_ms": 412},
    {"tool": "strings",  "tool_version": "bytasm 0.1.0", "status": "succeeded", "duration_ms": 95},
    {"tool": "yara-x",   "tool_version": "1.x", "rule_set": "bytasm-rules@0.1 (sha256:9f2…)", "status": "succeeded", "duration_ms": 61},
    {"tool": "capa",     "tool_version": "9.x", "status": "timed_out", "duration_ms": 180000,
     "message": "capa did not finish within 180 s. Results from other tools are complete."}
  ],
  "counts": {"findings": 17, "by_tool": {"metadata": 2, "yara-x": 15}}
}
```

(Version strings above are illustrative. Real values come from the installed tools.)

Errors use one shape everywhere (RFC 9457 "problem details" style is a good fit):

```json
{"type": "https://bytasm.dev/errors/unsupported-format", "title": "Unsupported file format",
 "detail": "The file is a ZIP archive. Bytasm 0.1 accepts PE and ELF files only.", "status": 422}
```

v0.1 import responses use these status codes:

- 201: created
- 403 (`input_policy`): in `fixtures` mode, the hash is not in the fixture manifest. The file was never parsed.
- 409: duplicate within the sample
- 413: too large
- 415: not PE/ELF, or an archive
- 422: invalid metadata, empty file, malformed, or parse timeout
- 503 + `Retry-After`: the parser slot is busy

Rejection messages come from a fixed server-side list. Adapter output is never echoed to the user.

**Run progress (v0.2+):** start with polling (`GET /runs/{id}` every 2 s while active). It is simple and robust. Server-Sent Events can come later. In v0.1 the import request itself is the progress unit: the UI shows "Uploading…" and then "Validating and reading metadata…" until the response arrives.

### 7.3 Loading, empty, error, and partial states

| State | Release | Treatment |
|---|---|---|
| Loading | v0.1 | Skeleton rows matching the final layout. No spinners longer than 300 ms without text. |
| Empty | v0.1 | One sentence explaining what will appear plus the single next action ("No samples yet. **Import a binary**"). |
| Error / rejected | v0.1 | What failed, in human terms, then what the user can do, then a collapsible technical detail with a request ID. Rejections state that nothing was imported. |
| Busy | v0.1 | "Another file is being validated. Try again in a few seconds." (503 from the single parser slot). |
| Refused by input policy | v0.1 | "This version only accepts Bytasm's test fixtures. The file was not parsed or stored." Includes a link to the README's supported-inputs section. No option to override from the UI. |
| **Partial** | v0.2 | A persistent banner on run, findings, and report: "Partial result: YARA-X timed out. Findings below come from metadata and strings only. Absence of a YARA-X match does not mean the pattern is absent." The same text goes into the report. |
| Cancelled | v0.2 | Kept in history, greyed, with what had finished before cancellation. |

### 7.4 Accessibility requirements (recommendation: target WCAG 2.2 AA)

- Every interaction works by keyboard, with visible focus rings, and the drawer traps and returns focus.
- Colour is never the sole signal (diffs use `+`/`−`/`~` and text, statuses use dot plus label).
- Text contrast ≥ 4.5:1 (≥ 3:1 for large text and UI boundaries), checked in both themes.
- Tables use real `<table>` semantics with header cells. Sortable columns announce their sort state.
- Live regions (`aria-live="polite"`) announce run status changes.
- Hex excerpts and hashes use a monospace font and have a "copy" button with an accessible name.
- Charts (if any) have a table alternative.
- Respect `prefers-reduced-motion` and `prefers-color-scheme`.
- Automated checks: axe-core in Playwright tests, plus a manual keyboard pass per milestone.

### 7.5 Communicating uncertainty and authorship

- **Two visual families.** *Tool findings* have a neutral card, a tool badge ("YARA-X · rule `url_reference`"), and the wording "matched", "reported", "observed". *Analyst annotations* have a distinct left border and author avatar, and are labelled **Note / Interpretation / Conclusion**.
- **Wording rules.** The UI never says "malicious", "safe", "detected malware", or "risk score". It says what was matched or observed and by which tool.
- **Coverage notes.** Next to capa findings, show capa's own documented limitations when relevant (packed sample warning, installer warning). Show "not analysed" when a step was skipped or failed.
- **Declared vs verified.** Header values (timestamps, linker versions) carry a "declared in file" hint.
- **Conclusions require citations.** The UI won't save a Conclusion without at least one linked finding or evidence item.

### 7.6 Making long-running analyses understandable (v0.2+)

- Show **steps**, not queue internals. "capa: analysing code features (step 4 of 4)", not "job 8812 picked by worker-1".
- Show elapsed time and the step's timeout ("up to 3 min").
- Explain *why* a step can be slow in one sentence, on demand.
- Keep the technical log available but collapsed by default. Strip terminal control sequences and truncate long lines.
- Allow leaving the page. Runs continue, and the project page shows their state.

---

## 8. Security and privacy threat model

### 8.1 Scope, assets, actors, trust boundaries

- **Assets:** the host machine and its credentials (SSH keys, cloud tokens, browser data), the user's samples (may be confidential), annotations and reports, and the integrity of results.
- **Threat sources:** a crafted binary designed to exploit a parser (memory-safety bugs in native parsers, decompression or recursion bombs, pathological inputs causing CPU or memory blowup), malicious strings embedded in a binary that target the UI (XSS) or the terminal (escape sequences), a compromised dependency or tool release, and (if network-exposed) other people on the network.
- **Trust boundaries:** browser ↔ API, API ↔ storage, worker ↔ tool subprocess, tool output ↔ database, database ↔ rendered HTML (UI and reports).

**Important (fact vs. claim):** Bytasm never executes samples in any planned release before the dynamic-analysis research track. **Parsing is still an attack surface.** Parsers and analysers process bytes that, for untrusted input, an attacker controls. Containers reduce the blast radius but are **not** a security boundary strong enough for running arbitrary code. Docker's own documentation warns that default capabilities and mounts "may provide incomplete isolation" (**verified**).

**The v0.1 security model, stated candidly.** v0.1's security rests on **not parsing untrusted input at all** (§3.4).

| v0.1 does | v0.1 does not |
|---|---|
| Refuse, by default, any file whose SHA-256 is not in Bytasm's committed fixture manifest, before parsing | Verify that a `self_built` (opt-in) file really is self-authored. That rests on the operator. |
| Keep LIEF out of the API process and bound parser crashes, hangs, memory, CPU, and output | Contain a parser **exploit**. It would run as the API's user, with the API container's files, reachable secrets, and network. |
| Apply basic upload hygiene (size limit, content checks, archive rejection, hash-based paths, storage outside served paths) and escape all sample-derived text | Make parsing untrusted files safe. Resource limits and containers reduce some risks; they do not provide isolation. |
| Record a self-attestation of authorisation | Prove authorisation or make a legal determination |
| Run only on localhost with request guards | Defend a network-exposed or multi-user deployment |

**Using v0.1 with downloaded, received, third-party, or suspicious binaries is outside its design and unsupported.** Gate I1 (§5.4.3) is the minimum before that changes, and potentially malicious files need more (tier T2, §3.4).

### 8.2 Threats, mitigations, and when they land

Release/gate values:

- **v0.1** = required in the first release.
- **Public** = before the repository or a demo video is public.
- **v0.2** = with the background worker.
- **I1** = gate I1, before any non-self-authored input (§5.4.3).
- **Non-local** = before any access beyond localhost.
- **Hosted** = §8.3.

| Threat | Mitigation (recommendation unless marked) | Release / gate | Source basis |
|---|---|---|---|
| Untrusted or crafted input reaching a parser without an isolation boundary | **Input policy:** `fixtures` mode (hash allowlist from the committed manifest, checked before parsing) is the default. `self_built` is a local-config-only opt-in, allowed after M1 acceptance tests, refused on non-loopback bindings, and recorded per sample. Only the `owned_or_built` basis is offered. No API or UI override. Gate I1 is required before widening. | v0.1 (policy) · I1 (wider inputs) | Recommendation |
| Trusting filename / extension / `Content-Type` | Identify by magic bytes **and** a full parse. Store the declared name as untrusted display text only. | v0.1 | OWASP File Upload CS (**verified**: Content-Type is "trivial to spoof"; signature checks should not be used alone) |
| Oversized uploads, disk exhaustion | Streaming limit (64 MiB, provisional) enforced mid-stream on the raw body, early `Content-Length` check, empty files rejected. A total-storage quota warning comes later. | v0.1 (quota later) | OWASP (**verified**: set size limits) |
| Path traversal / filename tricks | Server-generated storage paths from the SHA-256 only. The user filename never touches the filesystem. | v0.1 | OWASP (**verified**: application-generated names) |
| Storage reachable from the web | Blob directory and upload temp directory outside any served path. Downloads only via an ID lookup endpoint as an attachment. | v0.1 | OWASP (**verified**: storage outside webroot preferred) |
| Archive bombs, nested archives | **Archives rejected.** If archive import is ever added: decompressed-size budget, file-count and depth limits, and path normalisation on extraction. | v0.1 | OWASP (**verified**: ZIP "not recommended", beware zip bombs, limit decompressed size) |
| Parser bug: crash, hang, resource exhaustion (on admitted input) | Parser never runs in the API process. Each parse runs in a subprocess with wall-clock timeout (30 s), self-applied `RLIMIT_AS` (1 GiB), `RLIMIT_CPU`, `RLIMIT_FSIZE`, a clean env, bounded output, a process-group kill, and one parser at a time. Partial output is never used. These are **robustness controls, not a sandbox.** See §5.4.1 for the lifecycle, limitations, and open questions Q1–Q8. | v0.1 | Python `subprocess`/`asyncio`/`resource` docs (**verified**) + recommendation |
| Parser exploit reaching host or app secrets (v0.1 shares the API container) | **Primary: input policy (above).** Defence in depth: containers run as non-root, with `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, explicit `mem_limit`/`cpus`/`pids_limit` (none apply by default), `init: true`, **no Docker socket**, no bind mounts of `$HOME` or the project directory, only the named data volume, and the default seccomp profile. The child gets a clean env. **Residual risk:** an exploit runs as the API's user (§5.4.1 limitations). | v0.1 | OWASP Docker CS (**verified**: rules 1–4, 7), Docker docs (**verified**: socket control = host control; no default resource constraints; seccomp default) |
| Same, real separation | Analyzer container (§5.4.3): `network_mode: none`, no secrets or DB credentials, blobs mounted **read-only**, `read_only: true` + `tmpfs`, limits, file-spool hand-off, boundary tests, independent review | I1 | Docker Compose reference, OWASP Docker CS rule 8 (**verified**) + recommendation |
| Parser making network calls (exfiltration) | v0.1–v0.4: **not restricted** (accepted only because inputs are self-authored, §5.4.1). At I1 the analyzer has no network. A Compose `internal: true` network is "externally isolated" but still reaches the other services on it (**verified**), so it is not used for the analyzer. Tool rules are baked into the image at build time. | I1 | Docker Compose networks / `none` driver docs (**verified**) |
| Automatic third-party submission | No outbound integrations. Hash lookups (if ever) are opt-in per sample, with the privacy implication explained. | v0.1 | Product principle |
| Malicious tool output (huge, malformed, hostile strings) | Output size cap, schema validation before DB insert, unknown fields dropped, fixed reason codes instead of adapter text, all extracted text treated as untrusted. Control characters stripped from logs. | v0.1 | Recommendation |
| XSS in the UI | React escaping by default. **Ban `dangerouslySetInnerHTML`** with a lint rule. Filenames, section names, symbol names, and diagnostics rendered as text only. Strict CSP for the SPA (`default-src 'self'`, no inline scripts). From v0.3, annotations are shown as plain text or a DOMPurify-sanitised Markdown subset. | v0.1 (escaping, lint) · Non-local (strict CSP) | OWASP XSS CS (**verified**: framework escape hatches, DOMPurify, CSP as defence in depth) |
| XSS in exported HTML reports | Rendered by an auto-escaping template engine (Jinja2 with autoescape on). **No JavaScript in reports.** `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">`. Tests use strings like `<script>alert(1)</script>` and `"><img src=x onerror=…>` to prove escaping. In v0.1 the JSON report is served as an attachment with `application/json`. | v0.4 (HTML) | OWASP XSS CS (**verified**) + recommendation |
| Cross-site requests against the local, unauthenticated API (a page the user visits POSTs a crafted file) | Bind to `127.0.0.1`. `Host` header allowlist (also blunts DNS rebinding). Required custom header (`X-Bytasm-Import` for imports) on state-changing requests, which forces a CORS preflight. No foreign origins allowed. CSRF tokens come with authentication. | v0.1 (tokens: Non-local) | OWASP (CSRF on upload endpoints, **verified**) + recommendation |
| Network exposure | Ports published on `127.0.0.1` only. Refuse to start on a non-loopback interface unless authentication is configured. | v0.1 (binding) · Non-local (auth guard) | OWASP Docker CS (**verified**: rule 5a) + recommendation |
| Resource abuse | One parser subprocess at a time (provisional), 503 when busy, per-parse limits. From v0.2: per-step timeouts and a maximum number of queued runs per sample version. | v0.1 | Recommendation |
| Sensitive data in logs | Log IDs, hashes, sizes, durations, statuses, reason codes. **Never** log file bytes, extracted names/strings, or annotation bodies. | v0.1 | Recommendation |
| Supply chain | Lock files (`uv.lock`, `package-lock.json`) and `pip-audit`/`npm audit` in CI (v0.1). Dependabot or Renovate, secret scanning, SBOM generated with Syft (CycloneDX/SPDX, **verified**), and pinned container base image digests (Public gate). | v0.1 · Public | NIST SSDF practice groups PO/PS/PW/RV (**verified**) |
| Release integrity | Signed git tags (Public gate). Artefact signing and provenance per SLSA (current spec v1.2, **verified**), aiming for SLSA Build L1–L2 using GitHub Actions. | Public · Hosted | SLSA (**verified**) |
| Vulnerability reports | `SECURITY.md` with supported versions and how to report (**verified** GitHub guidance) in v0.1. Enable GitHub private vulnerability reporting (**verified**: available for public repos) at the Public gate. | v0.1 · Public | GitHub docs |
| User misunderstanding of risk or permission | Disclosure on the import screen and in the README, covering four points. v0.1 accepts self-authored binaries only and is not safe for downloaded, received, third-party, or suspicious files. Bytasm never runs imported files. Resource limits are not a sandbox. The authorisation field is a self-attestation, not proof of permission. | v0.1 | Product principle |

### 8.3 Safeguards required before wider inputs, hosting, or dynamic analysis

**Before accepting authorised third-party binaries (tier T1):** gate I1 exit criteria (§5.4.3), including the independent review.

**Before accepting potentially malicious binaries (tier T2), even for static analysis only:**

- Gate I1.
- A dedicated, disposable VM or host that holds no credentials, personal data, or unrelated files, and can be reset after use.
- A stronger runtime boundary considered and documented (gVisor, a microVM, or a full VM).
- A separate threat model and runbook.
- Specialist review. **⚠ Needs specialist security review.**

**Before hosting:**

- Real authentication (OIDC or hardened local accounts) and per-project authorisation checks on every endpoint, with tests.
- TLS, rate limiting, upload quotas per user, and abuse reporting.
- Encryption at rest, backup and restore, data retention and deletion policy.
- Privacy notice and terms. The legal basis for processing uploaded files, which may contain personal data, needs review. **⚠ Needs specialist legal review** (data protection; possible export-control or dual-use considerations).
- An independent security review or penetration test.
- Separate analysis hosts from the API host, building on gate I1.

**Before dynamic analysis:**

- **Hardware-virtualised isolation**, not containers alone. Options include Firecracker microVMs (Linux/KVM only, minimal device model, jailer as a "second line of defense", **verified**), full VMs, or an established sandbox (CAPE) on dedicated hardware. gVisor reduces kernel attack surface but its stated goal is to *minimise*, not eliminate, escape risk, and it has compatibility limits (**verified**). It is better suited to hardening static workers than to detonating malware.
- Disposable guests restored from a snapshot per run. No shared folders. Controlled or simulated network with egress filtering.
- A dedicated host or network segment, with monitoring of the analysis infrastructure itself.
- A written threat model and runbook reviewed by someone experienced in malware analysis infrastructure. **⚠ Needs specialist security review.**

### 8.4 Responsible-use and legal notes

- Bytasm records an authorisation statement but **cannot verify it**. Laws on reverse engineering, licence terms (EULAs), and anti-circumvention vary by jurisdiction. The project should state in its README that users are responsible for having the right to analyse a file, and avoid features aimed at circumvention. **⚠ Needs specialist legal review** if the project is distributed beyond a personal portfolio.
- Licence compatibility: Bytasm can use permissive (Apache-2.0, MIT, BSD-3) dependencies freely with attribution. Bundling GPL-3.0 tools (ghidriff) in a distributed image raises obligations. **⚠ Needs licensing review** before v0.7. A NOTICE/THIRD_PARTY_LICENSES file should be generated from the SBOM.

---

## 9. Testing, reliability, and observability

### 9.1 Test plan

| Area | Tests (examples) | Release | Level |
|---|---|---|---|
| Hashing | SHA-256 of fixtures matches committed `MANIFEST.sha256`. Streaming hash equals full-read hash. Empty file is rejected. | v0.1 | Unit |
| File identification | Each fixture is identified correctly (format, arch as declared, bitness). A PE renamed `.elf` is still PE. A ZIP renamed `.exe` is rejected. Plain text is rejected. | v0.1 | Unit |
| Entropy measurement | Per-section entropy from the adapter matches an independent plain-Python Shannon implementation over the same in-file bytes. The high-entropy fixture section is near 8. `.bss`/zero-raw-size sections give `NULL` ("no file data"). A generated section whose range exceeds the file gives `NULL` plus a warning. | v0.1 | Unit |
| Malformed inputs | **Programmatically generated** corrupt files (truncated headers, `e_lfanew` pointing past EOF, section count = 65535, zero-length sections) produce a *controlled* rejection and never crash the API. A property-based test (Hypothesis) mutates headers of a valid fixture. | v0.1 | Unit + fuzz-style |
| Subprocess runner | Fake adapters (tiny Python scripts):<br>• Success → parsed.<br>• Hang → killed at timeout, process group reaped.<br>• Ignores `SIGTERM` → `SIGKILL` after the grace period.<br>• Forks a child, or a child calls `setsid()` → behaviour recorded (Q4).<br>• Exit 1 → failure.<br>• Exit 2 + reason code → mapped message.<br>• Invalid JSON, oversized result, or huge stdout → failure without reading or keeping excess output.<br>• Exceeding `RLIMIT_AS`/`RLIMIT_CPU`/`RLIMIT_FSIZE` → killed (Q5).<br>• Child env contains no secrets.<br>• Cancellation injected during cleanup (Q3).<br>• No orphan processes or temp directories after each case. | v0.1 | Integration |
| Input policy | `fixtures` mode: a non-manifest file → 403, temp removed, and **the parser is never spawned** (asserted via a spy on the runner). Manifest fixtures are accepted and recorded with `admitted_under = fixture_manifest`. `self_built` mode is off by default, enabled only by local server configuration, and recorded as `self_built_optin`. Starting with `self_built` on a non-loopback binding fails. No endpoint, header, or UI control can change the policy. Any basis other than `owned_or_built` → 422. | v0.1 | API integration |
| Upload validation & lifecycle | Oversize body (with and without `Content-Length`) → 413, temp removed. Empty → 422. Duplicate in sample → 409, no parse. Invalid metadata header → 422 before any body bytes are read. Busy slot → 503. Path-like declared filenames (`../../etc/passwd`) stored only as text. Interrupted uploads (Q1), with and without `Content-Length` → rejected, nothing persisted, no temp file. A body shorter than `Content-Length` is rejected (additional check). Only a body consumed to the ASGI completion signal is accepted. Disconnect mid-parse (Q2) → no orphan process, consistent DB state. Simulated commit failure → no orphan blob. Startup sweep removes stale temp directories and unreferenced blobs. | v0.1 | API integration |
| Cross-site request guard | Import without the custom header, or with a foreign `Host`, is refused. A browser-level request from a second origin is blocked by CORS preflight (Q8). | v0.1 | API integration + E2E |
| Isolation boundary | From inside the analyzer: no non-loopback interface and outbound connections fail, no secrets or DB credentials readable, blob mount not writable, each limit triggers a controlled failure. The orchestrator rejects hostile result files. Compose settings asserted. | I1 | Integration (CI) |
| UI escaping | A generated fixture copy with an HTML-like section name (PE section names are limited to 8 bytes, so use an ELF section name) renders as text in the sample overview. | v0.1 | E2E |
| Report reproducibility | Generating a report twice from the same data gives identical JSON except `generated_at`. The JSON validates against the schema. The report contains the self-attestation notice and limitations. Blob hash is re-verified on export. | v0.1 | Unit |
| Orchestration (worker) | Timeout in one step → run `partial`. Cancel during a step leaves no orphaned process. | v0.2 | Worker integration |
| Finding ↔ evidence | Every finding has ≥ 1 evidence row. Every `byte_range` evidence lies within file size, and its excerpt equals the actual bytes at that offset. Every finding references an invocation with a raw output file whose hash matches. | v0.2 | Integration (invariant checks, which also run as a DB consistency job) |
| Determinism of tools | Re-running the default profile on the same fixture yields identical finding fingerprints (for deterministic tools). | v0.2 | Integration |
| Comparison | v1 vs v2 fixtures yield exactly the known added import/string/finding. Comparing a version with itself yields an empty diff. Mismatched tool versions produce a warning. | v0.3 | Unit + integration |
| HTML report escaping | A fixture with XSS-like strings renders those strings escaped. A snapshot test checks the report contains no `<script`. CSP meta is present. | v0.4 | Unit (render) + e2e |
| Authentication (when enabled) | Non-loopback start without auth refuses to boot. Later: cross-project access denied. | Non-local gate | Integration |
| End-to-end | **v0.1:** create project, import fixture, see metadata, refusal of a non-fixture file by the input policy, rejection of a renamed ZIP, export JSON. axe-core checks on each screen. Later releases extend this to runs, findings, annotations, compare, and HTML. | v0.1+ | E2E |
| CI | v0.1: lint (ruff, eslint), type-check (mypy/pyright, tsc), unit + integration (PostgreSQL service container), one Playwright test, dependency audit. Public gate: secret scan, SBOM artefact, compose-settings assertion. | v0.1 · Public | CI |

### 9.2 Making safe test binaries yourself

Write tiny C programs you author, compile them yourself, and commit both source and binaries:

```c
// fixtures/src/hello_v1.c
#include <stdio.h>
int main(void) { puts("bytasm fixture v1: https://example.invalid/help"); return 0; }
```

```c
// fixtures/src/hello_v2.c — adds a new string and a new imported function, so the diff has something to show
#include <stdio.h>
#include <stdlib.h>
int main(void) {
  const char *home = getenv("HOME");
  puts("bytasm fixture v2: https://example.invalid/help");
  printf("config dir: %s/.bytasm-fixture\n", home ? home : "?");
  return 0;
}
```

Build matrix (inside a pinned Docker image so the compiler version is recorded):

- **v0.1, required:**
  - ELF x86-64: `gcc -O0 -o hello_v1.elf hello_v1.c`, plus a stripped variant (`strip`).
  - PE x86-64: `x86_64-w64-mingw32-gcc -o hello_v1.exe hello_v1.c` (MinGW-w64 cross-compiler).
  - A high-entropy-section ELF: embed 4 KiB of fixed pseudo-random bytes (generated from a seed, committed as a C array) in a named section (`__attribute__((section(".blob")))`). Used to test the entropy *measurement*, not a detection rule.
- **v0.1, time-boxed:** ELF AArch64, built with `aarch64-linux-gnu-gcc …` (cross-compiler). Include it **only if it can be built and tested within half a day**. Otherwise v0.1 documents: *"Parses PE and ELF files of any architecture LIEF supports; tested on x86-64 PE and ELF fixtures. An AArch64 fixture is a later compatibility milestone."* CI never rebuilds fixtures; it reads the committed bytes. The fixture's *target* architecture is unrelated to the host/container architecture that runs Bytasm.
- **v0.2:** `hello_v2` variants for diffing (used in v0.3). An XSS-string fixture, a program whose string literal is `"<script>alert('x')</script>"`, for strings/report escaping tests.
- **Generated in tests, not committed:** malformed headers, and a copy of an ELF fixture with an HTML-like section name for the v0.1 UI escaping test. Their hashes are not in the manifest. In M1 they are passed directly to the adapter and the inspect CLI, not through the import API. From M3, API tests that need them use a test-only configuration with `self_built` enabled, which is allowed because they are test-authored (tier T0). The default and development configuration stays fixtures-only.
- **The manifest is also the v0.1 allowlist.** `MANIFEST.sha256` defines which files `fixtures` mode accepts, so changing fixtures means regenerating it in the same commit.

Practices:

- **Never execute** fixtures in tests. The test suite only reads them. They are harmless anyway, but this keeps the rule simple and enforceable.
- Compilers rarely produce byte-identical output across versions, so **commit the built fixtures plus `MANIFEST.sha256`**, and record compiler versions in `fixtures/BUILD_INFO.txt`. Use `SOURCE_DATE_EPOCH` and `-ffile-prefix-map` to reduce variance.
- Keep fixtures small (< 100 KB each) and under a clear licence (your own code).
- **Default fixtures are compiled from source written for Bytasm.** Their basis is `owned_or_built`.
- A publicly downloadable binary is **not** automatically authorised for analysis. Any external fixture requires checking that its licence or terms permit the intended analysis (and redistribution, if committed), recorded as `terms_reference`. External fixtures are untrusted input, so they can only be used **after gate I1**.
- **Do not** use copyrighted commercial binaries, confidential software, or real malware samples.

### 9.3 Operational signals

Recorded per run and per invocation (DB columns, plus structured JSON logs):

- **v0.1:** parse duration per import, and the outcome of every import attempt in structured logs. Rejected imports persist no DB rows, so their reason lives only in the logs (hash, size, reason code, duration). These measurements feed the review of the provisional limits in §5.4.1.
- Duration (queue wait from v0.2, per step, total) and peak memory where available.
- Final status: succeeded / rejected (v0.1). From v0.2: complete / partial / cancelled / failed. The **failure reason taxonomy** is `timeout`, `nonzero_exit`, `invalid_output`, `resource_limit`, `unsupported_input`, `internal_error`, `busy`.
- Tool name and version, rule-set hash, profile snapshot hash.
- Bytasm version (git SHA), container image digest, host architecture.
- Storage: total blob bytes, raw output bytes, count of samples. Shown on the tools page.
- A small `/api/v1/health` plus a "System" panel. Prometheus/Grafana is unnecessary for the MVP. Structured logs and SQL queries over these tables are enough, and they double as a data-engineering showcase.

---

## 10. Data Science opportunities (without forcing ML)

Where your background adds real value:

1. **Descriptive aggregation across versions.** Track section sizes, import counts, string counts, and finding counts across a sample's versions as tidy time series. Answer "when did this binary start importing networking APIs?"
2. **Honest visualisation.**
   - A section-layout bar (offset → size, coloured by permissions, labelled).
   - Per-section entropy as a strip plot with the threshold shown.
   - An import-by-library treemap or sorted bar chart.
   - A diff summary as a diverging bar chart (added vs removed per category).

   Every chart comes with a table alternative and axis labels.
3. **Careful cross-tool comparison.** When two tools describe the same thing (LIEF vs pefile section tables, or Bytasm's string extractor vs FLOSS static strings), measure agreement (Jaccard similarity of sets, counts of disagreements) on the fixture corpus. Disagreement is a signal to investigate parsing differences, not a "score".
4. **Search over the user's own authorised corpus.** Indexing strings, imports, and rule matches is a data-modelling problem: partitioning, indexes, and trigram vs full-text trade-offs.
5. **Rule-quality measurement on a transparent corpus.** For Bytasm's own YARA rules, keep a labelled fixture set (what *should* and *should not* match). Report precision/recall per rule with the corpus composition published. The numbers describe performance *on that corpus only* and do not generalise.
6. **Provenance as data.** Runs, invocations, and versions form lineage, the same idea as data lineage in DataCheck. A query like "which reports would change if capa-rules were upgraded?" is a lineage query.

**Descriptive vs. verdict.** A count, an entropy value, or a rule match is a *measurement*. "This binary is malicious" or "this binary is safe" is a *claim* that needs context, intent, and usually dynamic evidence. Bytasm reports measurements and matches **as evidence to review**. Detection rules have false positives (legitimate software uses sockets, compression, and anti-debugging) and false negatives (packing hides behaviour, and capa documents this, **verified**). An aggregated "score" hides these failure modes behind one number, which is why the MVP has none.

---

## 11. Portfolio story

**What Bytasm adds to the existing portfolio:**

| Existing | What it shows | What Bytasm adds |
|---|---|---|
| Repair (RAG, Java/Spring, Python, pgvector) | Applied AI, polyglot services | A deliberate decision **not** to use AI where it would undermine trust, plus a roadmap for evidence-grounded use if it's ever justified |
| DataCheck (migration, validation, audit trails) | Data quality, reconciliation, auditability | The same provenance/audit mindset applied to a security domain: lineage from file to tool to finding to report |
| Spacelector (full-stack CRUD) | Product delivery | Async orchestration, untrusted-input handling, and a threat model |
| Applied Data Science (UOC) | Statistics and analysis | Descriptive measurement, careful comparison, rule evaluation on a labelled corpus |
| Le Wagon | Fast full-stack shipping | Engineering discipline: ADRs, tests, CI, SBOM, security policy |
| Expected Data Engineer internship (Zurich) | Production data work | Job orchestration, schema design, reproducibility metadata. These are directly transferable concepts. |

**What a recruiter could see (if built well):** product thinking (explicit non-goals, validated assumptions), full-stack delivery, relational data modelling with provenance, background job orchestration with failure handling, integration of mature third-party tools rather than reinventing them, secure file handling informed by OWASP/NIST, testing and CI, clear documentation, and the judgement to scope a hard domain responsibly.

**Candid credibility check:**

- *Credible:* a small feature set that works end-to-end, a green CI, a threat model whose mitigations are **tested** (escaping tests, timeout tests, hardening flags visible in `compose.yaml`), honest docs about limits, and a 5-minute demo on self-built fixtures.
- *Merely ambitious-looking:* a long feature list, a "risk score", buzzword architecture, claims of malware detection, screenshots of dashboards with fake data, or a security section with no tests behind it.
- Bytasm does not make you a reverse engineer, and the README shouldn't imply it. It shows you can build trustworthy tooling *around* reverse engineering while learning the domain. No project guarantees interviews or offers. This one gives a reviewer concrete things to inspect.

---

## 12. Beginner learning plan (milestones)

Each milestone is small, ships something runnable, and has a simple acceptance criterion. Optional concepts can be skipped at that stage.

| # | Outcome | Concepts to learn | Acceptance criterion | Why before the next | Optional now |
|---|---|---|---|---|---|
| **M0 Foundations** (v0.1) | Git repo, README, licence, `SECURITY.md`, ADR-0001 (FastAPI + Option A + provisional limits), CI running lint on an empty Python package and an empty Vite app, Compose with PostgreSQL | Git hygiene, ADRs (Architecture Decision Records: short documents explaining one decision), CI basics | `git clone && docker compose up db` works, and CI is green | Everything else depends on a reproducible base | Pre-commit hooks |
| **M1 Fixtures + inspect CLI** (v0.1) | Self-built fixtures (PE x86-64, ELF x86-64, high-entropy-section ELF, AArch64 ELF if done within half a day), `MANIFEST.sha256`, `BUILD_INFO.txt`, and a CLI `bytasm inspect <file>` that prints SHA-256, format, arch, sections (+ entropy), imports, exports as JSON (LIEF). LIEF confirmed on `linux/arm64` and `linux/amd64`. | What PE/ELF are, headers, sections, imports, entry points, magic bytes, Shannon entropy, cross-compilation, host vs target architecture | Unit tests assert expected metadata per fixture. Entropy matches an independent implementation. **Parse time and peak memory measured** for fixtures and a synthetic file at the size limit, then the §5.4.1 provisional limits are reviewed. M0–M1 work with **fixtures only**. Passing these acceptance tests is the precondition for ever enabling `self_built` (§3.4). | You must understand the data before modelling it | Relocations, DWARF |
| **M2 Subprocess runner** (v0.1) | Adapter launcher: self-applied rlimits, clean env, own process group, bounded output, timeout → `SIGTERM`/`SIGKILL`, schema validation, exit-code contract | Processes, process groups, signals, rlimits, asyncio subprocesses; robustness vs. isolation | Fake-adapter tests (§9.1 "Subprocess runner") pass. No orphan processes or temp directories. Q3–Q6 in §5.4.1 are answered by test or recorded as limitations. | The robustness core every later tool reuses (not a sandbox) | — |
| **M3 Intake API** (v0.1) | Alembic schema (v0.1 subset, §6), `POST /imports` with guards, metadata header, single parser slot, bounded raw-body streaming, **input policy (fixture-manifest allowlist, `self_built` opt-in)**, duplicate check, runner call, all-or-nothing persistence, startup sweep | Streaming request bodies, hashing while streaming, ASGI disconnects, transactions, migrations, OWASP upload guidance | API tests (§9.1 "Input policy", "Upload validation & lifecycle", "Cross-site request guard") pass. Q1, Q2, Q7, Q8 in §5.4.1 are answered by test or recorded as limitations. | The UI needs stored, parsed samples | Dedupe across projects |
| **M4 UI** (v0.1) | Projects, project detail, import form (input-policy disclosure, `owned_or_built` attestation), sample overview (identity, admitted-under policy, metadata, sections with entropy labelled as a measurement, imports, exports) | React data fetching, routing, accessible forms, generated API clients | Playwright happy path. Input-policy refusal shown. Hostile section name rendered as text. Keyboard-only import possible. | Results must be visible before the report | Dark theme |
| **M5 JSON report → tag v0.1.0** | Report schema (including `admitted_under` and the input-policy limitation), generator, download. README quick start with a "Supported inputs and security limits" section. 2-minute demo. | JSON Schema, deterministic output | The v0.1 release gate (§12.1) passes | Completes the slice | Recorded video |
| **M6 Pattern matching** (v0.2) | Background worker (§5.4.2), strings adapter, YARA-X adapter with 5–8 self-written rules + rule tests, finding/evidence tables, findings UI + evidence drawer, multi-step runs, `partial`, cancel | Job queues, strings and encodings (ASCII vs UTF-16LE), YARA rule syntax, offsets vs virtual addresses | Every finding has evidence whose bytes match the file at the offset (invariant test) | Annotations and comparison need findings | Rule precision measurement |
| **M7 Compare & annotate** (v0.3) | Structural diff v1 vs v2. Annotations with three kinds, revisions, citations. | Set diffs, stable fingerprints, append-only modelling | v1/v2 fixture diff shows exactly the expected changes. A Conclusion can't be saved without citations. | Reports include comparisons and annotations | Diff visualisation charts |
| **M8 Deeper analysis & sharing** (v0.4) | capa adapter (`-j`), limitations surfaced in UI. HTML report + preview. | ATT&CK/MBC, function-level features, auto-escaping templates, CSP | capa runs on fixtures within its timeout. XSS fixture is escaped in HTML. | — | ATT&CK matrix view |
| **Gate I1 Isolated analysis boundary** (after v0.2) | Analyzer container per §5.4.3, file-spool hand-off, boundary tests, threat model, independent review. Then enable the `written_permission` / `public_fixture_terms_permit` bases. | Container isolation and its limits, threat modelling | §5.4.3 exit criteria met | Required before any non-self-authored input | gVisor runtime evaluation |
| **Hardening gates** | Items tagged Public / v0.2 / Non-local in §8.2 | Container security options, supply-chain basics (SSDF) | Each gate's items are in place before that gate is crossed | Must precede the corresponding exposure | Signed artefacts |

### 12.1 v0.1 release gate

This list is authoritative; the earlier copy in `MVP_SCOPE_REVIEW.md` §5.1 is superseded by it.

- [ ] README quick start from a clean machine to the UI in < 15 minutes.
- [ ] README and import screen state:
  - v0.1 accepts self-authored binaries only and is not safe for downloaded, received, third-party, or suspicious files.
  - Bytasm never runs imported files.
  - Resource limits are not a sandbox.
  - Authorisation is a self-attestation, not proof of permission.
- [ ] Default `fixtures` mode accepts every committed fixture with the expected metadata, asserted in tests.
- [ ] Default `fixtures` mode refuses any other file **without spawning the parser**, asserted in tests.
- [ ] `self_built` mode:
  - is off by default;
  - can be enabled only through local server configuration after the M1 acceptance tests pass, with no remote or UI control;
  - is refused on a non-loopback binding;
  - is shown in a banner while enabled;
  - is recorded per sample and in reports.
- [ ] Third-party, downloaded, received, or suspicious binaries remain unsupported, and the README says so. There is no mode that accepts them before gate I1.
- [ ] The interrupted-upload tests (Q1) pass against the pinned Starlette/Uvicorn versions. Only uploads consumed to the ASGI completion signal are accepted.
- [ ] ZIP, empty, oversize, short-body, and generated truncated-header inputs are rejected with clear messages. The API keeps serving.
- [ ] A hanging fake adapter is killed at the timeout. No orphan process or temp directory remains.
- [ ] Q1–Q8 in §5.4.1 are answered by tests or recorded in the README's known-limitations section.
- [ ] A cross-site request without the custom header, or with a foreign `Host`, is refused.
- [ ] The hostile section-name test passes in the UI.
- [ ] The JSON report validates against the schema, includes `admitted_under` and the limitations, and two exports differ only in `generated_at`.
- [ ] The Compose file shows:
  - localhost binding, non-root, no Docker socket, no home mounts
  - `cap_drop: [ALL]`, `no-new-privileges`
  - explicit `mem_limit`/`cpus`/`pids_limit`, `init: true`
- [ ] CI green: lint, types, unit + integration tests, one Playwright test, dependency audit.

---

## 13. Repository structure and project management

### 13.1 Current repository state (re-inspected 2026-10-26, blueprint revision 0.3)

- `~/code/bytasm` is **not a git repository** yet.
- `docs/` contains `PROJECT_BLUEPRINT.md` (this file), `MVP_SCOPE_REVIEW.md` (decision record for revisions 0.2 and 0.3), and `design/references/frontend-ref-{1,2,3}.png`, which exist and are readable (described in §5.10). The images are local-only and git-ignored because redistribution rights have not been confirmed.
- `.claude/` and `docs/.claude/` hold local Claude Code / tooling settings and lock/marker files (hooks, a local API base URL). These are machine-specific. **Recommend adding `.claude/` and `**/.claude/` to `.gitignore`.**
- The `untitled folder/` noted in revision 0.1 **no longer exists**.
- `.DS_Store` files exist in several folders. Add them to `.gitignore`.
- No application code, no README.

### 13.2 Proposed structure (once the stack ADR is accepted)

```
bytasm/
├── README.md
├── LICENSE                      # recommendation: Apache-2.0 (permissive, patent grant, matches Ghidra/LIEF/capa)
├── SECURITY.md
├── CONTRIBUTING.md              # later
├── compose.yaml                 # db, api, web (worker from v0.2); hardening flags visible here
├── Makefile                     # fixtures, test, lint, e2e, sbom
├── .gitignore
├── .github/
│   ├── workflows/ci.yml         # lint, types, tests, e2e, audit, secret scan, SBOM
│   ├── ISSUE_TEMPLATE/
│   └── dependabot.yml
├── backend/
│   ├── pyproject.toml / uv.lock
│   ├── src/bytasm/
│   │   ├── api/                 # FastAPI routers, schemas
│   │   ├── domain/              # entities, services (no framework code)
│   │   ├── db/                  # SQLAlchemy models; migrations/ (Alembic)
│   │   ├── intake/              # streaming upload, input policy, identification, storage (v0.1)
│   │   ├── runner/              # subprocess launcher: rlimits, timeout, cleanup (v0.1)
│   │   ├── adapters/            # metadata_lief (v0.1); strings, yarax (v0.2); capa (v0.4); fake adapters for tests
│   │   ├── jobs/                # background worker, run orchestration (v0.2)
│   │   ├── compare/             # (v0.3)
│   │   └── reports/             # JSON schema (v0.1), Jinja2 templates (v0.4)
│   └── tests/{unit,integration}/
├── frontend/
│   ├── package.json / package-lock.json
│   ├── src/{routes,components,api,styles}/
│   └── tests/
├── e2e/                         # Playwright + axe
├── rules/
│   └── yara/                    # Bytasm's own rules + expected-match tests
├── fixtures/
│   ├── src/*.c
│   ├── build/Dockerfile         # pinned cross-compilers
│   ├── bin/                     # committed small binaries
│   ├── MANIFEST.sha256
│   └── BUILD_INFO.txt
├── schemas/
│   ├── adapter-result.schema.json
│   └── report.schema.json
└── docs/
    ├── PROJECT_BLUEPRINT.md     # this file
    ├── adr/0001-stack.md …
    ├── threat-model.md          # extracted from §8 and kept current
    ├── data-model.md
    └── design/references/       # local-only images, git-ignored (§5.10)
```

### 13.3 Issue labels

`type:feature`, `type:bug`, `type:chore`, `type:docs`, `type:security`, `type:test` · `area:intake`, `area:jobs`, `area:adapters`, `area:findings`, `area:compare`, `area:reports`, `area:ui`, `area:infra` · `priority:p1/p2/p3` · `good-first-learning` (for RE-concept tasks) · `needs-decision` · `blocked`

### 13.4 Initial GitHub milestones

`M0 Foundations` · `M1 Fixtures + inspect CLI` · `M2 Subprocess runner` · `M3 Intake API` · `M4 UI` · `M5 JSON report / v0.1.0` · `M6 v0.2 Pattern matching` · `M7 v0.3 Compare & annotate` · `M8 v0.4 Deeper analysis & sharing` · `Gate I1 Isolated analysis boundary` · `Hardening gates`

### 13.5 First issues for v0.1 (dependency order)

1. **ADR-0001: record accepted decisions.**
   - FastAPI.
   - Self-authored-input scope for v0.1. Fixtures-only through M0–M1. `self_built` is a local-config-only opt-in after the M1 acceptance tests pass. It is a provenance restriction, not a sandbox.
   - Option A for that scope: the API waits for a resource-limited LIEF subprocess, with no queue; this is not a sandbox.
   - Provisional limits (64 MiB, 30 s, 1 GiB, 1 concurrent parser).
   - Worker triggers, and gate I1 as the condition for wider inputs.
2. **Repo bootstrap**: `git init`, `.gitignore` (incl. `.DS_Store`, `.claude/`), LICENSE, README skeleton with a "Supported inputs and security limits" section (self-authored only, no execution, limits ≠ sandbox, self-attestation ≠ authorisation), `SECURITY.md`, CI with ruff + eslint on empty packages.
3. **Fixture build pipeline**: C sources, pinned cross-compiler Dockerfile, MANIFEST, BUILD_INFO. AArch64 ELF time-boxed to half a day.
4. **Verify LIEF on `linux/arm64` and `linux/amd64`** in a container.
5. **`bytasm inspect` CLI** with LIEF: hash, format, arch, sections + entropy, imports, exports (JSON) + unit tests + entropy cross-check.
6. **Measure parse time and peak memory**, and review the provisional limits.
7. **Subprocess runner + adapter contract + fake-adapter tests.**
8. **Compose: PostgreSQL + API skeleton + health endpoint**, with Alembic baseline migration, `init: true`, and the v0.1 container settings from §8.2.
9. **Schema (v0.1 subset)**: project, sample, sample_version (with `admitted_under`), authorization_record, analysis_run, tool_invocation, section, symbol, report.
10. **Import endpoint** per the §5.4.1 lifecycle: guards, metadata header, parser slot, bounded raw-body streaming, **input policy before parsing**, duplicate check, all-or-nothing persistence, startup sweep, plus tests answering Q1, Q2, Q7, and Q8.
11. **Frontend**: projects, project detail, import form with the input-policy disclosure, sample overview, generated API client, lint ban on `dangerouslySetInnerHTML`.
12. **JSON report**: schema (with `admitted_under` and limitations), generator, download endpoint with blob hash re-verification, determinism test.
13. **README quick start, known limitations (Q1–Q8 outcomes), 2-minute demo → tag v0.1.0** once §12.1 passes.

(v0.2 issues, starting with the worker and the yara-x `linux/arm64` check, are written after v0.1 ships.)

### 13.6 Definition of Done

A change is done when:

- It meets the issue's acceptance criterion and is demonstrable locally.
- Tests cover the behaviour, including at least one failure path, and CI is green.
- Untrusted data paths are escaped or validated, and no new raw-HTML rendering was added.
- Docs are updated (README, ADR, or blueprint section) if behaviour or decisions changed.
- Accessibility: keyboard reachable, labelled, and passes the axe check for UI changes.
- No secrets, sample bytes, or extracted strings are logged.

### 13.7 README sections

1. What Bytasm is (and isn't), in three sentences, with a screenshot.
2. Supported inputs and security limits:
   - v0.1 accepts self-authored binaries only: fixtures-only through M0–M1, then an optional local-config `self_built` mode (a provenance restriction, not a sandbox).
   - It is not safe for downloaded, received, third-party, or suspicious files.
   - Imported files are never executed.
   - Resource limits are not a sandbox.
   - Gate I1 is required for wider inputs.
3. Responsible use and authorisation: self-attestation is not proof of permission.
4. Quick start (`docker compose up`, open localhost, import a fixture).
5. Features in v0.1, and known limitations (including the outcomes of Q1–Q8, §5.4.1).
6. How it works (architecture diagram, adapter contract).
7. Security model (summary + link to threat model). No sample execution.
8. Supported formats and tools, with versions and licences.
9. Reproducibility: what a report contains and how to re-run.
10. Development: tests, fixtures, CI.
11. Roadmap (with "possible, not promised").
12. Acknowledgements and third-party licences.

### 13.8 Demo scripts

**v0.1 (2 minutes):**

1. `docker compose up`, open localhost, create project "Demo".
2. Import the fixture `hello_v1.exe`. Point out:
   - the input-policy disclosure: "self-authored only, not for downloaded or suspicious files; Bytasm never runs them"
   - the `owned_or_built` basis and its "self-attestation, not proof of permission" notice
   
   Show SHA-256, format, and architecture.
3. Try a file that is not in the fixture manifest and show the refusal: "not parsed or stored". Then try a renamed ZIP fixture copy and show the content rejection.
4. Sample overview: admitted-under policy, sections with entropy (point out the "measurement" label), imports.
5. Export the JSON report and show the generator version, LIEF version, the self-attestation block, `admitted_under`, and the limitations.
6. Show the CI badge and the input-policy, upload-rejection, and timeout tests. Say plainly: "The subprocess limits handle parser bugs. They are not a sandbox. That's why v0.1 only parses self-authored files, and accepting other files needs an isolation gate."

**v0.4 target (5 minutes, still on self-authored fixtures unless gate I1 has passed):**

| Time | Action | What to say |
|---|---|---|
| 0:00–0:30 | Show README top + architecture diagram | "Bytasm is a local-first workbench for documenting static binary analysis. It never runs the file. It integrates existing tools and keeps provenance." |
| 0:30–1:15 | Create project. Import `hello_v1.exe` with authorisation "I built this". Show hash and format. Try a renamed `.zip` and show the rejection. | "Identification is by content, not extension. Files are stored by hash, read-only, outside the web root." |
| 1:15–2:15 | Run default profile. Show steps progressing, then sample overview (sections, imports). | "Each tool runs as a resource-limited subprocess with a timeout. That handles tool bugs; it is not a sandbox, so inputs are still self-authored until the isolation gate. Every step records tool version and raw output." |
| 2:15–3:00 | Findings: open a YARA-X match and show offset + hex excerpt + rule. Open a capa finding with its address and the limitations note. | "Findings are observations with evidence, not verdicts." |
| 3:00–3:30 | Add a Conclusion citing two findings, with confidence "likely". | "Human conclusions are visually and structurally separate, and must cite evidence." |
| 3:30–4:15 | Import `hello_v2.exe`, run, open Compare: "+ `getenv` import, + new string". | "Version comparison is set-based on stable fingerprints, and it warns if tool versions differ." |
| 4:15–4:45 | Export the HTML report and open it offline. Point at tool versions, rule hashes, partial-status section. | "Someone else can see exactly what ran and re-run it." |
| 4:45–5:00 | Show CI badge, the threat-model doc, and the escaping test | "Security claims are backed by tests." |

---

## 14. Research sources and verification status

Research was performed on **2026-10-26** using web fetches of primary sources. "Verified" claims in this document trace to the entries below. Versions change frequently, so re-check them when implementing.

### 14.1 Sources consulted

| Source | URL | What it supports |
|---|---|---|
| Ghidra repository | https://github.com/NationalSecurityAgency/ghidra | Apache-2.0 licence. JDK 25 64-bit required. PyGhidra launcher. "user-interactive and automated modes". |
| Ghidra releases | https://github.com/NationalSecurityAgency/ghidra/releases | Ghidra 12.2 listed as latest (22 Oct, year inferred as 2026 from page footer). Prior 12.1.x releases. |
| Ghidra `analyzeHeadless` README (mirror of the file shipped in `support/` of the Ghidra distribution) | https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html | `-import`, `-noanalysis`, `-postScript`, `-scriptPath`, `-readOnly`, `-deleteProject`, `-analysisTimeoutPerFile`, `-max-cpu`, `-log`, `-scriptlog` semantics. **Note:** a third-party mirror. Confirm against `support/analyzeHeadlessREADME.html` in your Ghidra install. |
| PyGhidra on PyPI | https://pypi.org/project/pyghidra/ | v3.2.0 (Oct 22 2026). `start()`, `open_project`, `program_loader`, `analyze` with timeout, `ghidra_script`. Requires Ghidra ≥ 12.0, Python ≥ 3.9. Apache-2.0. |
| capa repository / README | https://github.com/mandiant/capa | Capability detection. Inputs: PE, ELF, .NET, shellcode, sandbox reports (CAPE, DRAKVUF, VMRay). ATT&CK/MBC mapping. Ghidra backend via PyGhidra. Standalone binaries. Apache-2.0. |
| capa usage | https://github.com/mandiant/capa/blob/master/doc/usage.md | `-j` JSON output, `-v`/`-vv`, `-t`, `--restrict-to-functions`. Backend-selection flags were **not** documented there; check `capa -h`. |
| capa limitations | https://github.com/mandiant/capa/blob/master/doc/limitations.md | Packed files, installers, wrapper functions, and loop scope give misleading or incomplete results. |
| LIEF docs | https://lief.re/doc/latest/index.html | Parses ELF, PE, Mach-O, COFF, OAT, DEX, VDEX, ART. Python/C++/Rust APIs. |
| LIEF repository | https://github.com/lief-project/LIEF | Apache-2.0. `pip install lief`. Latest tagged release v1.0.0 at time of research (docs labelled 2.0.0 dev). |
| YARA-X repository | https://github.com/VirusTotal/yara-x | Rust rewrite of YARA, BSD-3-Clause. Legacy YARA effectively in maintenance mode. |
| YARA-X Python API | https://virustotal.github.io/yara-x/docs/api/python/ | `pip install yara-x`. `Scanner.set_timeout()`. Match `offset`/`length`. |
| YARA-X `math` module | https://virustotal.github.io/yara-x/docs/modules/math/ | `entropy(offset, size)` returns 0.0–8.0 for `size` bytes from a file offset. Out-of-range behaviour not documented. |
| YARA-X `pe` module | https://virustotal.github.io/yara-x/docs/modules/pe/ | `Section` fields include `name`, `raw_data_offset`, `raw_data_size`. No per-section entropy field. |
| YARA-X `elf` module | https://virustotal.github.io/yara-x/docs/modules/elf/ | `Section` fields `name`, `offset`, `size`, `type`, `flags`, `address`. `for any section in elf.sections` example. No entropy field. |
| Python `subprocess` | https://docs.python.org/3/library/subprocess.html | `preexec_fn` "NOT SAFE to use in the presence of threads". `start_new_session`. `process_group` (3.11+). `close_fds=True` default. |
| Python `resource` | https://docs.python.org/3/library/resource.html | `RLIMIT_AS`, `RLIMIT_CPU` (SIGXCPU), `RLIMIT_FSIZE`, `RLIMIT_NPROC`. A process may lower its own limits. |
| Python `subprocess` (timeouts) | https://docs.python.org/3/library/subprocess.html | `Popen.communicate(timeout)`: "The child process is not killed if the timeout expires". `run(timeout)` kills and waits for the child. `env` replaces the inherited environment. Silent on grandchildren. |
| Python asyncio subprocesses | https://docs.python.org/3/library/asyncio-subprocess.html | `communicate()`/`wait()` have no timeout parameter, so use `wait_for()`. `wait()` can deadlock with `PIPE`. `kill()` sends `SIGKILL` to the child. Silent on whether `wait_for` timeout kills the child. |
| Python asyncio event loop | https://docs.python.org/3/library/asyncio-eventloop.html | `loop.subprocess_exec` passes other keyword arguments to `subprocess.Popen` (except a listed few) |
| Starlette requests | https://starlette.dev/requests/ | `request.stream()` yields chunks "without storing the entire body to memory". `is_disconnected()`. `form()` spools uploaded files; `max_part_size` does not limit files; `max_body_size` / `RequestBodyLimitMiddleware` mentioned. `ClientDisconnect` not documented on this page. |
| FastAPI: using the Request directly | https://fastapi.tiangolo.com/advanced/using-request-directly/ | Bodies read from `Request` are not validated or documented by FastAPI |
| FastAPI: request files | https://fastapi.tiangolo.com/tutorial/request-files/ | `UploadFile` is a `SpooledTemporaryFile`. `bytes` parameters hold the whole file in memory. |
| ASGI HTTP spec | https://asgi.readthedocs.io/en/latest/specs/www.html | `http.disconnect` is delivered via `receive`. The server is not required to cancel the app. `send` may raise `OSError` on a closed connection (2.4+, "not guaranteed"). |
| Uvicorn server behaviour | https://uvicorn.dev/server-behavior/ | Pauses reading at a high-water mark, resumes on `receive`. After the response, `receive` returns `http.disconnect`. Silent on cancelling the app task. |
| Docker resource constraints | https://docs.docker.com/engine/containers/resource_constraints/ | "No resource constraints" by default. `--memory` hard limit and OOM kill. `--cpus`. Kernel-feature caveats. |
| Docker `none` network driver | https://docs.docker.com/engine/network/drivers/none/ | `--network none`: "only the loopback device is created" |
| Compose networks | https://docs.docker.com/reference/compose-file/networks/ | `internal: true` creates an "externally isolated network" (other services on it remain reachable) |
| Compose services | https://docs.docker.com/reference/compose-file/services/ | `network_mode: none` "Turns off all container networking". `pids_limit`, `mem_limit`, `cpus`, `read_only`, `cap_drop`, `init` (reaps processes), `user` (defaults to root if unset). |
| Docker seccomp | https://docs.docker.com/engine/security/seccomp/ | Default profile is an allowlist, applied by default, blocking "around 44 system calls out of 300+". "Moderately protective." |
| Docker Desktop container security FAQ | https://docs.docker.com/security/faqs/containers/ | Docker Desktop runs containers inside a customised Linux VM, isolating containers from the host |
| pefile | https://github.com/erocarrera/pefile | MIT. PE parsing. Warnings for malformed values. |
| pyelftools | https://github.com/eliben/pyelftools | Public domain. Pure Python ELF/DWARF parsing. Python ≥ 3.11. |
| FLOSS | https://github.com/mandiant/flare-floss | Apache-2.0. Static/stack/tight/decoded strings. `-j` JSON. PE-oriented documentation (ELF support not confirmed). |
| ghidriff | https://github.com/clearbluejar/ghidriff | GPL-3.0. Ghidra-based function diffing (Version Tracking correlators, BSim). JSON/Markdown output. Targets Ghidra 12.0.4 + pyghidra 3.x. |
| MITRE MBC | https://github.com/mbcproject/mbc-markdown | Malware Behavior Catalog v3.1, relationship to ATT&CK, used by capa. Licence terms in its `tou.md` (not reviewed). |
| SARIF 2.1.0 (OASIS) | https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html | Standard output format for static analysis tools, including object code. Binary regions (`byteOffset`/`byteLength`), `address` object, tool driver name/version, invocations, artefact hashes, property bags. |
| OWASP File Upload Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | Extension allowlist, Content-Type untrusted, signature checks not sufficient alone, generated filenames, size limits, storage outside webroot, ZIP caution, CSRF. |
| OWASP XSS Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html | Context-aware encoding, framework escape hatches, DOMPurify, CSP as defence in depth. |
| OWASP Docker Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html | Don't expose the Docker socket, run as non-root, drop capabilities, no-new-privileges, resource limits, read-only filesystem, port-mapping vs UFW. |
| Docker Engine security | https://docs.docker.com/engine/security/ | Daemon control = host control. Capabilities allowlist may give incomplete isolation. User namespaces not on by default. |
| NIST SP 800-218 (SSDF v1.1) | https://csrc.nist.gov/pubs/sp/800/218/final | SSDF v1.1, Feb 2022. |
| NIST SSDF project page | https://csrc.nist.gov/projects/ssdf | Practice groups PO, PS, PW, RV. SP 800-218A (AI profile). No Rev. 1 shown at time of research. |
| SLSA | https://slsa.dev/spec/v1.0/levels | Build levels L0–L3 and provenance. v1.0 marked retired. v1.2 is current (read the current version when implementing). |
| gVisor docs | https://gvisor.dev/docs/ | Application kernel, `runsc`. Aims to *minimise* escape risk. Compatibility/performance trade-offs. |
| Firecracker | https://firecracker-microvm.github.io/ | KVM-based microVMs, minimal device model, jailer. Linux hosts only. |
| Procrastinate | https://procrastinate.readthedocs.io/en/stable/ | PostgreSQL-only task queue (PG 13+, Python 3.10+, MIT). Retries, cancellation, locks, periodic tasks, async, Django integration. |
| Syft | https://github.com/anchore/syft | SBOM generation (CycloneDX, SPDX). Apache-2.0. |
| GitHub: security policy | https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository | `SECURITY.md` with supported versions and reporting instructions. |
| GitHub: private vulnerability reporting | https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository | Available for public repositories. How to enable. |

### 14.2 Does SARIF fit?

**Partially, for tool findings only. It should not be the canonical format.**

- *Fits:* SARIF is explicitly for static-analysis results and covers object code, binary byte regions, addresses, rule metadata, tool versions, invocations, and artefact hashes (**verified**). YARA-X matches and capa capabilities map naturally to `result` + `reportingDescriptor` + `physicalLocation`.
- *Doesn't fit well:* analyst annotations with kinds, revisions, and citations; authorisation records; structural diffs between two artefacts; per-step partial status as a first-class concept. These could go into property bags, but consumers would ignore them.
- **Recommendation:** keep Bytasm's own versioned JSON schema as the canonical report and add an optional SARIF export of tool findings (v0.7) when there is a consumer for it. STIX and similar threat-intelligence formats target intelligence sharing, not analysis provenance, and are not recommended for the MVP. **Assumption**, not researched in depth.

### 14.3 Not verified in this session (check before relying on them)

- **Option A implementation questions Q1–Q8 (§5.4.1).** The docs do not establish these, so they are tested in M2/M3:
  - Q1: interrupted-upload behaviour of `request.stream()` with the pinned Starlette/Uvicorn versions, and reliable detection of the ASGI completion signal. **Not verified until the interrupted-upload test exists.**
  - Q2: whether uvicorn cancels handlers
  - Q3: cancellation-safe cleanup
  - Q4: `killpg` survivors
  - Q5: rlimit enforcement in the container vs. macOS
  - Q6: `/proc/<pid>/environ` and `PR_SET_DUMPABLE`
  - Q7: `form()` buffering and `RequestBodyLimitMiddleware`
  - Q8: CORS preflight blocking
- `RLIMIT_NPROC` per-user accounting on Linux (not used; `pids_limit` instead).
- **Gate I1 design (§5.4.3)** has not been prototyped. It must be re-checked against current Docker documentation and tested, including gVisor compatibility if used. Docker's documentation describes isolation mechanisms but does **not** state that containers are a sufficient boundary for hostile code, and Bytasm must not claim it.
- Actual LIEF parse time and peak memory at the 64 MiB limit (M1). The current limits are provisional.
- Exact capa CLI flag for selecting backends, and capa's current release number. Run `capa -h` in the pinned image (v0.4).
- Availability of `linux/arm64` wheels or binaries: LIEF (M1), yara-x (v0.2), capa (v0.4).
- Whether FLOSS supports ELF.
- Current exact versions of FastAPI, SQLAlchemy, React, Vite, TanStack, React Aria, Playwright, axe-core, Jinja2 behaviour details. These are recommended from general knowledge, so pin versions at implementation time.
- WCAG 2.2 success-criteria details (https://www.w3.org/TR/WCAG22/). Cited as the target standard but not re-read in this session.
- RFC 9457 (problem details) and RFC 6901 (JSON Pointer). Cited from general knowledge.
- MITRE MBC licence terms (`tou.md`), and ATT&CK terms of use if ATT&CK IDs are displayed.
- Any legal conclusions: reverse-engineering legality, EULA terms, data protection, export controls. **⚠ Needs specialist legal review.**
- Market demand for Bytasm. **No data was gathered.** See the assumptions in §1.6.
