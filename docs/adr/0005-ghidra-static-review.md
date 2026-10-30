# ADR-0005: bounded optional Ghidra static review

- Status: implementation decision under owner review, 2026-10-30.
- Authority: the owner's explicit request for a functioning Ghidra milestone.
- Supersedes the diagnostic-only release boundary of proposed ADR-0004 for this
  implementation. The historical blueprint and ADRs remain unchanged.

## Scope change

The earlier release scope deferred Ghidra. This milestone adds a real optional
caller-installed Ghidra Headless provider without adding AI, agents, MCP, GUI
automation or dynamic analysis. Application startup never downloads software.
Official 12.2 installation documentation requires a 64-bit JDK 25. The reviewed
profile pins that pairing, its fixed script digest and options digest.

## Admission decision: option B

Preserve fixture-manifest admission and the existing native Linux self_built
opt-in. Do not admit arbitrary authorized third-party files. The existing import
parser and shared writable worker/database volume do not satisfy isolation gate
I1. Resource controls and a network-disabled container do not contain every
parser exploit. Broader intake requires a separately reviewed parser boundary,
filesystem/credential separation, host-specific containment, and verified import
isolation before the current admission policy can change.

## Execution and ownership

Only explicitly configured installation paths select executable code. Ghidra
receives the sample solely as an import argument. Fixed self-authored Java scripts
extract data using supported Headless/programmatic APIs. Samples never select
scripts, plugins, commands, environment variables, names or output paths.

A harmless health script creates an empty program in memory and checks Headless
and native decompiler startup. It imports no sample. Metadata alone never sets
available. Health success and analysis-enabled are separate: analysis requires a
non-root offline Linux worker with bounded cgroup memory, CPU and process limits,
and bounded tmpfs workspaces. Native macOS/Windows analysis is unavailable.
The API reads only a bounded status document from a worker with a recent
heartbeat; the worker independently rechecks controls and admission for each run.

Private disposable projects, preferences, cache and logs live inside a per-step
workspace. The supervisor uses argument arrays, a minimal environment, closed
inherited descriptors, process groups, deadlines and bounded pipe readers.
The shared application volume and same-UID processes remain trusted local
application state. These controls are not a complete sandbox.

## Evidence and compatibility

One versioned ghidra-static profile inventories at most 256 functions and records
details for the first 16, in Ghidra's address order. This is a reproducible bounded
review, not interactive arbitrary function selection or a deep review profile.
Exact address-space/text pairs are retained. Body size means Ghidra body address
count, not a contiguous range, file offset or source-code size. Direct static
calls cover only the emitted instruction window. Missing pseudocode remains
unavailable; it never becomes an empty original-source claim.

Typed bounded documents are stored transactionally as content-addressed
ToolInvocation outputs. Existing tables already support these records. Migration
0007 changes no existing columns/data and rejects downgrade while Ghidra runs
exist. Historical report schemas 2/3/4 and their stored downloads remain intact.
Ghidra exports use a separate ghidra-report-1 contract; old report and comparison
selection exclude Ghidra-only runs so they cannot shadow baseline analysis.

Plain-language explanations use deterministic counts, statuses and reviewed
limitations. No behavioral hypothesis is inferred from function names. Analyst
notes remain explicitly authored, through the existing annotation workflow;
function-level annotation citations and Ghidra comparisons are deferred.

## Distribution

No Ghidra or JDK distribution is bundled. Temporary official verified tools may
be mounted read-only for local verification. The release has a top-level Apache
license and component-specific licenses, including separately licensed GPL
support programs; the top-level license does not clear every component. The
existing ida-settings license ambiguity remains a redistribution blocker.

## Bounded follow-ups

User-selected functions; non-call references and enriched imports/exports/data;
Ghidra version comparisons with documented match semantics; richer evidence
annotations; exact section-function maps; independently reviewed arbitrary-file
intake; additional tested hosts and deployment packaging audits. None is exposed
as a nonfunctional control.
