# ADR-0006: immutable selected-function inspection jobs

- Status: implementation decision under owner review, 2026-10-30.
- Scope: next product increment requested after merged v0.5; preserves ADR-0005's
  admission, offline worker and caller-installed Ghidra boundary.

## Decision

Keep SQLite and the existing run claim loop. A selected inspection is another
immutable ghidra-static run, with source run/output identity and one to eight
exact selected address-space pairs pinned in the options digest. It uses a fresh
private Headless project rather than retaining reusable parser-controlled
Ghidra databases. This repeats bounded import/analysis only on explicit request;
search and stored-evidence reads never launch a parser. The cost is up to the
existing three-minute wall deadline per new selection. Failed/cancelled requests
can be retried; exact active/succeeded requests reuse their run in the same
project/version/source/output/profile/script scope.

Increase initial inventory retention from 256 to 1024, with no increase to
2 MiB output, 768 MiB heap, 60-second analysis or 180-second parent deadlines.
Whole-program decompilation is not exposed. Default details remain first 16;
selected runs detail at most eight entries. ghidra-2 carries the new inventory
bound; historical ghidra-1 records retain their 256-entry validation. Current
provider output must use ghidra-2. Old queued scripts fail identity checking;
old stored output remains readable and exportable. Incompatible source selection
requests require a new current-profile run; they never silently mix identities.

Discovery order is deterministic lexicographic address-space/address text;
original stored indices remain evidence identities. Cursors bind the immutable
scope, filters and page size with a checksum. They are not authentication or a
secret signature. Every read independently verifies bounded stored bytes and
provenance. Page size is 1..100 with 512 KiB response cap.

One-hop relationships use only retained direct-call records. Source call-sites
and evidence pointers remain exact. Targets resolve only by exact inventory
entry plus address space; interior and unretained targets remain unresolved.
Incoming tables are incomplete when other functions have no retained details.
The accessible table provides keyboard expansion and provenance for every edge;
the diagram draws at most eight edges. API bounds are 33 nodes and 64 edges.

New analysis exports use a separate bytasm-ghidra-report-2 contract with selected
source provenance. No existing report schema 2/3/4, stored report bytes, annotation
revision or baseline comparison selection is modified. No migration is required:
existing immutable snapshots and content-addressed invocation outputs contain the
new records. Exports remain JSON-derived, escaped, inert and bounded at 16 MiB.

## Rejected alternatives and follow-up

Keeping writable Ghidra projects for reuse introduces parser-owned persistent
state and invalidation/cleanup risks not justified by current isolation. Running
analysis per search keystroke is wasteful and obscures the authorization boundary.
Adding function notes through synthetic rule findings would misrepresent tool
observations; a proper revisioned function-target model remains a later slice.

I1 remains blocked on separated quarantine/parser/state transfer, storage and
credential isolation, ownership/deletion/restore semantics, resource exhaustion
campaigns and platform containment review. Existing fixture/self_built admission
stays unchanged. Container/resource controls are not a complete sandbox. No AI,
dynamic analysis, editable scripts or new tool distribution is introduced.

## Verified deployment correction

A separate tmpfs scratch mount means atomic rename cannot directly publish into
the persistent store (EXDEV). For verified output bytes only, use destination-local
private staging, flush and atomic rename, with ordinary/failure cleanup and the
existing age-based startup recovery for reserved staging names. Do not copy
Ghidra projects or use this reliability fix as an I1 intake boundary. The opt-in
real browser lane uses separate API/worker containers and filesystems to exercise
this configuration rather than substituting provider output.
