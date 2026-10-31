# Static investigation workbench implementation plan

Goal: implement evidence-backed investigation slices against PR #11, preserving admission and historical contracts.
Architecture: immutable review documents in a dedicated additive table; exact version/tool source selection on the server; snapshot-derived UI and privacy exports. Existing run and report paths retain their contracts.
No staging, commits, branch changes, remote mutation, or sample execution.

- [x] Verify baseline: HEAD 40162f4725aa74e2ba6ea982cea534d716339720; existing untracked docs/design preserved.
- [x] A: failing integration cases for selection, latest attempts, exact scope, refresh, corruption and bounds; implement typed persisted snapshots and bounded APIs.
- [x] B: reviewed titles, conditions, alternatives, next steps and deterministic relevance; verify unknown provenance stays generic.
- [x] L/M: snapshot-only export preview and actual byte minimization, standalone escaped HTML, derivative digests, historical preservation.
- [x] E subset: bounded exact-offset bytes API and accessible viewer; verify windows against admitted stored bytes.
- [x] J: inspect local runtime and implement a real disposable metadata boundary where supported; never infer I1 completion from configuration.
- [x] F subset: immutable function overlays, exact citations, stale-save conflict and explicit snapshot/export inclusion.
- [x] Validate applicable backend/frontend/browser checks; inspect final diff and reconcile acceptance matrix with actual results.

Acceptance matrix must be maintained in docs/milestones/v0.8-investigation-workbench.md. A-N constitute a much larger program than any single slice; partial delivery must remain explicit. Do not mark unverified items passed.

Execution record: shipped slices are described by the acceptance matrix, not a claim that every A–N requirement passed. Verification: backend 729 passed / 23 skipped, frontend 97 passed, browser 19 passed; subsequent final scope changes passed 17 focused backend cases, 97 frontend cases, 2 affected browser journeys and current lint/types. Real reduced-image boundary campaign: 12 passed. No code commits or Git operations were performed beyond read-only inspection.

Publication follow-up: the owner's subsequent explicit request authorizes
branching, staging, committing, pushing, PR creation and merge. The initial
Git restriction above describes implementation only. Publish the implemented
slices with their acceptance limits, leaving user-owned docs/design assets out.
