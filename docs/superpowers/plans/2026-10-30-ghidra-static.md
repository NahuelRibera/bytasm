# Ghidra static analysis implementation plan

**Goal:** Replace metadata-only diagnostics with a real optional Headless provider and a bounded fixture-only review workflow.
**Architecture:** Preserve SQLite claim-loop jobs and existing report schemas. Add a versioned bounded Ghidra document stored as an invocation output, scoped read APIs and a separate canonical Ghidra export. Preserve original decisions; record scope change in ADR-0005.
**Spec:** Owner's complete Ghidra milestone request, 2026-10-30.

## Constraints and decisions

No Git mutations, no broader admission, no sample execution, no network containing sample data, no AI, no bundled Ghidra. Existing clean main checkout is the explicitly requested review location. Native macOS arbitrary intake remains blocked. Real provider must fail closed when offline/resource controls cannot be established. Official 12.2 documentation requires JDK25. Temporary verified official tool installations for testing are authorized by the request.

## Tasks

- [x] Provider: typed bounded function/address/instruction/reference protocol; fixed Java Headless scripts; bounded subprocess supervisor, real no-sample self-check, private workspace/preferences and offline gating. Tests for protocol and failure modes; real fixture test when tool available.
- [x] Backend: reviewed versioned ghidra-static profile; existing transactional worker lifecycle; invocation output persistence; scoped paginated inventory/detail APIs; deterministic summary; canonical independent JSON/escaped CSP HTML export, preserving historical schemas.
- [x] Frontend: available/unavailable provider semantics; one real run action; searchable paginated inventory, function pseudocode/assembly/static calls, text-equivalent coverage and evidence summaries. Only implemented controls.
- [x] Verify: focused then full repository checks, real offline fixture analysis if installation succeeds, report preservation and documentation acceptance matrix.

## Review focus

Hostile tool text must stay bounded and escaped. A successful process with missing/invalid/truncated protocol must not become an empty success. Address spaces must remain explicit, never converted to offsets. Cancellation must discard current-step output. Worker and API configuration may differ; worker must independently recheck provider and input policy.

## Status ledger

Initial inspection: clean main at fb10a48, no merge state or user changes observed. Existing Ghidra diagnostics never launch tools. Docker Linux ARM64 available; native host Darwin ARM64, installed JDK21 only. Preserve fixtures/self_built boundary (option B). No Ghidra evidence exists yet.

Final ledger: real health + three fixture formats/architectures verified; four opt-in real-provider tests passed, including actual worker/API export and cancellation/deadline cleanup. Native check passed (667 backend,75 frontend), Linux ARM64 full suite passed (669), browser E2E17 passed, demo12 steps, audit/fixture/schema checks passed. Independent review fixes landed and re-reviewed. Optional exact installation-mount checker mode32 focused tests passed. Full acceptance/deferred boundaries and exact commands are in docs/milestones/v0.5-ghidra-static-review.md. No Git mutations.
