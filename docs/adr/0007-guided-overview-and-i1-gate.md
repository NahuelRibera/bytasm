# ADR-0007: Guided stored-evidence overview; I1 remains closed

Status: implemented presentation decision, 2026-10-31. I1 design below is a
proposal, not an approved or implemented isolation boundary.

## Decision

Extend the existing React/CSS system with a reading layer on a sample version:
file type/header declarations → actual selected run/check states → observations
→ unknowns → next actions → existing exact evidence and function workbench.
Use existing GET contracts only. No parser, migration, new dependency, tool
installation, sample execution, remote service or schema version is added.

With `run_id`, fetch that exact run and require version ID, hash and size to
match. A missing or mismatched run yields an explicit unavailable state, without
falling back. Without `run_id`, show the newest recorded analysis run (existing
API order: queued time descending, ID descending). Never substitute an older
successful run for a failed, active or cancelled latest run. Selected-function
jobs remain separate and reachable through their run pages.

Labels describe completion only, not concern, severity or maliciousness.
Succeeded means checks completed within recorded limits, not full coverage.
Counts appear only for completed rule checks; string caps remain explicit.
Ghidra jobs direct the reader to inventory/detail bounds in their exact run.
Unknown publisher/authenticity and execution behavior remain explicit. No
combined threat label is justified by the current small reviewed rule set.

Reports deliberately keep their independent historical selection contract.
The overview explains that report scope may differ; preview is required for
understanding which run a report contains. Do not rewrite historical snapshots.

## I1 decision and rejected shortcut

Do not add an `untrusted` setting or upload exception. A hash allowlist plus a
user assertion cannot establish containment. Docker resource limits and offline
worker configuration cannot close these observed gaps:

- the API receives and performs basic header checks and launches LIEF under its
  own identity; its import child can access application storage and network;
- parser workers share writable SQLite/blob/output/report storage with control;
- process-group cancellation cannot guarantee killing `setsid` descendants;
- no tested quarantine/validated-output transfer separates compromised parsers
  from trusted persistent state;
- no independent containment and disk-exhaustion campaign has passed.

A future Linux deployment should first prototype a disposable per-job VM with
no host folder/socket/credential mounts and a separate trusted broker. A constrained
container may be evaluated only with an explicit same-kernel threat model and
independent review; this repository's Compose layout is not that design.
The broker should stream bounded bytes into quarantine, compute identity without
file-format parsing, transfer exact read-only inputs, start a fixed trusted
profile, collect only bounded typed output, independently validate hashes and
evidence, and publish transactionally. Parser state/projects/caches are disposable.
No parser may hold trusted database/report-store credentials or write access.

The complete runtime acceptance checklist and current threat-path review are in
[the I1 gate](../security/i1-acceptance.md). Until every requirement is proven
on a named platform/deployment, all external input remains refused. On deployment
health failure there must be no native fallback. Archives/dynamic execution are
separate future reviews, not additions to this increment.
