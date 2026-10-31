# I1: external-input admission remains blocked

Reviewed against checkout `34641f9716d68851e30e9802dbc936f326841a13` on
2026-10-31. No I1 runtime claim is made. Current modes remain manifest fixtures
(default) and explicit native Linux self_built (an assertion, not proof of origin
or safety). macOS is fixtures-only; Windows operation is not established.
See [ADR-0007](../adr/0007-guided-overview-and-i1-gate.md).

## Current sample path and residual threats

| Path | Existing control / evidence | Remaining boundary failure |
|---|---|---|
| Request → upload | loopback/Host/Origin/custom-header guards; streamed 64 MiB cap and hash; fixture policy before LIEF | API still receives attacker bytes and reads early signatures; no isolated quarantine service; no accounts |
| Format / metadata | basic identification after admission; bounded LIEF child with hash check | API control plane has file-format logic; child shares identity and storage/network access |
| Queue / cancellation | SQLite transactions, one worker lock, heartbeat, cancel/commit races and restart recovery tests | worker owns writable trusted state; process groups cannot kill every escaped descendant |
| Strings / YARA-X / capa | fixed profiles/rules, bounded children, schema and exact byte checks | native processes retain filesystem/network access; offline Compose still shares data volume/kernel |
| Ghidra | real no-sample health required; offline non-root Linux checks; fresh private projects/cache; strict 2 MiB protocol, 180 s parent wall bound | no independent exploit containment proof; same trusted-store access; detached descendant escape remains possible |
| Input / scratch / results | content hashes, private scratch, read-only input, validated result envelope; destination-local staging/rename for EXDEV | read-only mode bits do not contain same-UID exploit; shared storage can be altered; aggregate disk exhaustion not contained per job |
| HTML / browser / downloads | React escaping; canonical validated snapshots; escaped inert HTML with CSP; explicit raw downloads | browser/host are trusted; evidence can disclose private strings/pseudocode/notes; hidden UI text remains stored |
| Shutdown / restart | interrupted runs reconciled; age-based reserved staging/temp cleanup | no guarantee against compromised parser state or all power-loss/exhaustion cases; existing data retained |
| Retention / deletion | stopping keeps local data; existing age-based orphan cleanup | no user-facing complete per-sample deletion with notes/reports; no hostile-state backup/restore design |
| Archives / installers | no recursive archive feature | disabled; no decompression, nested execution or package install allowed |

Sources: `api/imports.py`, `intake/upload.py`, `intake/identify.py`,
`intake/policy.py`, `runner/{supervisor,limits,workspace,hardening}.py`,
`jobs/{pipeline,worker,runs,ghidra_step}.py`, `ghidra_provider.py`,
`ghidra_protocol.py`, `storage.py`, `reports/`, `api/web.py`, `compose.yaml`,
`scripts/check-container.sh`. Paths are relative to `backend/src/bytasm/`
unless rooted at the repository. Tests are safeguards for admitted fixtures;
they are not evidence of hostile-input containment.

## Required acceptance evidence (all unchecked)

Each row needs a reproducible command/test, exact tool/image/kernel/architecture,
result, artifacts and independent reviewer. A configuration assertion is not a
runtime pass. Synthetic adversarial helper programs must be self-authored test
harnesses, separate from analyzed samples; never execute an imported sample.

- [ ] **Control separation:** stream size/hash only in the privileged broker;
  move even format identification into quarantine. Compromised parser cannot
  read or modify API process, SQLite, trusted store, queue, reports or other jobs.
- [ ] **Disposable compute:** per-job VM or reviewed isolated namespace boundary;
  no home/source/SSH/cloud/browser credentials, host sockets, Docker socket,
  unrelated devices, IPC or writable host mounts. Probe explicit canary paths.
- [ ] **Runtime networking:** from the running parser boundary, IPv4/IPv6,
  loopback-to-host, DNS UDP/TCP, metadata endpoints and raw socket attempts all
  fail as intended. Document any guest-local communication exception precisely.
- [ ] **Runtime identity and confinement:** non-root, no capabilities, no-new-
  privileges, read-only root/input and noexec scratch; verify syscall/MAC profile,
  namespaces/cgroups or VM equivalents, not environment assertions alone.
- [ ] **Budgets:** finite CPU, memory, PIDs, wall time, stdout/stderr, output file,
  total scratch/output disk, queue count and concurrency. Fill each independently;
  trusted control/store remain responsive and existing records unchanged.
- [ ] **Exact input transfer:** bounded regular file only; reject symlink/device/
  FIFO, immutable hash/size before and after transfer and before every tool.
  Test concurrent mutation/replacement, unexpected encodings and hostile names.
- [ ] **Fixed tools:** verified caller-installed Ghidra/JDK and pinned scripts,
  rules/profile identity; no input-controlled commands, options or projects.
  Fresh settings/cache per run; no parser-owned persistent cache survives.
- [ ] **Output protocol:** size cap before allocation, strict typed envelope,
  counts/integers/UTF-8/pointers/addresses/ranges independently validated against
  exact sample; malformed/truncated/extra output fails closed. Transfer only
  validated bytes, never parser-owned trees or Ghidra project directories.
- [ ] **Termination:** fork, double-fork, setsid, ignored TERM, hang and crash
  harnesses leave no descendants after timeout/cancel/shutdown/restart. Prove
  boundary teardown, scratch removal and no contaminated subsequent run.
- [ ] **Publication/recovery:** transactional output with cross-filesystem
  staging; inject disk full, permission errors, API/worker death at each phase,
  duplicate jobs, corrupt queue and cancellation races. No partial success or
  trusted-store corruption; cleanup cannot delete referenced evidence.
- [ ] **Historical compatibility:** migrations preserve notes/revisions and old
  JSON/HTML byte hashes; no silent historical rewrite; exports recheck identities.
- [ ] **Privacy/browser:** hostile text in every field stays inert; no automatic
  external navigation/assets/telemetry. Preview/inclusion rules and explicit
  retention/deletion cover sample, runs, raw output, notes, reports and tmp state.
- [ ] **Archives:** keep disabled until separate format allowlists, entry/total
  byte/ratio/nesting caps, duplicate/path traversal/symlink/device/FIFO rejection
  and streamed hashing pass bomb-like fixture tests inside this same boundary.
- [ ] **Fail closed:** absent/stale/unhealthy/misconfigured boundary cannot admit
  or process external input. Test configuration and runtime failure after queue
  admission. Fixtures-only demos still work; no native fallback.
- [ ] **Platform/review:** independently review threat model and runtime evidence
  on each enabled OS/architecture. Linux ARM64 cannot authorize AMD64, macOS or
  Windows. Document kernel/hypervisor escape residual risk and supported setup.

## Next verifiable step

Prototype the broker/disposable-worker transfer using harmless generated data and
self-authored escape/exhaustion harnesses. Demonstrate that the parser cannot read
a control-plane canary or write trusted storage and that all descendants disappear
on teardown. No user-facing external intake until this and the full checklist
pass independent review. Existing Compose scripts are diagnostics for the current
fixture deployment; they cannot mark this checklist complete.
