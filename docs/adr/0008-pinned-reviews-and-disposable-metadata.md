# ADR-0008: pinned reviews and disposable metadata workers

Status: implemented decision under owner review, 2026-10-31. No external-admission approval.

## Review identity and selection

A review is an append-only canonical JSON document, schema `bytasm-review-1`,
with an independent random ID, timestamp and SHA-256. Migration 0008 adds a
separate table; migration 0009 adds immutable function overlays. Historical
sample/Ghidra reports and their independent selection policies are untouched.

Combined selection scans at most 200 runs of one exact sample version. It selects
the newest succeeded invocation of each tool in a terminal run, ordered by queued
time then run ID. This preserves completed steps of partial/cancelled runs.
It records each tool's latest attempted step separately, including missing,
skipped, queued, failed and cancelled attempts. Tools did not necessarily run
together. Exact-run mode considers only that analysis run, with no substitution;
it does not include the separate import invocation as though it ran again.

A changed or missing selected output refuses creation. It never falls back to
an older output to conceal an integrity failure. Sample bytes, size, source
hashes, supported typed protocols, tool/adapter versions, rule identity, normalized
findings, evidence and strings are checked. Strings and YARA ranges are independently
checked against sample bytes. Ghidra uses the existing strict script/profile
verification. Capa checks its pinned public result model and exact matched rule
sources against its retained packaged snapshot.

Reads verify the canonical snapshot digest and identity, not current live tool
outputs. `verified_at_creation` means exactly that. A snapshot does not silently
change or acquire a current catalog meaning. Refresh appends a new ID with a
supersedes link, even for exact-run scope. The old snapshot remains readable.
There is no update endpoint. The JSON/HTML privacy derivatives consume only the
stored snapshot, including the captured latest-attempt disclosures and selected
analyst revision. Browsing evidence never runs a parser.

## Interpretation boundaries

Reviewed capa code features precede reviewed text and structural context, then
unreviewed observations. Repeated locations do not increase weight. The model
chooses reading order, not probability or severity. All retained observations
remain accessible. Existing seven rule interpretations now have human labels,
conditions, alternatives, limitations and next steps in pinned and current live views. Historical report views retain their source ordering and labels.

`imports-1` adds 13 curated exact import-name categories for LIEF 1.0.0 and
metadata_lief 0.1.0. These are declarations of imported names, not proven calls,
capabilities, execution or purpose. Each group points into exact source metadata.
The catalog has a deterministic content digest. No symbol proximity, name-only
function correlation, network lookup, AI or rule repository import is introduced.

## Analyst overlays

Function scope binds sample hash, version, run, invocation, output digest and
exact address-space/entry pair, with its original record pointer. Ordinals alone
are never persistent identity. Each save appends a digest-checked revision and
checks the expected predecessor revision; concurrent stale saves conflict.
Aliases, bookmarks, collections, notes and workflow state remain overlays.
Pseudocode citations validate the complete exact text digest and inclusive
one-based line range. A new run has its own scope; notes are not silently carried
forward. Missing/changed source output refuses edits and is explained by the UI.
Routine activity logs receive no note bodies. Snapshot exports include current
function overlays only by explicit policy; prior revisions and ordinary version
annotations are outside this export contract.

## Disposable metadata operation

An optional local `BYTASM_METADATA_ISOLATION_IMAGE=sha256:…` chooses a fixed trusted
image ID. No uploaded field selects an executable, image, script, mount or runtime.
The broker computes and admits the bounded bytes before creating the worker.
The exact stream passes over stdin; no host path is given to the parser. The
worker verifies the digest before importing LIEF. Output is bounded and strictly
validated; the broker independently recomputes section entropy for valid byte
ranges, with a 128 MiB aggregate measurement budget. Existing transactional import
publication remains the only path into trusted storage. The invocation records
the fixed profile, image identity and transport.

A fresh non-root read-only container has no host mounts, network, capabilities,
Docker socket or trusted application files. It has 512 MiB memory/no swap,
one CPU quota, 32 PIDs, 16 MiB noexec scratch, bounded file descriptors and no
Docker logging. Parent deadline, bounded pipe draining and forced container
removal bound jobs and tear down detached descendants. Cleanup failure prevents
publication. No native parser fallback exists when this mode is configured.
The default native path and fixture/self_built rules remain as before.

Docker Desktop's available Linux/aarch64 runtime was used on this Darwin ARM64
host. No KVM/Firecracker/QEMU acceleration was assumed or installed. Docker
Desktop already supplies a VM; the workers still share its Linux kernel with
other containers. A kernel/runtime escape, malicious trusted image, daemon
compromise, broker compromise and host-side format checks remain residual risks.
A separately managed VM per operation was not built or verified. Docker's trusted
control plane retains host privilege; it is never mounted inside the worker.
This operation is an architectural improvement, not completion of I1.
