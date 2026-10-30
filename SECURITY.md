# Security policy

Bytasm is an early-development tool for local static inspection of self-authored
PE and ELF binaries. It never executes imported files. It is not ready to handle
untrusted binaries or to run as a network service.

## Allowed inputs

The default `fixtures` policy checks a file's SHA-256 against
`fixtures/MANIFEST.sha256` before parsing. Native Linux can also accept programs
you compiled from source you wrote, through the locally configured `self_built`
mode. That mode relies on your statement about the file's origin; it cannot
verify it. It is disabled by default and refused on macOS and in containers.

Do not import downloaded, received, third-party or suspicious binaries,
including malware samples. These require the separate analysis boundary and
independent review planned in blueprint §5.4.3 (gate I1).
The authorisation statement stored with an import is a record of your claim,
not proof of permission.

## Process and container limits

LIEF, strings extraction and YARA-X run in child processes. The runner limits
CPU time to 25 seconds, wall time to 30 seconds, memory to 1 GiB on Linux,
and file writes to 32 MiB. It disables core dumps, limits captured output and
terminates the process group on timeout or cancellation. YARA-X also has a
20-second scan timeout.

These limits help with crashes and resource exhaustion. They do not contain a
parser exploit: children run as the same user and can access the database,
stored files and network. A child that calls `setsid()` can escape the process
group kill. Linux prevents children from reading the server environment through
`/proc`; this does not prevent access to its stored data. macOS cannot enforce
the memory limit, so native macOS runs accept fixtures only.

Compose runs the API and worker as UID 10001, drops capabilities, uses
`no-new-privileges`, default seccomp, a read-only root filesystem, a `noexec`
temporary directory and explicit resource limits. It mounts a named data volume,
with no host directories or Docker socket. The worker publishes no port.
Both services share the data volume and network; outbound connections are
allowed, and containers share the host kernel. This is not the gate I1 boundary.

## Requests and stored results

The native server binds to loopback. Compose publishes the API on host
`127.0.0.1`; its internal interface remains reachable from the Docker host and
bridge network. Host and Origin checks restrict browser requests, CORS is not
enabled, and state changes require `X-Bytasm-Request`. There is no authentication.
Do not expose the API through a public port, tunnel or reverse proxy.

Before each analysis step, the worker checks the input policy, file hash and
size again. Only successful, size-capped and schema-validated child results are
used. Earlier completed steps survive a later failure. Evidence bytes and
extracted strings are checked against the stored file before saving.

Rules are bundled with the application. The app cannot load user-supplied rules
or alternate paths, and the compiler disables `include`. File-derived text,
rule text and diagnostics are rendered as escaped text. Parser messages are
not shown to users. Logs contain IDs, hashes, counts and fixed codes, not sample
contents, matched bytes or rule text. Reports include string counts, not values.

Blobs and outputs are stored by SHA-256 outside served paths. Blobs are
read-only; report exports re-check the referenced files. Audit events are
append-only in application code, but anyone with database write access can
change them. A rule match or entropy value is an observation, not a safety
verdict. Header fields are declarations made by the file and may be forged.

Dependencies are locked in `backend/uv.lock` and `frontend/package-lock.json`.
`make audit` checks them against public advisory data using pip-audit and npm.
The [blueprint](docs/PROJECT_BLUEPRINT.md) §8 contains the threat model;
[milestone records](docs/milestones/) describe tests and remaining gaps.
The worker/database decisions in [ADR-0003](docs/adr/0003-v0.2-pattern-matching.md)
are still proposed.

## Analyst text and comparison exports

Annotations are plain text displayed through React's escaping. Conclusions
require scoped finding/evidence citations; they remain the analyst's statements,
separate from machine observations. The application checks citation relationships
on write and export. Revisions and citations are append-only, with database
constraints and triggers, but someone who controls the database or files can
still tamper with them. The local author badge is not authentication.

Activity records contain IDs and revision numbers, never annotation bodies.
Comparison exports can contain changed extracted strings and evidence excerpts.
Review them before sharing; the single-version report still exports string
counts only. Comparisons describe static observations, not behavioural
equivalence or a safety verdict.

## Reporting a vulnerability

Contact the maintainer privately. If GitHub's Security tab offers
**Report a vulnerability**, use that; do not open a public issue with exploit
details. Include the commit, reproduction steps and expected impact. Describe
how to generate a test binary rather than attaching a third-party or malicious
sample.

The target acknowledgement time is seven days. This is a single-maintainer
project, so a fix may take longer.
