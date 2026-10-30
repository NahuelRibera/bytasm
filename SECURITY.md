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
Both services share the data volume and host kernel. The worker has no network
interface beyond loopback (`network_mode: none`); the API retains outbound
connections on its bridge network. This is not the gate I1 boundary.

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


## v0.4 capa and HTML boundary

capa 10.0.0 is a third-party static tool, not a Bytasm sandbox. Only the fixed
vivisect PE x86/x64 backend and an attributed two-rule subset are selected;
.NET, ELF, shellcode, dynamic reports, user rules/plugins and library signatures
are unsupported in this integration. No network service receives files or hashes.
The worker rechecks current admission and the blob hash before each child.
The child also verifies sample/rule hashes. The strict bounded result envelope
and parent provenance/pointer checks precede transactional persistence.

Limits: 64 MiB input; 1 GiB address space on Linux; 100 CPU seconds in the capa
bridge, 110-second internal CLI deadline, 120-second parent deadline;
16 MiB per-file child limit, 8 MiB retained raw JSON, 64 KiB accepted stderr,
16 MiB parent envelope; at most 16 matched rules and 32 recorded function
locations per rule. The actual packaged subset contains two rules. Parent
stdout/stderr have independent 64 KiB caps. On native Linux a same-UID thread-count
backstop allows eight additional tasks; RLIMIT_NPROC is UID-scoped and
ineffective for root. Supported Compose uses its verified 128-task cgroup
cap instead: PID-namespace /proc cannot enumerate same-UID tasks in other
containers, so deriving RLIMIT_NPROC from that count would prevent valid forks. Native macOS cannot enforce RLIMIT_AS and remains
fixture-only. These controls do not block all file/network access or establish
an isolated analysis boundary. Original bounded CLI output is an explicit
local download; it may contain function addresses and private temporary paths.
It is not copied into ordinary logs or inline in reports. capa's rule cache
is restricted to a fresh private per-step directory by the pinned entry shim
(XDG_CACHE_HOME alone is ignored by capa on macOS);
no persisted or user/global pickled rule cache is read.

A failed, unavailable or unsupported capa step never means no capabilities.
Completed earlier steps survive; cancellation/restart use the existing worker
transactions and process-group termination. capa supplies virtual addresses,
not the file byte ranges displayed for YARA-X. Its rule text and ATT&CK/MBC
labels remain untrusted observations. Packed programs, installers, wrappers
and the absence of library signatures limit interpretation.

Report HTML comes only from a hash-verified, schema-validated JSON snapshot.
Jinja2 autoescaping is mandatory. There is no JavaScript, remote content, form
or raw-HTML insertion. Header/meta CSP restricts sources; print and narrow
layouts wrap file-derived text. Comparison reports can disclose changed strings
and analyst-authored material: review before sharing. This work adds neither
arbitrary binary admission nor a backup/archive import mechanism. See
THIRD_PARTY_NOTICES.md for licensing review and the outstanding transitive
license packaging clarification before image redistribution.

## Post-PR6 review presentation and offline worker

Compose's worker now has `network_mode: none`; both the resolved-configuration
and running-container checks require it. It uses the shared SQLite/filesystem
queue and publishes no ports. This does not remove the API/LIEF import child's
outbound access, native-process access, shared writable volume or same-UID risks.
It does not establish a sandbox or pass I1. All admission/resource/cancellation
checks remain mandatory, including fixture-only native macOS behavior.

Review explanations are deterministic self-authored templates keyed to exact
tool version, rule identifier and rules hash. Unrecognised provenance receives
no rule-specific hypothesis. These are hypotheses, separate from cited analyst
conclusions; no score or executed behavior is inferred. The presentation is
bounded and escaped, and creates no new activity/log content. API access logs
are disabled; queries, values and annotation bodies are not routine log data.

String categories describe a prefix's shape only, never its purpose. Path-like
values are hidden by default in the explorer, but remain in the local API and
existing bounded raw output. This is a display control, not encrypted storage.
Filename directory components are hidden in overview summaries; full original
provenance remains an explicit disclosure. Comparison exports can still contain
changed strings and analyst text: review before sharing. No automatic URL links,
external queries, sensitive-string classifier or new binary admission is added.
Stored JSON summaries remain authoritative when rendering historical HTML.

## Optional Ghidra static analysis boundary

Metadata preflight remains bounded/nonblocking and never establishes availability.
Doctor and the configured worker run a real bounded Headless/native health check
using an empty in-memory program, without importing a sample. Only explicitly
configured trusted Ghidra/JDK paths select executable code. No tool is installed
automatically, no GUI/plugins/MCP/AI integration is added, and no sample-derived
content is sent to a network service.

Sample analysis requires the offline non-root Linux/resource/tmpfs controls in
[the setup guide](docs/ghidra-setup.md). The API reads a bounded worker health
record only while its heartbeat is fresh; every analysis rechecks controls,
admission, sample hash and script/profile identity. Private per-run projects,
settings, caches and bounded logs never reuse user-owned databases/preferences.
Arguments are arrays; sample paths appear only as Headless import inputs.
No sample is run, loaded as a library, debugged, emulated or detonated.

Ghidra output is hostile parser output, bounded before parent allocation,
validated against a strict typed protocol and stored transactionally. Address
spaces remain explicit; no virtual-address/file-offset conversion is invented.
Raw tool logs are not routine logs. Pseudocode is reconstruction, static calls
are relationships rather than observed execution, and no safety verdict follows.

This remains option B: fixtures/self_built admission is unchanged. A parser
vulnerability could still affect the host or shared application data. Process
groups cannot contain every escaped descendant; cgroup process/memory limits
and container teardown are backstops, not a complete sandbox. API import isolation
and writable-volume separation still block arbitrary-file admission. Exported
Ghidra reports can disclose names, addresses and pseudocode; review before sharing.
See ADR-0005 and the current milestone for verification and unrun checks.
