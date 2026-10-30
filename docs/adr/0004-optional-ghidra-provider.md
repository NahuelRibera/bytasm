# ADR-0004: optional caller-installed Ghidra Headless provider

- Status: **Proposed**, 2026-10-30. This records the owner's requested scope
  change, not acceptance of an unverified analysis boundary.
- Scope: a future v0.5 static-only provider; this increment delivers diagnostics
  only. ADR-0001/0002 remain historical accepted records; ADR-0003 stays proposed.

## Context and source of authority

The current blueprint §3.3 defers Headless Ghidra until v0.5; §4 already plans
function inventory and decompiler excerpts. It does not permanently prohibit
Ghidra. The owner's current request intentionally advances that integration,
without authorizing broader binary admission, REA, agents, dynamic execution,
model providers or a database/queue replacement. Keep the blueprint intact.

## Proposed design

Use a caller-installed, explicitly configured Ghidra 12.2 distribution and a
64-bit JDK 25. Do not download/install either, discover arbitrary directories,
load user projects, bundle extensions or invoke sample-selected scripts.
Configuration uses `BYTASM_GHIDRA_HOME` and `BYTASM_GHIDRA_JAVA_HOME`, separate
from the API's ordinary Java/PATH environment. Configuration alone must never
declare the tool available or enable a profile.

An eventual fixed, self-authored Java post-script should emit a versioned,
bounded protocol. After admission/hash rechecks, a network-less low-privilege
worker should use private disposable projects, process-tree cleanup, isolated
preferences, a heap and container memory budget, temporary-disk quota, timeout
and stdout/stderr caps. `-analysisTimeoutPerFile` alone is insufficient. Do not
reuse the native Python runner's 1 GiB address-space limit for a JVM without
measurement. Do not treat a writable shared database volume as gate I1.

Future results need exact run/version/tool/profile/script digests, typed address
spaces and exact textual addresses; virtual addresses must not become invented
file offsets. Function inventory and selected details need separate bounded,
scoped APIs. Commit validated step results atomically using the existing SQLite
claim loop, preserving earlier successful steps under its partial-run policy.
Use a new evidence/report contract only after a migration preservation/downgrade
design; never add incompatible function fields silently to schemas 2/3/4.

## What is implemented now

Read-only metadata preflight, `bytasm doctor`, and a distinct optional-provider
diagnostic in Tools. It reads only explicitly configured installation metadata
and checks fixed expected file locations. No executable, Java class or script is
launched. Declared versions are not a successful health check. `available` and
`analysis_enabled` are always false, and `health_check` is `not_run`. There is
no Ghidra run/profile, result table, report field or incomplete analysis button.
Invalid optional configuration never prevents existing app workflows starting.

## Blockers and alternatives

No caller-installed Ghidra is configured in this checkout; the observed local
JDK is 21, not 25. Downloading/installing dependencies is explicitly excluded.
Native workers retain network access; the existing offline Compose worker does
not contain Ghidra/JDK. Host mounts or Docker-socket access are not a workaround.
Real headless self-check, fixture-positive integration, bounded extraction and
cleanup cannot be honestly verified here. Complete P0 remains blocked until
these resources and a tested offline runner are supplied. Then implement and
verify a complete vertical slice before adding any analysis control.

Running an unverified native launcher, accepting metadata as proof of usability,
simulating Ghidra with fabricated function output, or bundling an unreviewed
distribution were rejected. A diagnostic-only increment is intentionally less
capable than a functioning provider and must be described that way.

## Licensing sources

[12.2 installation requirements](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md)
and [application properties](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/application.properties)
specify JDK 25. The [LICENSE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/LICENSE)
is Apache-2.0; the [NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/NOTICE)
identifies per-module third-party licenses and GPL support programs. The exact
binary distribution is not installed or audited here: no redistribution
clearance is claimed. No Ghidra/Java distribution or third-party script is added.
