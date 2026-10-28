# Security policy

## Project status

Bytasm is in early development (v0.1, milestones M0–M5 implemented; v0.1.0
not tagged; v0.2 strings extraction and YARA-X pattern matching are implemented on a branch and under review). It is not released, not hosted anywhere, and not meant for
real-world analysis yet.

## Responsible use

- Use Bytasm only on software you wrote or are clearly authorised to analyse.
- **By default Bytasm only accepts its own committed fixtures.** A file is
  admitted only if its SHA-256 is listed in `fixtures/MANIFEST.sha256`, and that
  check runs before any parsing. The optional `self_built` mode (native Linux
  only, enabled only by local server configuration, refused in the container) also accepts binaries you
  compiled from source you wrote, on your word.
- Do not use Bytasm on downloaded, received, third-party, or suspicious
  binaries, including malware samples. No mode accepts them.
- Bytasm performs static analysis only. It never executes the files it imports.
- The authorisation statement recorded with each import is a self-attestation,
  not proof of permission.

## Security model and known limitations

- **No sandbox.** LIEF, a C++ parser, runs in a separate child process with
  its own process group, a minimal environment, resource limits it applies to
  itself before loading LIEF (memory 1 GiB, CPU 25 s, file writes 32 MiB, no
  core dumps), a 30 s timeout, and capped output. This is **process and
  resource separation**: it limits crashes, hangs, and memory use caused by
  parser bugs. It is **not** a security sandbox. The child runs as the same
  user with the same file and network access, so a crafted file that
  exploited LIEF could read your files, the Bytasm database and stored files,
  and make network connections.
- **YARA-X (v0.2) is handled like LIEF.** The worker re-checks the input
  policy and re-verifies the stored file's SHA-256 and size before every scan;
  YARA-X then runs in a separate child process with the same limits, a 20 s
  scan timeout under the 30 s kill, a per-pattern match cap, and capped
  output. The child re-hashes the sample and the rule snapshot before
  compiling. Its result is schema-validated, and every reported byte range is
  checked against the stored file before anything is saved. The worker holds
  the database and runs as the same user, so this is **not** a sandbox and
  **not** gate I1.
- **The strings extractor (v0.2) is handled the same way.** It is Bytasm's
  own code, run as a separate child process with the same limits, after the
  same admission checks, before every step. It re-hashes its input, only
  matches byte patterns, keeps at most 5,000 strings of at most 256
  characters, and its result is checked string by string against the stored
  file. String values are untrusted text: shown escaped, never logged, and
  not exported in the JSON report (counts only).
- **Rules are code.** The rule set (`rules/yara/`) is bundled and read-only:
  no API, UI, environment variable or request can add rules or point at other
  files. `include` is disabled in the compiler. Rule text, metadata and
  compiler messages are shown as escaped text, and compiler diagnostics are
  reduced to code, title and position.
- **Findings are observations.** A match says a pattern occurred in the bytes;
  it is not a verdict, and no match does not mean safe. Bytasm stores no
  severity or score. Logs record run IDs, hashes, counts and codes, never
  sample bytes, matched bytes or rule text.
- **The container is not a sandbox either.** `compose.yaml` runs Bytasm as a
  non-root user (UID 10001) with all capabilities dropped,
  `no-new-privileges`, Docker's default seccomp profile, a read-only root
  filesystem, a `noexec` `/tmp`, explicit memory/CPU/process limits, an init
  process, only its own named data volume, no Docker socket and no host
  mounts. That limits what a compromised parser could do to the *host*.
  The v0.2 `worker` service has the same settings and publishes no port.
  Inside the containers, the parsers still share the API's user, data volume
  (database, stored files) and network, and outbound connections are not
  restricted. The container shares the host kernel. A real analysis boundary
  is isolation gate I1 (blueprint §5.4.3), not v0.1.
- **The input policy is the main control.** Safety comes from *what Bytasm
  agrees to parse*, not from containment.
- **Platform limits.** The memory limit is enforced on Linux. On macOS,
  `setrlimit(RLIMIT_AS)` is refused by the OS, so the memory limit is not
  applied (the CPU, file-size, and timeout limits are). That is why native
  macOS runs are fixtures-only and `self_built` requires Linux. On Linux the
  server marks itself non-dumpable, so the child cannot read its environment
  through `/proc`. A process that leaves the parser's process group
  (`setsid()`) escapes the timeout kill (see the README's known limitations).
- **Local only.** Natively, the server binds only to loopback. In the
  container it listens on the container's own interface, and Docker publishes
  the port on the host's `127.0.0.1` only (asserted by `make compose-check`);
  the container interface itself is reachable from the Docker host and its
  bridge network. In both cases it accepts only its own
  `Host` names and origin, sends no CORS permissions, and requires an
  `X-Bytasm-Request` header on every state-changing request. There is no
  authentication, so it must never be exposed to a network.
- **Untrusted output and text.** The parser's output is size-capped and
  schema-validated before use. Output from a failed, timed-out, or killed
  process is never used. Parser messages are never shown to users. File-derived
  names are rendered as escaped text only (React; raw-HTML APIs banned by lint).
- **Stored files** are kept by SHA-256 outside any served path, read-only, and
  re-verified before every report export.
- **Header values are declared, not verified.** Entropy is a measurement, not
  a verdict. Bytasm does not classify files as safe or malicious.
- **Dependencies** are pinned by `backend/uv.lock` and
  `frontend/package-lock.json` and audited with `make audit` (pip-audit and npm
  audit against public advisory data).
- **Resource limits are provisional** (blueprint §5.4.1). The M1 measurement
  found no reason to change them
  (`docs/measurements/2026-10-26-m1-parse-time-memory.md`).

The tested answers to the implementation questions are in
`docs/milestones/v0.1-m2-m5.md`. The full threat model is in
`docs/PROJECT_BLUEPRINT.md` §8, and the accepted decisions are in
`docs/adr/0001-stack.md` and `docs/adr/0002-v0.1-implementation-choices.md`;
the v0.2 decisions (proposed) are in `docs/adr/0003-v0.2-pattern-matching.md`
and `docs/milestones/v0.2-pattern-matching.md`.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

- Once the repository is published on GitHub, use **private vulnerability
  reporting** ("Security" tab → "Report a vulnerability").
- Until then, contact the maintainer privately.

Please include the Bytasm commit, the steps to reproduce, and the impact you
expect. If your report involves a binary, describe how to generate it
rather than attaching a third-party or malicious file. You should get an
acknowledgement within 7 days. This is a single-maintainer learning project,
so fixes may take longer.
