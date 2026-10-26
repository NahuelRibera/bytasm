# Security policy

## Project status

Bytasm is in early development (v0.1, milestones M0–M1). It is not released,
not hosted anywhere, and not meant for real-world analysis yet.

## Responsible use

- Use Bytasm only on software you wrote or are clearly authorised to analyse.
- **During M0–M1, Bytasm only inspects its own committed fixtures.** A file is
  accepted only if its SHA-256 is listed in `fixtures/MANIFEST.sha256`, and that
  check runs before any parsing.
- Do not use Bytasm on downloaded, received, third-party, or suspicious
  binaries, including malware samples. No current or planned v0.1 mode
  accepts them.
- Bytasm performs static analysis only. It never executes the files it inspects.

## Known limitations

- **No sandbox.** Bytasm parses files with LIEF, a C++ library. A crafted file
  could exploit a parser bug. In M1 the parser runs inside the CLI process.
  From M2 it will run in a resource-limited subprocess, which limits crashes,
  hangs, and memory use. It is **not** a security sandbox: it runs as the same
  user with the same file and network access.
- **The input policy is the main control.** Safety in this phase comes from
  *what Bytasm agrees to parse* (its own fixtures), not from containment.
- **Header values are declared, not verified.** Architecture, entry point,
  timestamps, and flags are what the file says about itself.
- **Entropy is a measurement, not a verdict.** Bytasm does not classify files
  as safe or malicious.
- **Resource limits are provisional** (64 MiB file size today; parser time and
  memory limits arrive in M2). The M1 measurement found no reason to change
  them (`docs/measurements/2026-10-26-m1-parse-time-memory.md`).

The full threat model is in `docs/PROJECT_BLUEPRINT.md` §8, and the accepted
decisions are in `docs/adr/0001-stack.md`.

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
