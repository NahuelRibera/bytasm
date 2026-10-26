# Bytasm

Bytasm is a **local-first static binary-analysis workbench** for PE and ELF
files, **in early development**. It reads a binary's bytes and reports what the
file declares about itself (format, architecture, sections, imports) plus a few
measurements (such as per-section entropy). It never runs the file.

Today Bytasm is a command-line tool, `bytasm inspect`, that works **only on its
own committed test fixtures**. The web app, API, and reports described in
[`docs/PROJECT_BLUEPRINT.md`](docs/PROJECT_BLUEPRINT.md) do not exist yet.

> **Status:** milestones M0 (foundations) and M1 (fixtures + inspect CLI) of
> v0.1. Not released. Not suitable for real-world analysis.

## Supported inputs and security limits

Read this before using Bytasm.

- **Fixtures only (M0–M1).** `bytasm inspect` accepts a file only if its
  SHA-256 is listed in [`fixtures/MANIFEST.sha256`](fixtures/MANIFEST.sha256).
  That check runs **before** the parser sees any byte. There is no option,
  flag, or environment variable to inspect other files.
- **Not for downloaded, received, third-party, or suspicious binaries.** Bytasm
  uses LIEF, a C++ parser. A crafted file could trigger a parser bug. Bytasm
  has no isolation that would contain an exploit, so it only parses
  self-authored files.
- **Bytasm never executes the files it inspects.** It only reads them.
- **The parser subprocess is not a security sandbox.** In M1 LIEF runs inside
  the CLI process. From M2 it will run in a separate, resource-limited
  subprocess. That subprocess runs as the same user with the same file and
  network access, so it limits the damage from parser *bugs* (crashes, hangs,
  memory use). It does **not** contain a parser *exploit*.
- **Later phases:** after the M1 acceptance tests pass, an optional, local-only
  `self_built` mode may be added for binaries you compiled from source you
  wrote. It is a provenance rule based on your own word, not a safety check.
  Any wider input (third-party files) requires the isolation gate I1 and an
  independent security review first
  ([ADR-0001](docs/adr/0001-stack.md), blueprint §3.4).

## Responsible use

Analyse only software you wrote or are clearly authorised to analyse. In this
phase that means Bytasm's own fixtures. Any future "I am authorised" statement
in Bytasm is a self-attestation for your records. It is not proof of
permission and not a legal determination. See [`SECURITY.md`](SECURITY.md).

## Quick start (development)

Requirements: [uv](https://docs.astral.sh/uv/) (it provides Python 3.12+ and
creates a project-local virtual environment; nothing is installed globally).

```sh
make install          # create backend/.venv from backend/uv.lock
uv --directory backend run bytasm inspect ../fixtures/bin/hello_v1-aarch64.elf
```

`uv --directory backend` runs from `backend/`, so fixture paths are relative to
it. You can also activate `backend/.venv` and run `bytasm inspect <path>`.

## What `bytasm inspect` reports

Deterministic JSON on stdout (sorted keys, no timestamps, no absolute paths):
inspecting the same file twice gives byte-identical output.

| Field | Meaning |
|---|---|
| `file.sha256`, `file.size_bytes` | Hash and size of the exact bytes inspected |
| `input_policy` | `mode: fixtures`, `admitted_under: fixture_manifest`, and the manifest entry that matched |
| `format` | `ELF` or `PE`, identified from the bytes, never from the file name |
| `architecture`, `bitness`, `endianness` | As declared in the file header |
| `entry_point` | Declared entry address, or `null` if the file has none (for example, a `.o` object) |
| `declared_header` | Other header values (ELF type, PE timestamp, subsystem…), **as declared and not verified**. A PE timestamp can be forged or zeroed |
| `sections[]` | Name, type, file offset, bytes in the file (`file_size`), header-declared size, virtual address, flags, and `entropy` |
| `imports`, `exports` | ELF: libraries and imported functions from the dynamic symbol table; exported functions as LIEF reports them. PE: import table and export table |
| `adapter` | Bytasm adapter version, LIEF version, entropy method |
| `warnings`, `notes` | Problems found while measuring, and fixed reminders of what the values mean |

**Entropy** is Shannon entropy in bits per byte (0–8), measured by Bytasm over
each section's bytes *in the file*. Sections with no file bytes (such as
`.bss`) get `null` ("no file data"). Sections whose declared range runs past the
end of the file get `null` and a warning. Entropy is a measurement, not a
verdict. Bytasm applies no threshold and never labels a file as good or bad.

**Errors** are JSON too: `{"error": {"code": ..., "message": ...}}`.

| Exit code | Meaning | Error codes |
|---|---|---|
| 0 | Report printed | — |
| 1 | Operational problem | `file_not_found`, `manifest_error` |
| 2 | Input refused (or a usage error, reported on stderr) | `unknown_hash`, `empty_file`, `file_too_large`, `unsupported_format`, `malformed_input`, `parse_failed` |

The order of steps is the safety design: read the file once (64 MiB
provisional limit) → SHA-256 → manifest check → identify PE/ELF from magic
bytes and basic header checks → only then load LIEF and parse **the same
in-memory bytes** that were hashed.

## Fixtures

Self-authored C programs in [`fixtures/src/`](fixtures/src), compiled into
[`fixtures/bin/`](fixtures/bin). Toolchains, exact versions, and build
commands are in [`fixtures/BUILD_INFO.txt`](fixtures/BUILD_INFO.txt).

| Fixture | What it is |
|---|---|
| `hello_v1-aarch64.elf` | AArch64 ELF executable |
| `hello_v1-aarch64-stripped.elf` | The same, stripped |
| `entropy_blob-aarch64.elf` | AArch64 ELF with a 4 KiB high-entropy `.blob` section and a `.bss` array |
| `hello_v1-x86_64.elf` | x86-64 ELF executable (PIE, dynamically linked against glibc) |
| `hello_v1-x86_64-stripped.elf` | The same, stripped |
| `hello_v1-x86_64.o` | x86-64 ELF **relocatable object** (not a linked executable) |
| `hello_v1-x86_64.exe` | PE32+ x86-64 console executable (MinGW-w64) |
| `exports_v1-x86_64.dll` | PE32+ x86-64 DLL exporting two named functions |

Bytasm *parses* PE and ELF files for any architecture LIEF supports, but it is
*tested* only on the fixtures above.

## Development

All Python tooling runs inside `backend/.venv` through uv.

```sh
make lint              # ruff format --check + ruff check
make typecheck         # mypy --strict
make test              # pytest
make check             # all three (what CI runs)
make verify-fixtures   # check fixture bytes against MANIFEST.sha256
make fixtures          # rebuild fixtures (Docker + clang; never runs them)
make check-linux       # the check suite inside a linux/arm64 container
make measure           # parse time and peak memory (see docs/measurements/)
```

CI (`.github/workflows/ci.yml`) runs the manifest check, ruff, mypy, and
pytest on Python 3.12 and 3.14. It never rebuilds fixtures.

Repository layout:

```
backend/            Python package `bytasm` (src/bytasm), tests, uv.lock
  src/bytasm/intake/    manifest allowlist, format identification
  src/bytasm/adapters/  LIEF metadata adapter, entropy
fixtures/           self-authored sources, committed binaries, MANIFEST.sha256
  build/              build.sh and the pinned cross-toolchain Dockerfile
scripts/            Linux container check, parse measurement
docs/               blueprint, scope review, ADRs, design references
```

## Roadmap

Next milestones (blueprint §12): M2 subprocess runner (resource limits,
timeouts; robustness, not isolation) → M3 intake API → M4 UI → M5 JSON report
and v0.1.0. Everything beyond that is possible, not promised.

## Licence

Not chosen yet. Licensing is an open decision in the blueprint (§13.2), so this
repository has no `LICENSE` file for now.

Third-party: [LIEF](https://lief.re) (Apache-2.0).
