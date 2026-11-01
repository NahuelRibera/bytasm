# Recorded real tool outputs

Exact `ghidra-4` documents produced by the real Ghidra provider (Ghidra 12.2
PUBLIC, Temurin JDK 25.0.5+8, Linux arm64 container, offline, read-only, no
sample executed) on 2026-11-01 for v0.10. They let always-run tests correlate
real Ghidra output with live LIEF, YARA-X, capa and strings results without a
Ghidra installation. The real provider lane (`scripts/check-ghidra-real.sh`)
remains the acceptance check for the extractor itself.

| File | Fixture | SHA-256 of the document |
|---|---|---|
| `capa_read_file-x86_64.exe.ghidra.json` | `fixtures/bin/capa_read_file-x86_64.exe` | `99cb035c88c1d473efdf68ddc499a66947a7c35767e0e02029100f899631d3cf` |
| `hello_v1-x86_64.elf.ghidra.json` | `fixtures/bin/hello_v1-x86_64.elf` | `678c2fef3b6a6608a1d3c566211f3527723de38ba3db4957cb49a295b862bdcf` |

Each document records its own `script_sha256` and `profile_sha256`. A later
change to `BytasmExtract.java` changes the current digests but does not alter
these records; tests seed runs with the recorded digests. Never hand-edit a
recorded document. Re-record with the same container settings if the protocol
changes, and update this table.
