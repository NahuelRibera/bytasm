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

## ghidra-5 (v0.11, 2026-11-02)

Produced by the real provider with the v0.11 extractor (same container settings: offline, read-only,
non-root, 2 GiB, 2 CPUs; no sample executed). They are kept in a subdirectory, so the
always-run tests that seed the ghidra-4 documents above are unchanged.

| File (`ghidra-5/`) | Fixture | SHA-256 of the document |
|---|---|---|
| `capa_read_file-x86_64.exe.ghidra.json` | `fixtures/bin/capa_read_file-x86_64.exe` | `b40912dbc19bc8de15646396623e9abb4f5cf8355de622fe8134879bada76b53` |
| `hello_v1-x86_64.elf.ghidra.json` | `fixtures/bin/hello_v1-x86_64.elf` | `35585eff3537f1d820fedf025f8584dd2a8b8bbc1c6868bbe9fa787fde8ea9b3` |
| `hello_v2-x86_64.elf.ghidra.json` | `fixtures/bin/hello_v2-x86_64.elf` | `36cd25098358fc58f5fb7a565393aeab85347b58a4026d48810abab187e7d3a7` |
| `hello_v1-aarch64.elf.ghidra.json` | `fixtures/bin/hello_v1-aarch64.elf` | `a09e7a6d8a56427e5c9cee78c7e279fbf20ac1569ac45c2f174676fa873c515a` |
