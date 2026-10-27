# Bytasm JSON report, schema version 1

One report describes one imported sample version. Schema: [`schemas/report.schema.json`](../schemas/report.schema.json) (JSON Schema 2020-12, generated from `backend/src/bytasm/reports/model.py` by `make schemas`).

## Reproducibility

- Canonical serialisation: UTF-8, keys sorted, two-space indent, ASCII escapes, trailing newline; lists in a fixed order (sections by index, names sorted).
- **Only `generated_at` differs** between two exports of the same data. Everything else comes from the database rows written at import time.
- Before export, Bytasm re-hashes the stored sample file and the stored adapter result. If either no longer matches its recorded SHA-256, the export is refused (HTTP 409) and nothing is written.
- The report file is stored and served by its own SHA-256 (`X-Bytasm-Report-SHA256` header on download).
- To reproduce the metadata independently, run `bytasm inspect` on the same fixture: sections, entropy values, imports, exports and header fields match.

## Top-level fields

| Field | Content |
|---|---|
| `report_kind`, `schema_version` | `bytasm.sample_version_report`, `1` |
| `generated_at` | UTC timestamp of this export (the only varying field) |
| `generator` | `bytasm`, its version, `source_revision` (`git describe`, `-dirty` if uncommitted), `image_id` (null when run natively) |
| `sample` | Project and sample names, version label, `sha256`, `size_bytes`, `format` (from the bytes), `declared_filename` (marked `untrusted_as_uploaded`), `blob_sha256_verified_at_export: true` |
| `input_policy` | `admitted_under` (`fixture_manifest` or `self_built_optin`), the manifest entry, and the input-policy notice |
| `authorization` | `type: self_attestation`, basis (`owned_or_built`), statement, timestamp, and the "not proof of permission" notice |
| `analysis` | The run (status, profile snapshot, Bytasm version, times) and its tool invocation: LIEF version, adapter and version, exit code, duration, `result_sha256` of the raw adapter output, `execution: separate_resource_limited_process` |
| `metadata.declared_in_header` | Architecture, bitness, endianness, entry point, and format-specific header fields, **as declared** |
| `metadata.sections[]` | Name, type, offsets, sizes, flags, and `entropy {value, unit: bits_per_byte, method, computed_by, measured_over: section_bytes_in_file, note}` |
| `metadata.imports`, `exports`, `warnings` | As reported by the adapter |
| `labels` | What each kind of value means (declared vs measured, untrusted text) |
| `limitations` | Static only, not executed; header values unverified; entropy is not a verdict; no verdict or score; self-authored inputs only; the parser process is not a sandbox |

There is no verdict, risk score, severity, or "malicious/safe" field, and adding one would break the schema.
