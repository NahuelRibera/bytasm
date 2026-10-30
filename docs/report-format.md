# Bytasm JSON report, schema version 3

One report describes a sample version or a comparison of two versions of the
same sample. Version 3 adds `scope`, analyst `annotations` and optional
`comparison`. The primary version retains the metadata/pattern fields below.
Version 2 (v0.2) keeps every version-1 field unchanged and adds one top-level field, `pattern_analysis`; a reader of version 1 that ignores unknown fields still reads the rest. Schema: [`schemas/report.schema.json`](../schemas/report.schema.json) (JSON Schema 2020-12, generated from `backend/src/bytasm/reports/model.py` by `make schemas`).

## Reproducibility

- Canonical serialisation: UTF-8, keys sorted, two-space indent, ASCII escapes, trailing newline; lists in a fixed order (sections by index, names sorted).
- **Only `generated_at` differs** between two exports of the same data. Everything else comes from database rows written at import time and by the included analysis run. Findings are sorted by (`rule_namespace`, `rule_id`), evidence by (`file_offset`, `pattern_id`, `raw_json_pointer`), steps by index.
- Before export, Bytasm re-hashes the stored sample file, the stored import adapter result, and the stored raw output of every step of the included analysis run. If any no longer matches its recorded SHA-256, the export is refused (HTTP 409) and nothing is written.
- The report file is stored and served by its own SHA-256 (`X-Bytasm-Report-SHA256` header on download).
- To reproduce the metadata independently, run `bytasm inspect` on the same fixture: sections, entropy values, imports, exports and header fields match.

## Top-level fields

| Field | Content |
|---|---|
| `report_kind`, `schema_version` | `bytasm.sample_version_report`, `3` |
| `generated_at` | UTC timestamp of this export (the only varying field) |
| `generator` | `bytasm`, its version, `source_revision` (`git describe`, `-dirty` if uncommitted), `image_id` (null when run natively) |
| `sample` | Project and sample names, version label, `sha256`, `size_bytes`, `format` (from the bytes), `declared_filename` (marked `untrusted_as_uploaded`), `blob_sha256_verified_at_export: true` |
| `input_policy` | `admitted_under` (`fixture_manifest` or `self_built_optin`), the manifest entry, and the input-policy notice |
| `authorization` | `type: self_attestation`, basis (`owned_or_built`), statement, timestamp, and the "not proof of permission" notice |
| `analysis` | The run (status, profile snapshot, Bytasm version, times) and its tool invocation: LIEF version, adapter and version, exit code, duration, `result_sha256` of the raw adapter output, `execution: separate_resource_limited_process` |
| `metadata.declared_in_header` | Architecture, bitness, endianness, entry point, and format-specific header fields, **as declared** |
| `metadata.sections[]` | Name, type, offsets, sizes, flags, and `entropy {value, unit: bits_per_byte, method, computed_by, measured_over: section_bytes_in_file, note}` |
| `metadata.imports`, `exports`, `warnings` | As reported by the adapter |
| `pattern_analysis` | The newest analysis run of this version whose status is `succeeded` or `partial` (blueprint J8), or `null` if there is none. Failed and cancelled runs are never reported. See below. |
| `labels` | What each kind of value means (declared vs measured, untrusted text, pattern analysis) |
| `limitations` | Static only, not executed; header values unverified; entropy is not a verdict; no verdict or score; self-authored inputs only; the parser process is not a sandbox; pattern matches are observations; single-version exports contain string counts only, while comparison exports warn that changed string values and analyst text may be included |

## `pattern_analysis` (version 2)

| Field | Content |
|---|---|
| `run` | `id`, `status` (`succeeded` / `partial`), `failure_reason`, `status_message` (for `partial`: which steps did not complete and that missing YARA-X results say nothing about absent patterns, blueprint 7.3), the frozen `profile`, `bytasm_version`, `queued_at`, `started_at`, `finished_at` |
| `steps[]` | Per step, in order (`strings`, `yara-x`): `status` (`succeeded`, `failed`, `timed_out`, `cancelled`, `skipped`), fixed `message`, tool and adapter versions, `duration_ms`, `result_sha256` of its stored raw output (null if the step kept nothing), `execution: separate_resource_limited_process` |
| `rule_set` | `tool: yara-x`, `name`, `version`, `sha256` of the exact rule text, `source: bytasm-repo`, `rule_count` |
| `strings` | `encodings`, `min_length`, `total_found`, `found_by_encoding`, `stored`, `truncated`, `values_included: false`; null if the strings step did not succeed. **String values are not exported**: they are untrusted text from the file and can be long; they stay in Bytasm (Strings tab, `GET /sample-versions/{id}/strings`). |
| `findings[]` | `kind: yara_match`, `tool: yara-x`, `tool_version`, `rule_id`, `rule_namespace`, `title` (the rule's description), `tags`, `metadata` (as YARA-X reported them), `fingerprint`, `match_count`, `evidence_truncated`, and `evidence[]` (at least one): `kind: byte_range`, `pattern_id`, `file_offset`, `length`, `xor_key`, `excerpt_hex` (at most 32 bytes, equal to the file's bytes at that offset), `excerpt_truncated`, `raw_json_pointer` (into that step's raw output) |
| `notices` | What a match means and does not mean |

There is no verdict, risk score, severity, or "malicious/safe" field, and adding one would break the schema.

## Version 3 additions

An ordinary export has `scope: {kind: "sample_version", version_ids: [id]}`,
`annotations` containing current analyst revisions and `comparison: null`.
Use `POST /sample-versions/{b}/reports?compare_with={a}` for a same-sample
comparison: scope names both versions, annotations cover both, and comparison
contains the full changed-key result. Repeated occurrence displays are capped
at 20 with explicit totals; comparison equality uses the full stored groups.

Annotation snapshots contain author, kind, text, confidence, revision and
validated finding/evidence citation references. They are separate from tool
findings. Prior revisions remain in application history. Comparison exports
may include changed extracted strings; single-version exports keep counts only.
Both sample blobs, selected outputs, rule snapshots and citation source outputs
are verified before export. Missing or incompatible analyses remain explicit.

The former published schema is preserved at
[`schemas/report-v2.schema.json`](../schemas/report-v2.schema.json). Existing
stored reports keep their bytes and download URLs. Consumers must check
`schema_version` before requiring the new fields. New exports use schema 3;
there is no automatic rewrite of older reports. See the
[v0.3 milestone](milestones/v0.3-compare-annotate.md) for contracts and limits.
