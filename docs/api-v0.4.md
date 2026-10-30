# v0.4 API additions

Base: `/api/v1`. Existing loopback, Host, Origin, request-header and admission
guards remain mandatory. OpenAPI is generated from the typed response/request
models; the TypeScript client mirrors these contracts.

| Method and path | Contract |
|---|---|
| `GET /tools` | Read-only tool/version/adapter/availability/formats/rules SHA/limitations registry and two built-in profiles. Does not open a sample. |
| `POST /sample-versions/{id}/runs` | `profile_id` is `default-static` (Quick) or `full-static` (adds capa). No custom steps/commands/rules are accepted. Returns queued run; the worker executes it. |
| `GET /runs/{id}` | Step statuses, raw-output SHA references, exact tool/adapter versions, preserved result counts and deterministic English summary. |
| `GET /runs/{id}/findings` | Optional exact `tool` (`yara-x`, `capa`), `kind` (`yara_match`, `capability`), literal bounded `q` (128 characters) and exact `namespace` (128 characters). Response echoes filters and pre-filter total. Existing bounded rule/evidence caps apply. |
| `GET /invocations/{id}/raw` | Existing explicit download, hash-verified. For capa: original bounded CLI JSON, not a fabricated Bytasm/capa hybrid. Never a sample-byte download. |
| `GET /sample-versions/{id}/reports` | Immutable history, `offset` 0–1,000,000, `limit` 1–100 (default 25), newest timestamp then ID; items include ID, hash, date, scope, format and `next_offset`. |
| `POST /sample-versions/{id}/reports` | Existing create-snapshot path, schema 4; optional same-sample `compare_with` scope. Validates provenance before storing canonical JSON. |
| `GET /reports/{id}/html` | Verified schema 4 snapshot → escaped standalone HTML; attachment by default, `download=false` inline. Old JSON download path is unchanged. |
| `GET /health` | Adds installed `capa_version`, heartbeat `worker_state` (`absent`, `present`, `stale` after 15 seconds). No filenames, sample data or filesystem paths. Not a full storage-integrity audit. |

Full order: strings, YARA-X, capa. capa supports native PE x86/x64 only;
unsupported file types get `unsupported`, a missing/mismatched pinned tool gets
`unavailable`, invalid/nonzero child output gets `failed`; timeouts/cancellation
remain distinct. Only validated successful output is persisted. Earlier steps
survive later problems; the run is `partial` if at least one step preserved a
result and another did not. User cancellation takes terminal precedence.

capa findings carry a rule namespace, exact original source and rule-supplied
ATT&CK/MBC labels. Evidence has `kind: virtual_address`, `virtual_address`,
`file_offset: null`, `length: null`, and the pointer into original capa JSON.
No function names, file offsets or executed behavior are inferred. Existing
annotations/citations accept these finding/evidence IDs with the same scope
checks and immutable revisions. Project run/annotation activity is unchanged.
Comparison adds `capabilities` with exact tool/adapter/rules/args compatibility.

See [report format](report-format.md), [v0.4 limits](milestones/v0.4-deeper-analysis-sharing.md)
and [dependency notices](../THIRD_PARTY_NOTICES.md). Corpus search, generic
integrity/backup/restore endpoints and user-editable profiles are not exposed.

`GET /rule-sets/{id}` also returns historical capa snapshots with their true tool,
source, original files and installed tool version. `virtual_address_hex` provides
an exact lowercase hexadecimal string for JavaScript displays above 2^53; the
integer `virtual_address` remains available for exact-integer JSON consumers.

## Post-PR6 additive review contracts

- `RunOut.review`: template version, version/run IDs, total/cap flag, at most 12
  observations with at most three source locations/pointers each, exact tool /
  adapter / rules provenance, evidence cap flag and internal source links.
- `GET /reports/{id}/review`: the same bounded view derived from a hash-verified,
  schema-validated schema 4 snapshot; missing is 404, corrupt is 409 and legacy
  schema views are unsupported (422). JSON downloads are unchanged.
- Strings: allowlisted `category=url_like|path_like|other` and
  `sort=offset|length|value|category`; counts are selected-run stored observations
  before filters. `value` orders retained prefixes, `length` decreases full
  recorded length. Pagination remains <=200 rows, deterministic ties; run_id
  stays scoped to this version. Oversized (>5,000) persisted sets are refused.
- Each string includes heuristic category and an optional unique fully-containing
  raw section reference. No address is derived; metadata invocation identifies
  the section source. Categories are not findings or confirmed meanings.
- Section metadata adds import-invocation identity and exact address/size display
  strings. Header overview adds exact display representations for integer values.
  These are declarations; no new parser formats/fields or report-schema changes.

## Optional-provider metadata diagnostic

`GET /tools` adds `optional_providers`, without changing the four existing tool
entries or the two built-in profiles. Ghidra diagnostics contain `provider`,
`status`, a fixed safe `message`, `declared_ghidra_version` (12.2 or null),
`declared_java_major`, `verification: metadata_only`, `health_check: not_run`,
`available: false` and `analysis_enabled: false`. Status is one of
`not_configured`, `installation_invalid`, `unsupported_version`, `java_missing`,
`java_incompatible`, `unsupported_host` or `execution_unavailable`. Missing or
unreadable/invalid files are reported without filesystem paths or raw exceptions.
Versions are metadata declarations, not the result of launching a tool.

Configuration is local/startup-read only; no new endpoint accepts installation
paths, commands, script choices or an availability override. There is no Ghidra
analysis, function-detail or report endpoint. Provider health/launch failure and
function results remain blocked pending real offline integration, not simulated.
