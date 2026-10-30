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
