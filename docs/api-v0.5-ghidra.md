# Ghidra static review API

Existing local request/Host/Origin guards apply. There are no accounts or remote
authorization claims: every resource is scoped through its retained run, sample
version and project. Keep the service on localhost. All text is hostile plain
text. No request can change admission, tool roots, scripts or profile options.

- GET /api/v1/tools: optional_providers distinguishes metadata from actual
  no-sample health and offline-worker analysis availability. Only a functioning
  worker exposes ghidra-static in profiles.
- POST /api/v1/sample-versions/{version}/runs with profile_id=ghidra-static:
  verifies effective worker health, existing admission, size and content hash;
  stores a version 1 profile/script digest snapshot in a queued run. Unavailable
  provider returns503/provider_unavailable without queueing. Existing run/cancel
  endpoints and worker lifecycle apply.
- GET /api/v1/runs/{run}/ghidra: typed summary, provenance, function counts,
  step/run state and coverage completed/total(1). Failed/missing output has
  available=false,function_count=null and no fabricated observations.
- GET /api/v1/runs/{run}/ghidra/functions?q=&offset=0&limit=50: case-insensitive
  identity substring (name, namespace, address), query max128 characters,
  offset0..1024, limit1..100. Stable
  indices refer to the exact bounded stored inventory; total and matched differ.
- GET /api/v1/runs/{run}/ghidra/functions/{index}: exact stored function,
  instructions, pseudocode status, direct call addresses, truncation flags and
  raw-output JSON-pointer citation. An inventory-only function is not analyzed
  by this read operation. No names or addresses become file offsets.
- GET /api/v1/runs/{run}/ghidra/export?format=json|html: separate canonical
  bytasm-ghidra-report-1 (legacy analysis) or bytasm-ghidra-report-2 attachment
  with CSP/nosniff for HTML. Hash/identity/schema
  mismatches return409/integrity_error and no evidence content. No completed
  Ghidra output returns404, not an empty success.
- GET /api/v1/invocations/{id}/raw: existing explicit validated-output download.

Every Ghidra read/export revalidates the2MiB bounded stored document and exact
provenance. Array/string/identity bounds are defined in ghidra-analysis.schema.json
and enforced again in the worker. The OpenAPI document is available locally at
/api/openapi.json. No Ghidra comparison/annotation-write API or editable profile
is exposed. Existing annotations and baseline comparison endpoints are unchanged.


## v0.6 discovery and explicit inspection

`GET /runs/{run}/ghidra/functions` accepts `field=all|name|namespace|address`,
`exact=true|false`, `external=true|false`,
`pseudocode=available|not_selected|failed`, and `has_calls=true|false`.
Search is case-insensitive and covers retained identity text only; an exact
match of a truncated name is not proof of its original full name. `has_calls`
means retained direct call records, never proof that a function makes no calls.
Order is lexicographic address-space/address text, with original record indices
preserved for citations. Ordering is deterministic, not a numeric address sort.

Pages return `next_cursor`, `scope_sha256`, `identified`, `inventory_complete`
and `functions_truncated`. Cursor requests use `cursor=...` and offset zero.
The cursor binds project, version, sample hash, run, invocation, output digest,
Ghidra/profile/script identities, filters and page size. Cursors are bounded
checksummed scope tokens, not authentication credentials or secret signatures.
Wrong/malformed/query-mismatched tokens return 422; every page independently
revalidates its source. Page JSON is capped at 512 KiB. A zero search result only
means no retained record matched. No read invokes Ghidra.

`POST /runs/{source}/ghidra/inspections`, body `{"indices":[16,17]}`, records an
explicit selected-function job. One to eight unique integer indices must exist
in the verified source inventory. Names/addresses/options/scripts supplied by a
client are not accepted. Fresh successful worker health is required. The source
must have current compatible script/profile identities; historical output stays
readable but incompatible selection returns 409/ghidra_incompatible. The response
is 202 with `run_id`, `source_run_id`, `reused`. Exact requests share active or
succeeded jobs; cancelled/failed jobs can be retried. Another active version job
returns 409/run_active. The same request in another project never shares a run.

Selected jobs reuse the existing run status/cancel endpoints and worker lifecycle.
They perform a fresh bounded Headless import with private project/preferences;
there is no persistent program cache and no full-program decompilation request.
The source remains immutable. Snapshot/provenance records include selected exact
address-space pairs and source run/output identity. Export the selected run to
retain its detail evidence and source link. External functions may have no
implementation pseudocode. A run can fail or time out without retained details.

`GET /runs/{run}/ghidra/functions/{index}/relationships` expands one retained
static call hop. `node_limit=2..33`, `edge_limit=1..64` (defaults 33/32). Edges
include original source function index, exact call-site/target addresses,
`direct_static_call` type and raw-output pointer. Targets link to inventory only
on an exact address-space/entry match; interior/unknown targets remain unresolved.
Incoming calls cover retained instruction windows only. `truncated` describes
view limits, `inventory_complete` the inventory and `reference_windows_complete`
the stored instruction/call windows. None certifies a complete program graph.

The overview adds retained pseudocode/failed-detail/instruction/call counts,
inventory state, selected entries and source provenance. Its sole selected tool
is Ghidra; it does not imply strings/YARA-X/capa ran in that run. A missing output
has unknown function count, never zero. No behavioral hypothesis is added.
