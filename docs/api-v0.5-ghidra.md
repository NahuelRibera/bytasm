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
  name substring, query max128 characters, offset0..256, limit1..100. Stable
  indices refer to the exact bounded stored inventory; total and matched differ.
- GET /api/v1/runs/{run}/ghidra/functions/{index}: exact stored function,
  instructions, pseudocode status, direct call addresses, truncation flags and
  raw-output JSON-pointer citation. An inventory-only function is not analyzed
  by this read operation. No names or addresses become file offsets.
- GET /api/v1/runs/{run}/ghidra/export?format=json|html: separate canonical
  bytasm-ghidra-report-1 attachment with CSP/nosniff for HTML. Hash/identity/schema
  mismatches return409/integrity_error and no evidence content. No completed
  Ghidra output returns404, not an empty success.
- GET /api/v1/invocations/{id}/raw: existing explicit validated-output download.

Every Ghidra read/export revalidates the2MiB bounded stored document and exact
provenance. Array/string/identity bounds are defined in ghidra-analysis.schema.json
and enforced again in the worker. The OpenAPI document is available locally at
/api/openapi.json. No Ghidra comparison/annotation-write API or editable profile
is exposed. Existing annotations and baseline comparison endpoints are unchanged.
