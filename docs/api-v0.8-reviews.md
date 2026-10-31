# Pinned review and function-overlay APIs

All routes are local `/api/v1`; mutations require `X-Bytasm-Request: 1`.
No request changes runtime, admission or tool commands.

| Route | Contract |
|---|---|
| POST `/sample-versions/{id}/reviews` | `{scope: "combined"}` (default) or `{scope: "exact_run", run_id}`. Returns new immutable `bytasm-review-1`, HTTP 201. Cross-version run IDs return 404. |
| GET `/sample-versions/{id}/reviews?offset=0` | 25 bounded identity/time/digest records, `next_offset`. |
| GET `/reviews/{id}` | Digest-verified canonical stored snapshot; no live reselection. |
| POST `/reviews/{id}/refresh` | Appends a snapshot with `supersedes_id`; retains scope. No old mutation. |
| POST `/reviews/{id}/export/preview` | Policy → exact derivative document, canonical JSON digest and byte size. |
| POST `/reviews/{id}/export/json` | The exact canonical derivative; attachment SHA-256 header. |
| POST `/reviews/{id}/export/html` | Escaped standalone semantic report of the same derivative; restrictive CSP, no active content. |
| GET `/sample-versions/{id}/bytes?offset=0&length=256` | Digest-verified file-offset window, hex/printable text, actual length/EOF; 1..4096-byte request. |
| GET `/runs/{id}/ghidra/functions/{index}/review` | Exact scope, latest overlay and 25 latest immutable revisions; `history_capped`. Requires verified source output. |
| POST same function route | Expected revision, alias, bookmark, collections, state, note, optional exact pseudocode citation; HTTP 201 or stale-revision 409. |

Published schemas: `schemas/review.schema.json`, `schemas/review-export.schema.json`.
Canonical JSON uses the established sorted-key, indented UTF-8/ASCII-escaped form.

Privacy policy booleans: `overview`, `observations`, `technical_details` default
true; `string_values`, `original_names`, `analyst_notes` default false;
`mask_sensitive_values` defaults true. Unknown controls are refused, not ignored.
Raw outputs and pseudocode/symbols are outside this export contract. Analyst notes
means current function overlays captured from the selected Ghidra source; ordinary
version/finding annotations and past revisions remain excluded.

A snapshot's selected source has run/invocation IDs, tool/adapter versions,
rule digest where relevant, full profile/parameters, output digest, recorded
retention and warnings. Latest attempts are captured separately at pin time.
All identities are scoped to the same exact version/hash/size. `verified_at_creation`
is not a claim of current integrity after files change on disk.

Relevance version `review-2` prioritizes reviewed capa code features (30), reviewed
URL text (20), UPX-style structural context (15), other declaration text (5/1), then
unreviewed matches (0). Scores only choose reading order. Repeated matches receive
no additional weight. Import categories are separately labelled as declarations.
