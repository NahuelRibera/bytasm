# Evidence correlation API (v0.10)

Read-only endpoints. They correlate observations already stored for one
sample version. They never start a tool, execute a sample, or change a run or
a pinned review. Types: `frontend/src/evidence-api.ts`. Models:
`backend/src/bytasm/evidence_graph.py`, `evidence_understand.py`,
`api/evidence.py`.

## Scope and run selection

Every endpoint accepts two optional query parameters:

| Parameter | Meaning |
|---|---|
| `ghidra_run_id` | A `ghidra-static` run of **this** version whose Ghidra step succeeded. |
| `analysis_run_id` | A `default-static` or `full-static` run of **this** version that ended `succeeded` or `partial`. |

Without a parameter, the newest qualifying run is used
(`latest-completed-per-source-v1`). A run ID from another version, the other
profile family, or an unfinished/failed run returns `404`; nothing is
substituted. Newer runs that were not selected are listed in
`scope.sources[].newer_unselected_run_ids` (at most 16). The import record's
LIEF metadata is always the structural source.

`scope.scope_sha256` digests the graph schema, version, input hash, import
invocation/output, Ghidra run/invocation/output and pattern run/step
identities. Cursors are bound to it. The graph for a scope is cached
in-process (8 scopes, LRU). Only terminal runs can be selected, so a scope's
inputs cannot change.

## `GET /api/v1/sample-versions/{version_id}/evidence` — Understand

Returns `scope`, `counts`, `coverage`, `claims` (at most 64, plus
`claims_total` / `claims_truncated`), `layout`, `limitations` and `build_ms`.

### Claims

```json
{
  "id": "claim:…",
  "kind": "capa_rule_at_function",
  "title": "Code refers to reading a file",
  "summary": "capa reported a rule match located at the function that starts at ram:140001450. …this does not show that the code ran.",
  "technical": "capa 10.0.0 rule match at VA 0x140001450; declared PE section mapping gives file offset 0x850, equal to the Ghidra memory-map offset of function entry ram:140001450.",
  "subjects": ["finding:…", "function:…"],
  "evidence": ["edge:…"],
  "sources": [{"tool": "capa", "run_id": "…", "invocation_id": "…", "output_sha256": "…", "pointer": "/rules/…"}],
  "interpretation": "File reads can supply application data or configuration.",
  "alternatives": "File reads are routine in ordinary applications.",
  "limitations": ["A rule match is a static observation, not a verdict or runtime event.", "…"],
  "completeness": {"state": "complete_within_retained_windows", "notes": []},
  "navigate": {"node_id": "function:…", "href": "/api/v1/sample-versions/…/evidence/nodes/function:…"},
  "reading_weight": 25
}
```

Claim kinds and their only permitted evidence:

| Kind | Built from edge type(s) |
|---|---|
| `capa_rule_at_function` | `capa_match_at_function_entry` |
| `entry_point_function` | `entry_point_is_function` |
| `yara_match_in_function` | `yara_match_in_function_body` |
| `function_references_external_symbols` | `references_external_symbol` (+ `external_symbol_named_as_import`) |
| `function_references_strings` | `references_string` (+ `target_is_string_occurrence`) |

`title`, `interpretation` and `alternatives` come from the reviewed
interpretation catalog only when `bytasm.review.explanation` accepts the exact
tool/version/rule/ruleset combination; otherwise the title is "Static rule
match needs review" and both are `null`. Untrusted text (symbol names, string
values) never appears inside `title`, `summary` or `technical`. It is
returned as subject node labels. `reading_weight` orders reading only and is
not a risk score. Claim IDs depend on tool identity, not database row IDs, so
the same evidence gets the same claim ID in another database.

`completeness.state`: `partial` when the Ghidra inventory was capped or timed
out; `bounded` when the subject function's instruction, reference, call or
body-range windows were capped, or only inventory data was retained;
otherwise `complete_within_retained_windows`. This never claims the binary
was fully analyzed.

### Coverage

`steps[]` lists every selected step with its real status. `joins[]` reports
each join type: `performed`, `reason` when it was not performed,
`candidates`, `joined`, and `not_joined` counts keyed by translation state.
Coverage reports counts only where both sides are known. For example,
"`functions_with_capped_windows` of `functions_with_detail_windows`" has a
denominator. It never reports a global completion percentage.

| Join | Performed only when |
|---|---|
| `calls`, `references` | a Ghidra run is selected |
| `string_occurrence` | Ghidra output is `ghidra-4` and the pattern run has a succeeded strings step |
| `capa_function` | `ghidra-4`, PE file, declared PE image base |
| `yara_body` | `ghidra-4` |
| `entry_point` | `ghidra-4` and a declared entry point |
| `import_name` | the import record declares imported functions |
| `section` | LIEF parsed sections with file bytes |

### Layout

`layout.sections[]` holds the declared LIEF sections (file range, declared
absolute VA, flags) with `contains`: graph nodes per kind located inside each
section by file offset. `layout.ghidra_blocks[]` (ghidra-4 only) holds
Ghidra's loaded memory blocks with `rwx` permissions and whether each block
is file-backed. Both are ready for a section map. They are two sources and
are deliberately not merged.

## `GET …/evidence/nodes` — Investigate

Query: `kind`, `q` (case-folded substring of label or address text, ≤128),
`limit` 1–200 (default 50), `cursor` or `offset`. Sort order: kind (fixed
order `entry_point, section, function, finding, external_symbol, import,
program_data, string`), address space, numeric address, file offset, identity.
A cursor is bound to scope, kind, `q` and limit; reusing it with other
parameters, or combining it with `offset`, returns `422`.

## `GET …/evidence/edges`

Query: `type`, `limit` 1–200 (default 100), `cursor` or `offset`. Sorted by
type, then source and target sort keys.

## `GET …/evidence/nodes/{node_id}`

The node, up to 256 incident edges (`edges_total`, `edges_truncated`), the
neighbor nodes of the returned edges, and the IDs of claims citing the node.
Optional `edge_type` filter. Responses over 1 MiB return `report_too_large`.

## Node and edge reference

Node fields: `id` (`kind:` + 20 hex characters of a SHA-256 over kind and exact
identity), `kind`, `label` (untrusted), `identity`, `address` (Ghidra space and
text, never a file offset), `file_offset`, `file_offset_basis`,
`file_offset_state`, `attributes`, `sources` (locators).

| Node kind | Identity | Source |
|---|---|---|
| `function` | Ghidra entry space and address (+ index) | Ghidra |
| `program_data` | Ghidra target space and address (`data_kind`: string or data) | Ghidra |
| `external_symbol` | resolved external target, or the reference target | Ghidra |
| `string` | file offset and encoding | strings step |
| `finding` | tool, namespace and rule ID (`finding_id` kept) | YARA-X / capa |
| `section` | section index | LIEF |
| `import` | function name | LIEF |
| `entry_point` | declared VA | LIEF |

Function attributes (all from the retained Ghidra record): `body_size`
(Ghidra address count), `body_range_count`, `detail_state`,
`retained_instructions`, `retained_calls`, `retained_references`,
`reference_kinds`, `retained_incoming_calls` (direct calls from retained
windows that target this exact entry), and every `*_truncated` flag.
These are counts within retained windows, not complexity metrics of the
program.

| Edge type | Strength | Rule |
|---|---|---|
| `calls` | exact_reference | Ghidra direct call whose target equals an inventory entry (same space) |
| `references_string` / `references_data` / `references_external_symbol` | exact_reference | Ghidra instruction reference; thunk resolution adds basis `ghidra_function_thunk` and keeps `original_target` |
| `target_is_string_occurrence` | exact_offset_equality | Ghidra string target → Ghidra memory map → offset equals a strings-step occurrence start |
| `capa_match_at_function_entry` | exact_offset_equality | capa VA → LIEF PE section declaration (VA − ImageBase = RVA) and Ghidra entry → Ghidra memory map give the same file offset, and exactly one function matches |
| `yara_match_in_function_body` | address_containment | YARA-X match first byte → Ghidra memory map (exactly one address) → inside a retained body range |
| `entry_point_is_function` | exact_offset_equality | declared entry VA → LIEF sections, and function entry → Ghidra map, are equal |
| `located_in_section` | structural_containment | file offset inside exactly one section's file bytes (PE: `min(SizeOfRawData, VirtualSize)`) |
| `external_symbol_named_as_import` | name_equality | Ghidra `LIBRARY::name`: exact name equals a LIEF import, and for PE the library matches case-insensitively; for ELF the namespace must be `<EXTERNAL>`. A coarse association, never an address join. |

Repeated observations of one relation become one edge: `locator_count`
counts them, and at most 8 `locators` are retained (`locators_truncated`).
A locator `pointer` is an RFC 6901 pointer into the invocation's raw output,
or `row:<table>/<id>` for a row persisted from that output.

## Translation states

`mapped`, `not_file_backed` (inside a known region without file bytes, such
as `.bss`), `outside_known_regions`, `ambiguous` (more than one distinct
answer; none is chosen), `unsupported_address`, `unavailable` (required
source absent, e.g. a historical `ghidra-3` output). Only `mapped` carries a
value. No other state is evidence of absence.
