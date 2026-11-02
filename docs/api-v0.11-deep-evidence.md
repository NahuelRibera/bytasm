# API v0.11: pinned evidence, comparison, structure and function structure

All endpoints are read-only, local-only (`/api/v1`, loopback, the existing request
guards) and return RFC 9457 problems from the fixed table in `api/problems.py`.
Nothing here runs a tool, reads sample bytes beyond verified stored outputs, or
changes admission. TypeScript types: `frontend/src/evidence-history-api.ts`
(data only, imported by nothing yet).

Untrusted text rule (unchanged from v0.10): node `label`, symbol `name`, dynamic
`text`, string values and every string inside `attributes`, `before` and `after`
come from the file or a tool. Render them as escaped text. Generated sentences
(`statements[].text`, claim summaries) never interpolate them.

## 1. Pinned evidence of a review

### `GET /reviews/{review_id}/evidence`

Summary of the immutable evidence snapshot a review pinned. Works for every review
schema; historical reviews report why there is no snapshot.

```json
{
  "review_id": "4c1e…",
  "review_schema": "bytasm-review-3",
  "evidence": {"state": "captured", "reason": null},
  "snapshot_schema": "bytasm-evidence-snapshot-1",
  "algorithm": "bytasm-evidence-graph-2",
  "content_sha256": "3e53…",
  "content_verified": true,
  "scope_sha256": "bb83…",
  "sample": {"version_id": "…", "sample_id": "…", "sha256": "…", "size_bytes": 14336, "format": "PE"},
  "sources": [
    {"source": "ghidra", "state": "available", "run_id": "…", "invocation_id": "…",
     "output_sha256": "b409…", "tool_version": "12.2", "protocol_version": "ghidra-5",
     "profile_sha256": "…", "script_sha256": "…",
     "retention": {"function_count": 97, "functions_retained": 97, "functions_truncated": false,
                   "analysis_timed_out": false, "detailed_functions": 16, "memory_blocks_truncated": false}},
    {"source": "capa", "state": "unavailable",
     "unavailable_reason": "No completed pattern run was selected.", "run_id": null}
  ],
  "address_mapping": {"declared_image_base": 5368709120, "ghidra_protocol": "ghidra-5",
                      "ghidra_memory_map": "available", "ghidra_image_base": {"space": "ram", "address": "140000000"},
                      "ghidra_rejected_file_ranges": 0, "ghidra_map_truncated": false},
  "coverage": [{"join": "import_slot", "performed": true, "reason": null, "candidates": 88,
                "joined": 32, "not_joined": {"lief_slot_without_ghidra_pointer": 4, "no_import_slot_at_offset": 56}}],
  "counts": {"nodes": {"external_symbol": 32, "function": 97, "import": 32, "…": "…"},
             "edges": {"external_symbol_import_slot": 32, "…": "…"}, "strengths": {"…": "…"}},
  "bounds": {"max_nodes": 4096, "max_edges": 8192, "max_bytes": 1572864, "nodes_total": 227,
             "nodes_retained": 227, "truncated": false, "omitted_nodes_by_kind": {}, "…": "…"},
  "limitations": ["Relationships are static correlations of stored tool outputs; …"]
}
```

`evidence.state`:

| state | meaning |
|---|---|
| `captured` | The review carries a snapshot; `content_verified` recomputes its digest. |
| `unavailable` | A review-3 review that could not capture one (`reason`: no import record, byte bound, or the 4 MiB review cap). |
| `not_captured_historical` | A `bytasm-review-1`/`-2` review. No graph is reconstructed, because current sources and algorithms may differ from those at pin time. |

### `GET /reviews/{review_id}/evidence/nodes` · `…/edges` · `…/nodes/{node_id}`

Same parameters and cursor semantics as the v0.10 live endpoints
(`kind`, `q`, `type`, `edge_type`, `offset` | `cursor`, `limit` ≤ 200; neighborhoods
≤ 256 edges; node detail ≤ 1 MiB). Items are `SnapshotNode` / `SnapshotEdge`:
the v0.10 node/edge shape plus `label_truncated`, `sources_total`, and locators
capped at 4. Cursors bind to the snapshot's `content_sha256`.
A review without a snapshot answers **409 `evidence_not_captured`** with
`"evidence": {state, reason}` in the problem body. A snapshot whose content no
longer matches its digest answers 409 `integrity_error`.

## 2. Evidence comparison

### `GET /evidence/compare`

| parameter | value |
|---|---|
| `a`, `b` (required) | `version:<32 hex>` (the version's current graph, built with the live `latest-completed-per-source-v1` selection) or `review:<32 hex>` (the pinned snapshot, never recomputed) |
| `a_ghidra_run_id`, `a_analysis_run_id`, `b_…` | Optional explicit run selection for a `version:` side; 422 for a `review:` side |
| `category` | `node` \| `edge` |
| `change` | `added` \| `removed` \| `modified` \| `not_comparable` \| `unchanged` |
| `kind` | node kind or edge type |
| `attribution` | see below |
| `offset` \| `cursor`, `limit` (1–200, default 50) | pagination over the deterministic change list |

Both sides must belong to the same project (422 otherwise). Unknown IDs: 404.
A review without a snapshot: 409 `evidence_not_captured`. Results are cached per
(scope, content) pair; the response is capped at 4 MiB.

Response: `{comparison, changes, build_ms}`.

`comparison` (summary, identical for every page):

- `a`, `b`: side kind (`version_current` / `pinned_review`), version, review,
  sample digest, algorithm, `scope_sha256`, `content_sha256`.
- `binary`: `identical` (same SHA-256), sizes, formats, `same_sample`.
- `environment[]`: per source, `state_a/b`, `differing_fields` among
  `tool_version, adapter_version, protocol_version, rule_set_sha256,
  profile_sha256, script_sha256`, retention flags, and `comparability`:
  `comparable` | `environment_differs` | `coverage_differs` | `unavailable_on_both`,
  with a reviewed `explanation`.
- `coverage[]`: per join, performed and joined on each side; `comparable` only
  when evaluated on both.
- `mapping`: declared and Ghidra image bases, memory-map states and
  `addresses_comparable` (true only for identical bytes and Ghidra environment).
- `correspondence[]`: per node kind and matching method, matched and unmatched
  counts and the method's limitation.
- `counts`: changes by kind for nodes and edges, by attribution, and
  `exact_joins_established` / `exact_joins_lost`.
- `statements[]`: reviewed comparative sentences with cited change IDs (≤ 16 each,
  `cites_total`).
- `review_candidates[]`: change IDs that deserve manual inspection (findings,
  functions, imports, external symbols or exact joins that changed under comparable
  coverage). A reading aid, not a severity.
- `incomparable[]`, `limitations[]`, `comparison_sha256`.

`changes.items[]`:

```json
{
  "id": "change:5a0e…",
  "category": "node",
  "kind": "import",
  "change": "added",
  "attribution": "binary_difference_under_comparable_coverage",
  "match_method": null,
  "correspondence_key": "import_name:getenv",
  "required_sources": ["lief", "ghidra"],
  "changed_fields": [],
  "reason": "Observed under comparable coverage: the producing sources ran on both sides with the same tool identity and configuration, and the files differ.",
  "exact_join": false,
  "before": null,
  "after": {"id": "import:…", "kind": "import", "label": "getenv", "…": "…"}
}
```

Attributions:

| attribution | meaning |
|---|---|
| `identical_input` | Same bytes and tool environment. |
| `comparable_coverage` | Unchanged under comparable coverage of different files. |
| `binary_difference_under_comparable_coverage` | Every producing source ran on both sides with identical identity and configuration, and the files differ. The only attribution that points at the file. |
| `analysis_environment_difference` | A producing source's tool, adapter, protocol, rules, profile or script differs. |
| `source_output_difference` | Same bytes and identity, different stored output. |
| `coverage_difference` | A required source or join is missing on one side (`change` is then `not_comparable`). |
| `retention_bound` | The side without the observation had a capped window or snapshot bound. |
| `no_stable_correspondence` | No matching method applies (`not_comparable`). |

Matching methods and their limits are listed in `evidence_compare.py` and in
`docs/milestones/v0.11-deep-evidence.md` §4.

## 3. Deep structure

### `GET /sample-versions/{version_id}/structure`

Without `table`: header scalars plus the first 50 rows of each table. With
`table=<name>&offset&limit` (≤ 500): one table page. Tables:
`import_slots`, `structural_observations`, `pe.sections`, `pe.data_directories`,
`pe.import_descriptors`, `pe.exports`, `pe.debug_entries`, `elf.segments`,
`elf.dynamic_entries`, `elf.dynamic_symbols`, `elf.notes`. Each carries its
`provenance` (declared, parsed, verified range, derived).

Imports made before metadata adapter 0.3.0 answer
`{"state": "unavailable", "unavailable_reason": "… imported with metadata adapter 0.2.0, which predates the deep structural tables (0.3.0). They are not reconstructed …"}`.
A tampered import output answers 409 `integrity_error`.

Example `import_slots` row (real `hello_v1-x86_64.elf`):

```json
{"library": null, "name": "puts", "name_truncated": false, "ordinal": null, "hint": null,
 "slot_rva": null, "slot_virtual_address": 16384, "slot_file_offset": 12288,
 "slot_basis": "lief_elf_relocation_load_segment", "relocation_type": "X86_64_JUMP_SLOT"}
```

## 4. Function structure (ghidra-5)

### `GET /runs/{run_id}/ghidra/functions/{index}/structure`

`state`: `available` | `not_selected` (inventory-only function) | `not_captured`
(protocol before ghidra-5; `reason` says a new run is required). Fields: entry,
body ranges, `basic_block_count` (+`_capped`), `instruction_count` (+`_capped`),
`basic_blocks[]` (`start`, `end` inclusive, `instruction_count`, `terminal`,
`flows[]` with `kind` `fallthrough|conditional_jump|unconditional_jump|computed_jump`,
`target` or null, `internal`), `flow_counts` (`kind:internal|external`),
`call_sites[]` (`kind` `direct|indirect`, `target` or null, `target_basis`,
`resolution` `inventory_function|outside_inventory|unresolved`, the target's inventory
index and name when exact), `thunk_target`, `pointer_slots`, `citation`,
`limitations`. Unresolved indirect calls and computed jumps keep `target: null`.

## 5. Changed contracts

- Live evidence endpoints report `schema_version: "bytasm-evidence-graph-2"`, two
  new edge types (`external_symbol_import_slot`, strength `exact_offset_equality`;
  `target_within_string_occurrence`, strength `offset_containment`), the
  `import_slot` join in coverage, call edges from ghidra-5 call sites (basis
  `ghidra_call_site`), function structure attributes, YARA edge attributes
  `length` and `last_byte_in_same_body`, and the claim kind
  `import_slots_match_ghidra_pointers`.
- `POST /sample-versions/{id}/reviews` creates `bytasm-review-3` with `evidence`
  and `evidence_status` (schema `schemas/review-v3.schema.json`).
- Review exports of review-3 are `bytasm-review-export-3` with an `evidence`
  block (`schemas/review-export-v3.schema.json`). Nodes and edges are included only
  when `technical_details`, `original_names` and `string_values` are all true.
- Ghidra runs emit `ghidra-5` (`schemas/ghidra-analysis-v5.schema.json`); the
  function detail endpoint returns the new fields with defaults for older protocols.
- New problem code `evidence_not_captured` (409).
