// v0.11 deep-evidence contract (docs/api-v0.11-deep-evidence.md). Data only:
// no component imports this yet, so the Engraved Signal UI can adopt it freely.
// Every `label`, `name`, `text` and `attributes` string from a node is untrusted
// file or tool text: render it as escaped text only.
import { ApiError, type Problem, queryString } from "./api";
import type { EvidenceEdgeType, EvidenceNodeKind } from "./evidence-api";
import type { GhidraAddress } from "./ghidra-api";

export type EvidenceEdgeTypeV2 = EvidenceEdgeType | "external_symbol_import_slot" | "target_within_string_occurrence";
export type EvidenceSourceName = "lief" | "ghidra" | "strings" | "yara-x" | "capa";

export interface SnapshotLocator { tool: string; tool_version: string; run_id: string; invocation_id: string; output_sha256: string | null; pointer: string }
export interface SnapshotSource {
  source: EvidenceSourceName;
  state: "available" | "unavailable";
  unavailable_reason: string | null;
  status: string | null;
  run_id: string | null;
  invocation_id: string | null;
  output_sha256: string | null;
  tool_version: string | null;
  adapter_version: string | null;
  protocol_version: string | null;
  rule_set_sha256: string | null;
  profile_sha256: string | null;
  script_sha256: string | null;
  retention: Record<string, string | number | boolean | null>;
}
export interface SnapshotNode {
  id: string;
  kind: EvidenceNodeKind;
  label: string;
  label_truncated: boolean;
  identity: Record<string, string | number | boolean | null>;
  address: GhidraAddress | null;
  file_offset: number | null;
  file_offset_basis: string | null;
  file_offset_state: string | null;
  attributes: Record<string, unknown>;
  sources: SnapshotLocator[];
  sources_total: number;
}
export interface SnapshotEdge {
  id: string;
  type: EvidenceEdgeTypeV2;
  strength: string;
  source: string;
  target: string;
  basis: string[];
  locators: SnapshotLocator[];
  locator_count: number;
  locators_truncated: boolean;
  attributes: Record<string, unknown>;
}
export interface SnapshotJoin { join: string; performed: boolean; reason: string | null; candidates: number; joined: number; not_joined: Record<string, number> }
export interface SnapshotBounds {
  max_nodes: number; max_edges: number; max_bytes: number;
  nodes_total: number; edges_total: number; nodes_retained: number; edges_retained: number;
  truncated: boolean; omitted_nodes_by_kind: Record<string, number>; omitted_edges_by_type: Record<string, number>;
  retention_order: string[];
}
export type EvidenceAvailability = { state: "captured" | "unavailable" | "not_captured_historical"; reason: string | null };
export interface ReviewEvidence {
  review_id: string;
  review_schema: string;
  evidence: EvidenceAvailability;
  snapshot_schema: string | null;
  algorithm: string | null;
  content_sha256: string | null;
  content_verified: boolean | null;
  scope_sha256: string | null;
  sources: SnapshotSource[];
  coverage: SnapshotJoin[];
  counts: { nodes?: Record<string, number>; edges?: Record<string, number>; strengths?: Record<string, number> };
  bounds: SnapshotBounds | null;
  limitations: string[];
}
export interface SnapshotPage<T> { review_id: string; content_sha256: string; matched: number; offset: number; limit: number; items: T[]; next_cursor: string | null }

export type ComparisonChange = "added" | "removed" | "modified" | "unchanged" | "not_comparable";
export type ComparisonAttribution =
  | "identical_input" | "comparable_coverage" | "binary_difference_under_comparable_coverage"
  | "analysis_environment_difference" | "coverage_difference" | "source_output_difference"
  | "retention_bound" | "no_stable_correspondence";
export interface ComparisonChangeItem {
  id: string;
  category: "node" | "edge";
  kind: string;
  change: ComparisonChange;
  attribution: ComparisonAttribution;
  match_method: string | null;
  correspondence_key: string | null;
  required_sources: EvidenceSourceName[];
  changed_fields: string[];
  reason: string;
  exact_join: boolean;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}
export interface EvidenceComparison {
  comparison: {
    schema_version: string;
    matching_policy: string;
    a: Record<string, string | null>;
    b: Record<string, string | null>;
    binary: { identical: boolean; sha256_a: string; sha256_b: string; size_a: number; size_b: number; format_a: string; format_b: string; same_sample: boolean };
    environment: { source: EvidenceSourceName; state_a: string; state_b: string; differing_fields: string[]; comparability: "comparable" | "environment_differs" | "coverage_differs" | "unavailable_on_both"; explanation: string }[];
    coverage: { join: string; performed_a: boolean | null; performed_b: boolean | null; joined_a: number; joined_b: number; comparable: boolean; reason: string | null }[];
    mapping: { addresses_comparable: boolean; explanation: string; declared_image_base_a: number | null; declared_image_base_b: number | null; ghidra_image_base_a: string | null; ghidra_image_base_b: string | null };
    correspondence: { kind: string; method: string; matched: number; unmatched_a: number; unmatched_b: number; limitation: string }[];
    counts: { nodes: Record<string, number>; edges: Record<string, number>; attribution: Record<string, number>; exact_joins_established: number; exact_joins_lost: number };
    statements: { id: string; kind: string; text: string; cites: string[]; cites_total: number }[];
    review_candidates: string[];
    incomparable: string[];
    limitations: string[];
    comparison_sha256: string;
  };
  changes: { filters: Record<string, string | null>; matched: number; offset: number; limit: number; items: ComparisonChangeItem[]; next_cursor: string | null };
  build_ms: number;
}
/** `version:<id>` (current graph) or `review:<id>` (pinned snapshot). */
export type EvidenceSide = `version:${string}` | `review:${string}`;

export interface FunctionStructure {
  run_id: string; invocation_id: string; index: number; protocol_version: string;
  state: "available" | "not_selected" | "not_captured"; reason: string | null;
  entry: GhidraAddress; name: string; body_size: number | null;
  basic_block_count: number | null; basic_block_count_capped: boolean;
  instruction_count: number | null; instruction_count_capped: boolean;
  basic_blocks: { start: GhidraAddress; end: GhidraAddress; instruction_count: number; terminal: boolean; flows: { target: GhidraAddress | null; kind: "fallthrough" | "conditional_jump" | "unconditional_jump" | "computed_jump"; internal: boolean }[]; flows_truncated: boolean }[];
  basic_blocks_truncated: boolean;
  flow_counts: Record<string, number>;
  call_sites: { source: GhidraAddress; kind: "direct" | "indirect"; target: GhidraAddress | null; target_basis: string | null; target_function_index: number | null; target_function_name: string | null; resolution: "inventory_function" | "outside_inventory" | "unresolved" }[];
  call_sites_truncated: boolean;
  thunk_target: GhidraAddress | null;
  citation: string;
  limitations: string[];
}
export interface StructureTables {
  version_id: string; state: "available" | "unavailable"; unavailable_reason: string | null;
  adapter_version: string; schema_version: string | null; format: "PE" | "ELF" | null; file_size: number | null;
  header: Record<string, unknown>;
  tables: { name: string; provenance: string; count: number; offset: number; limit: number; rows: Record<string, unknown>[]; next_offset: number | null }[];
  truncated: string[]; limitations: string | null;
}

async function get<T>(url: string): Promise<T> {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    let problem: Problem;
    try { problem = await response.json() as Problem; }
    catch { problem = { type: "about:blank", code: "http_error", title: "Request failed", status: response.status, detail: "The evidence records could not be loaded. Try again." }; }
    throw new ApiError(problem);
  }
  return response.json() as Promise<T>;
}
const review = (id: string) => `/api/v1/reviews/${encodeURIComponent(id)}/evidence`;
export const evidenceHistoryApi = {
  review: (reviewId: string) => get<ReviewEvidence>(review(reviewId)),
  reviewNodes: (reviewId: string, params: { kind?: EvidenceNodeKind; q?: string; cursor?: string; limit?: number } = {}) =>
    get<SnapshotPage<SnapshotNode>>(review(reviewId) + "/nodes" + queryString({ ...params })),
  reviewEdges: (reviewId: string, params: { type?: EvidenceEdgeTypeV2; cursor?: string; limit?: number } = {}) =>
    get<SnapshotPage<SnapshotEdge>>(review(reviewId) + "/edges" + queryString({ ...params })),
  compare: (a: EvidenceSide, b: EvidenceSide, params: { category?: "node" | "edge"; change?: ComparisonChange; kind?: string; attribution?: ComparisonAttribution; cursor?: string; limit?: number } = {}) =>
    get<EvidenceComparison>("/api/v1/evidence/compare" + queryString({ a, b, ...params })),
  functionStructure: (runId: string, index: number) =>
    get<FunctionStructure>(`/api/v1/runs/${encodeURIComponent(runId)}/ghidra/functions/${index}/structure`),
  structure: (versionId: string, params: { table?: string; offset?: number; limit?: number } = {}) =>
    get<StructureTables>(`/api/v1/sample-versions/${encodeURIComponent(versionId)}/structure` + queryString({ ...params })),
};
