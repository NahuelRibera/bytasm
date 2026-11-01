// v0.10 evidence correlation contract (docs/api-v0.10-evidence.md). Data only:
// no component imports this yet, so the Engraved Signal UI can adopt it freely.
import { ApiError, type Problem, queryString } from "./api";
import type { GhidraAddress } from "./ghidra-api";

export type EvidenceNodeKind = "entry_point" | "section" | "function" | "finding" | "external_symbol" | "import" | "program_data" | "string";
export type EvidenceEdgeType =
  | "calls" | "references_string" | "references_data" | "references_external_symbol"
  | "target_is_string_occurrence" | "capa_match_at_function_entry" | "yara_match_in_function_body"
  | "entry_point_is_function" | "located_in_section" | "external_symbol_named_as_import";
export type EvidenceStrength = "exact_reference" | "exact_offset_equality" | "address_containment" | "structural_containment" | "name_equality";
export type TranslationState = "mapped" | "not_file_backed" | "outside_known_regions" | "ambiguous" | "unsupported_address" | "unavailable";

export interface EvidenceLocator { tool: string; tool_version: string; run_id: string; invocation_id: string; output_sha256: string | null; pointer: string }
export interface EvidenceNode {
  id: string;
  kind: EvidenceNodeKind;
  /** Untrusted text from the file or a tool. Render as escaped text only. */
  label: string;
  identity: Record<string, string | number | null>;
  address: GhidraAddress | null;
  file_offset: number | null;
  file_offset_basis: string | null;
  file_offset_state: TranslationState | null;
  attributes: Record<string, unknown>;
  sources: EvidenceLocator[];
}
export interface EvidenceEdge {
  id: string; type: EvidenceEdgeType; strength: EvidenceStrength; source: string; target: string;
  basis: string[]; locators: EvidenceLocator[]; locator_count: number; locators_truncated: boolean;
  attributes: Record<string, unknown>;
}
export interface EvidenceClaim {
  id: string; kind: string; title: string; summary: string; technical: string;
  subjects: string[]; evidence: string[]; sources: EvidenceLocator[];
  interpretation: string | null; alternatives: string | null; limitations: string[];
  completeness: { state: "complete_within_retained_windows" | "bounded" | "partial"; notes: string[] };
  navigate: { node_id: string; href: string };
  reading_weight: number;
}
export interface EvidenceJoin { join: string; performed: boolean; reason: string | null; candidates: number; joined: number; not_joined: Record<string, number> }
export interface EvidenceSource {
  source: "metadata" | "ghidra" | "pattern"; run_id: string | null; status: string | null; profile_id: string | null;
  selected_by: "explicit" | "latest_completed" | "import_record" | "none";
  newer_unselected_run_ids: string[]; unavailable_reason: string | null;
}
export interface EvidenceSummary {
  scope: { schema_version: string; scope_sha256: string; project_id: string; version_id: string; sha256: string; file_format: string; selection_policy: string; sources: EvidenceSource[] };
  counts: { nodes: Record<string, number>; edges: Record<string, number>; strengths: Record<string, number> };
  coverage: {
    steps: Array<{ tool: string; status: string; run_id: string; invocation_id: string | null; tool_version: string | null }>;
    ghidra_protocol: string | null;
    ghidra_memory_map: "available" | "unavailable" | "not_selected";
    ghidra_memory_map_reason: string | null;
    functions_identified: number | null; functions_retained: number | null; functions_inventory_complete: boolean | null;
    functions_with_detail_windows: number | null; functions_with_capped_windows: number | null;
    strings_retained: number | null; strings_truncated: boolean | null;
    findings: number | null; findings_with_capped_evidence: number | null;
    joins: EvidenceJoin[];
    statements: string[];
  };
  claims: EvidenceClaim[]; claims_total: number; claims_truncated: boolean;
  layout: {
    file_size: number; basis: string;
    sections: Array<{ node_id: string; index: number; name: string; file_offset: number; file_size: number; declared_virtual_address: number | null; declared_virtual_size: number; flags: string[]; contains: Record<string, number> }>;
    ghidra_blocks: Array<{ name: string; start: string; end: string; permissions: string; initialized: boolean; file_backed: boolean }> | null;
  };
  limitations: string[];
  build_ms: number;
}
export interface EvidencePage<T> { scope_sha256: string; matched: number; offset: number; limit: number; items: T[]; next_cursor: string | null }
export interface EvidenceNodeDetail { scope_sha256: string; node: EvidenceNode; edges: EvidenceEdge[]; edges_total: number; edges_truncated: boolean; neighbors: EvidenceNode[]; claims: string[] }
export interface EvidenceSelection { ghidra_run_id?: string; analysis_run_id?: string }

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
const base = (versionId: string) => `/api/v1/sample-versions/${encodeURIComponent(versionId)}/evidence`;
export const evidenceApi = {
  summary: (versionId: string, selection: EvidenceSelection = {}) =>
    get<EvidenceSummary>(base(versionId) + queryString({ ...selection })),
  nodes: (versionId: string, params: EvidenceSelection & { kind?: EvidenceNodeKind; q?: string; cursor?: string; limit?: number } = {}) =>
    get<EvidencePage<EvidenceNode> & { kind: EvidenceNodeKind | null }>(base(versionId) + "/nodes" + queryString({ ...params })),
  edges: (versionId: string, params: EvidenceSelection & { type?: EvidenceEdgeType; cursor?: string; limit?: number } = {}) =>
    get<EvidencePage<EvidenceEdge> & { type: EvidenceEdgeType | null }>(base(versionId) + "/edges" + queryString({ ...params })),
  node: (versionId: string, nodeId: string, params: EvidenceSelection & { edge_type?: EvidenceEdgeType } = {}) =>
    get<EvidenceNodeDetail>(base(versionId) + "/nodes/" + encodeURIComponent(nodeId) + queryString({ ...params })),
};
