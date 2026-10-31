import { ApiError } from "./api";

export interface ReviewSource {
  tool: string;
  selected: { run_id: string; invocation_id: string; status: string; run_status: string;
    output_sha256: string; tool_version: string; adapter_version: string;
    completeness: string; retention?: Record<string, unknown>; limits: Record<string, unknown> | null; warnings: string[] } | null;
  latest_attempt: { run_id: string; status: string; run_status: string } | null;
  unavailable_reason: string | null;
}
export interface PinnedObservation {
  id: string; title: string; question: string; statement: string; hypothesis: string;
  why_it_matters: string; alternatives: string[]; conditions: string; limitations: string[];
  next_step: string; run_id: string; invocation_id: string; finding_id: string;
  output_sha256: string; tool: string; rule_id: string; evidence_capped: boolean;
}
export interface PinnedReview {
  answers?: Array<{ id: string; title: string; observations: Array<{ level: string; observation: string; why_it_matters: string; alternative: string; evidence: Record<string, unknown>; missing: string; next_action: string }>; missing: string; next_action: string }>;
  interpretation_version?: string;
  structure?: Record<string, unknown> | null;
  function_evidence?: Array<{ protocol_version?: string; entry: import("./ghidra-api").GhidraAddress; name: string; body_ranges?: import("./ghidra-api").GhidraFunction["body_ranges"]; references?: import("./ghidra-api").GhidraFunction["references"]; body_ranges_truncated?: boolean; references_truncated?: boolean; run_id: string; function_index: number; invocation_id: string; output_sha256: string; pointer: string }>;
  source_run_offset?: number; source_runs_more?: boolean;
  id: string; created_at: string; supersedes_id: string | null;
  sample: { version_id: string; sha256: string; size_bytes: number };
  scope: "combined" | "exact_run"; exact_run_id: string | null; catalog_version: string;
  sources: ReviewSource[]; observations: PinnedObservation[]; observations_total: number;
  import_observations?: Array<{ category: string; title: string; observation: string; alternative: string; next_step: string; pointers: string[]; supporting_names: string[]; invocation_id: string; output_sha256: string; limitation: string }>;
  observations_capped: boolean; unknowns: string[]; selection_explanation: string;
}
export interface PrivacyPolicy {
  analyst_notes: boolean; overview: boolean; observations: boolean; technical_details: boolean;
  string_values: boolean; original_names: boolean; mask_sensitive_values: boolean;
}
export const defaultPrivacy: PrivacyPolicy = { analyst_notes: false, overview: true, observations: true,
  technical_details: true, string_values: false, original_names: false, mask_sensitive_values: true };

async function request<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, body === undefined ? undefined : {
    method: "POST", headers: { "X-Bytasm-Request": "1", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new ApiError(await response.json());
  return response.json() as Promise<T>;
}
export const reviewApi = {
  create: (versionId: string, runId?: string, runOffset = 0) => request<PinnedReview>(`sample-versions/${versionId}/reviews`,
    runId ? { scope: "exact_run", run_id: runId } : { scope: "combined", run_offset: runOffset }),
  compare: (left: string, right: string) => request<Record<string, unknown>>(`reviews/${left}/compare/${right}`),
  get: (id: string) => request<PinnedReview>(`reviews/${id}`),
  refresh: (id: string) => request<PinnedReview>(`reviews/${id}/refresh`, {}),
  history: (versionId: string, offset = 0) => request<{ items: { id: string; created_at: string }[]; next_offset: number | null }>(`sample-versions/${versionId}/reviews${offset ? `?offset=${offset}` : ""}`),
  preview: (id: string, policy: PrivacyPolicy) => request<{ document: Record<string, unknown>; sha256: string; size_bytes: number }>(`reviews/${id}/export/preview`, policy),
};
