import { ApiError, type Problem, queryString } from "./api";

export interface GhidraAddress { space: string; address: string }
export interface GhidraFunction {
  entry: GhidraAddress;
  name: string;
  namespace: string;
  external?: boolean;
  name_truncated?: boolean;
  namespace_truncated?: boolean;
  body_size: number | null;
  pseudocode: string | null;
  pseudocode_status: string;
  pseudocode_truncated: boolean;
  instructions: Array<{ address: GhidraAddress; bytes_hex: string; text: string; text_truncated?: boolean; bytes_truncated?: boolean }>;
  calls: Array<{ source: GhidraAddress; target: GhidraAddress }>;
  instructions_truncated: boolean;
  calls_truncated: boolean;
  limitations: string[];
}
export interface GhidraOverview {
  run_id: string;
  project_id: string;
  version_id: string;
  input_sha256: string;
  run_status: string;
  step_status: string;
  invocation_id: string | null;
  available: boolean;
  provenance: null | {
    tool: string; tool_version: string; adapter_version: string;
    profile_sha256: string; script_sha256: string; raw_output_sha256: string;
    language_id: string; compiler: string; provider_host?: { os: string; architecture: string };
  };
  summary: {
    observations: Array<{ text: string; citation: string }>;
    hypotheses: string[];
    analyst_notes: string[];
    recommendations: string[];
    limitations: string[];
  };
  coverage: { completed: number; total: number };
  function_count: number | null;
  stored_functions: number;
  functions_truncated: boolean;
  detailed_functions?: number;
  failed_details?: number;
  retained_instructions?: number;
  retained_calls?: number;
  inventory_state?: string;
  source_run_id?: string | null;
}
export interface GhidraFunctions {
  run_id: string; matched: number; total: number; offset: number; limit: number;
  next_cursor?: string | null; identified?: number; inventory_complete?: boolean;
  functions_truncated?: boolean; scope_sha256?: string;
  items: Array<Pick<GhidraFunction, "entry" | "external" | "name" | "name_truncated" | "namespace" | "namespace_truncated" | "body_size" | "pseudocode_status" | "pseudocode_truncated" | "instructions_truncated" | "calls_truncated"> & { index: number }>;
}
export interface GhidraDetail {
  run_id: string; invocation_id: string; index: number; citation: string; function: GhidraFunction;
}
async function get<T>(url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, body === undefined ? { headers: { Accept: "application/json" } } : {
    method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json", "X-Bytasm-Request": "1" }, body: JSON.stringify(body),
  });
  if (!response.ok) {
    let problem: Problem;
    try { problem = await response.json() as Problem; }
    catch { problem = { type: "about:blank", code: "http_error", title: "Request failed", status: response.status, detail: "The Ghidra records could not be loaded. Try again." }; }
    throw new ApiError(problem);
  }
  return response.json() as Promise<T>;
}
const base = (runId: string) => `/api/v1/runs/${encodeURIComponent(runId)}/ghidra`;
export const ghidraApi = {
  overview: (runId: string) => get<GhidraOverview>(base(runId)),
  functions: (runId: string, q: string, offset: number, field = "all", pseudocode = "", cursor?: string) => get<GhidraFunctions>(`${base(runId)}/functions${queryString({ q, offset: cursor ? 0 : offset, limit: 25, field: field === "all" ? "" : field, pseudocode, cursor })}`),
  inspect: (runId: string, indices: number[]) => get<{ run_id: string; source_run_id: string; reused: boolean }>(`${base(runId)}/inspections`, { indices }),
  detail: (runId: string, index: number) => get<GhidraDetail>(`${base(runId)}/functions/${index}`),
  exportUrl: (runId: string, format: "json" | "html") => `${base(runId)}/export?format=${format}`,
};
export const addressLabel = (value: GhidraAddress) => `${value.space}:${value.address}`;

export interface GhidraRelationships {
  run_id: string; center_index: number; node_limit: number; edge_limit: number;
  retained_matches: number; truncated: boolean; inventory_complete: boolean; reference_windows_complete?: boolean;
  limitations: string[];
  edges: Array<{ source_index: number; target_index: number | null; call_site: GhidraAddress; target: GhidraAddress; reference_type: string; citation: string }>;
}
export const loadRelationships = (runId: string, index: number) =>
  get<GhidraRelationships>(`${base(runId)}/functions/${index}/relationships`);
