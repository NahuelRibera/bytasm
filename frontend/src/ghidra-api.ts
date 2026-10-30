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
}
export interface GhidraFunctions {
  run_id: string; matched: number; total: number; offset: number; limit: number;
  items: Array<Pick<GhidraFunction, "entry" | "external" | "name" | "name_truncated" | "namespace" | "namespace_truncated" | "body_size" | "pseudocode_status" | "pseudocode_truncated" | "instructions_truncated" | "calls_truncated"> & { index: number }>;
}
export interface GhidraDetail {
  run_id: string; invocation_id: string; index: number; citation: string; function: GhidraFunction;
}
async function get<T>(url: string): Promise<T> {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
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
  functions: (runId: string, q: string, offset: number) => get<GhidraFunctions>(`${base(runId)}/functions${queryString({ q, offset, limit: 25 })}`),
  detail: (runId: string, index: number) => get<GhidraDetail>(`${base(runId)}/functions/${index}`),
  exportUrl: (runId: string, format: "json" | "html") => `${base(runId)}/export?format=${format}`,
};
export const addressLabel = (value: GhidraAddress) => `${value.space}:${value.address}`;
