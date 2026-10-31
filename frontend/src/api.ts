// Typed client for the Bytasm local API, v0.1 + v0.2 (backend/src/bytasm/api/schemas.py).
//
// Every state-changing request carries `X-Bytasm-Request: 1`; the API refuses
// mutations without it. Error bodies are RFC 9457-style problem details whose
// messages come from a fixed server-side list.

export type PolicyMode = "fixtures" | "self_built";

export interface Health {
  status: "ok";
  bytasm_version: string;
  input_policy: { mode: PolicyMode; self_built_enabled: boolean };
  max_upload_bytes: number;
  parser_timeout_seconds: number;
  platform: string;
  parser_memory_limit_enforced: boolean;
  yara_x_version: string;
  // Seconds since `bytasm worker` last checked in; null if it never ran here.
  worker_last_seen_seconds: number | null;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  sample_count: number;
}

export interface VersionSummary {
  id: string;
  version_label: string | null;
  sha256: string;
  size_bytes: number;
  detected_format: string;
  architecture: string;
  admitted_under: string;
  imported_at: string;
}

export interface Sample {
  id: string;
  name: string;
  versions: VersionSummary[];
}

export interface SampleVersion {
  id: string;
  project_id: string;
  project_name: string;
  sample_id: string;
  sample_name: string;
  version_label: string | null;
  sha256: string;
  size_bytes: number;
  declared_filename: string | null;
  detected_format: string;
  admitted_under: string;
  manifest_entry: string | null;
  imported_at: string;
  authorization: {
    type: "self_attestation";
    basis: string;
    statement: string;
    terms_reference: string | null;
    recorded_at: string;
    notice: string;
  };
  invocation: {
    tool: string;
    tool_version: string;
    adapter: string;
    adapter_version: string;
    status: string;
    exit_code: number;
    duration_ms: number;
    result_sha256: string;
    entropy_method: string;
  };
  header: {
    format: string;
    architecture: string;
    bitness: number;
    endianness: string;
    entry_point: number | null;
    entry_point_hex?: string | null;
    declared_header_exact?: Record<string, string>;
    declared_header: Record<string, string | number>;
    imported_libraries: string[];
  };
  warnings: string[];
  counts: Record<string, number>;
}

export interface Section {
  index: number;
  name: string;
  section_type: string | null;
  file_offset: number;
  raw_size: number;
  virtual_address: number;
  virtual_address_hex?: string;
  virtual_size: number;
  virtual_size_decimal?: string;
  flags: string[];
  entropy: number | null;
  entropy_note: string | null;
}

export interface Sections {
  metadata_invocation_id?: string | null;
  entropy_method: string;
  entropy_unit: "bits_per_byte";
  sections: Section[];
}

export interface Imports {
  libraries: string[];
  functions: string[];
}

export interface Exports {
  functions: string[];
}

export interface ReportCreated {
  id: string;
  sample_version_id: string;
  format: "json";
  sha256: string;
  generated_at: string;
  download_url: string;
}

export interface Problem {
  type: string;
  code: string;
  title: string;
  status: number;
  detail: string;
  request_id?: string;
  existing_version_id?: string;
  sample_id?: string;
  run_id?: string;
}

export class ApiError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail);
    this.problem = problem;
  }
}

const MUTATION_HEADERS = { "X-Bytasm-Request": "1" };

async function parse<T>(response: Response): Promise<T> {
  if (response.ok) return (await response.json()) as T;
  let problem: Problem;
  try {
    problem = (await response.json()) as Problem;
  } catch {
    problem = {
      type: "about:blank",
      code: "http_error",
      title: `HTTP ${response.status}`,
      status: response.status,
      detail: "The server returned an unexpected response.",
    };
  }
  throw new ApiError(problem);
}

/** "?a=1&b=x" from the defined, non-empty values (or ""). */
export function queryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

/** Attachment URL of a tool invocation's stored, validated result document. */
export function rawOutputUrl(invocationId: string): string {
  return `/api/v1/invocations/${encodeURIComponent(invocationId)}/raw`;
}

async function get<T>(path: string): Promise<T> {
  return parse<T>(await fetch(path, { headers: { Accept: "application/json" } }));
}

export const api = {
  tools: () => get<{ tools: Array<{ tool: string; available: boolean; version: string | null; adapter: string; adapter_version: string; formats: string[]; rules_sha256: string | null; limitations: string }>; profiles: Array<{ id: string; name: string; steps: string[]; limitations: string }>; optional_providers?: GhidraDiagnostic[] }>("/api/v1/tools"),
  reportReview: (id: string) => get<Review>(`/api/v1/reports/${encodeURIComponent(id)}/review`),
  reportDocument: (id: string) => get<Record<string, unknown>>(`/api/v1/reports/${encodeURIComponent(id)}/download`),
  reportHistory: (id: string, offset = 0) => get<{ items: Array<{ id: string; sha256: string; generated_at: string; scope: { kind: string } | null }>; next_offset: number | null }>(`/api/v1/sample-versions/${encodeURIComponent(id)}/reports?offset=${offset}&limit=25`),
  health: () => get<Health>("/api/v1/health"),
  projects: () => get<Project[]>("/api/v1/projects"),
  activity: (projectId: string, offset = 0) =>
    get<ActivityPage>(`/api/v1/projects/${encodeURIComponent(projectId)}/activity${queryString({ offset, limit: 25 })}`),
  project: (id: string) => get<Project>(`/api/v1/projects/${encodeURIComponent(id)}`),
  samples: (projectId: string) =>
    get<Sample[]>(`/api/v1/projects/${encodeURIComponent(projectId)}/samples`),
  version: (id: string) => get<SampleVersion>(`/api/v1/sample-versions/${encodeURIComponent(id)}`),
  sections: (id: string) =>
    get<Sections>(`/api/v1/sample-versions/${encodeURIComponent(id)}/sections`),
  imports: (id: string) => get<Imports>(`/api/v1/sample-versions/${encodeURIComponent(id)}/imports`),
  exports: (id: string) => get<Exports>(`/api/v1/sample-versions/${encodeURIComponent(id)}/exports`),

  async createProject(name: string, description: string): Promise<Project> {
    const response = await fetch("/api/v1/projects", {
      method: "POST",
      headers: { ...MUTATION_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ name, description }),
    });
    return parse<Project>(response);
  },

  async importFile(projectId: string, file: Blob, metadata: ImportMetadata) {
    const response = await fetch(`/api/v1/projects/${encodeURIComponent(projectId)}/imports`, {
      method: "POST",
      headers: {
        ...MUTATION_HEADERS,
        "Content-Type": "application/octet-stream",
        "X-Bytasm-Import": encodeImportHeader(metadata),
      },
      body: file,
    });
    return parse<{ sample_version: SampleVersion }>(response);
  },

  async createReport(versionId: string): Promise<ReportCreated> {
    const response = await fetch(
      `/api/v1/sample-versions/${encodeURIComponent(versionId)}/reports`,
      { method: "POST", headers: MUTATION_HEADERS },
    );
    return parse<ReportCreated>(response);
  },

  // v0.2: the bundled rule set, analysis runs, findings.
  currentRuleSet: () => get<RuleSet>("/api/v1/rule-sets/current"),
  ruleSet: (id: string) => get<RuleSet>(`/api/v1/rule-sets/${encodeURIComponent(id)}`),
  runs: (versionId: string) =>
    get<{ runs: Run[] }>(`/api/v1/sample-versions/${encodeURIComponent(versionId)}/runs`),
  run: (id: string) => get<Run>(`/api/v1/runs/${encodeURIComponent(id)}`),
  findings: (runId: string, filters: FindingFilters = {}) =>
    get<Findings>(`/api/v1/runs/${encodeURIComponent(runId)}/findings${queryString(filters)}`),
  runLog: (runId: string) => get<RunLog>(`/api/v1/runs/${encodeURIComponent(runId)}/log`),
  strings: (versionId: string, params: StringsQuery = {}) =>
    get<StringsPage>(
      `/api/v1/sample-versions/${encodeURIComponent(versionId)}/strings${queryString(params)}`,
    ),

  async validateRules(): Promise<RuleValidation> {
    const response = await fetch("/api/v1/rule-sets/current/validation", {
      method: "POST",
      headers: MUTATION_HEADERS,
    });
    return parse<RuleValidation>(response);
  },

  async createRun(versionId: string, profileId = "default-static"): Promise<Run> {
    const response = await fetch(`/api/v1/sample-versions/${encodeURIComponent(versionId)}/runs`, {
      method: "POST",
      headers: { ...MUTATION_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ profile_id: profileId }),
    });
    return parse<Run>(response);
  },

  async cancelRun(runId: string): Promise<Run> {
    const response = await fetch(`/api/v1/runs/${encodeURIComponent(runId)}/cancel`, {
      method: "POST",
      headers: MUTATION_HEADERS,
    });
    return parse<Run>(response);
  },
};

export interface RuleFile {
  name: string;
  identifier: string;
  text: string;
}

export interface RuleSet {
  id: string | null;
  tool: "yara-x" | "capa";
  installed_tool_version?: string | null;
  name: string;
  version: string;
  label: string;
  sha256: string;
  source: string;
  current: boolean;
  rule_count: number;
  files: RuleFile[];
  installed_yara_x_version: string;
}

export interface Diagnostic {
  code: string;
  title: string;
  file: string | null;
  line: number | null;
  column: number | null;
}

export interface RuleValidation {
  rule_set_sha256: string;
  label: string;
  yara_x_version: string;
  compiled: boolean;
  rule_identifiers: string[];
  problems: string[];
  errors: Diagnostic[];
  warnings: Diagnostic[];
  duration_ms: number;
}

export type RunStatus = "queued" | "running" | "succeeded" | "partial" | "failed" | "cancelled";
export type StepStatus =
  | "unsupported"
  | "unavailable"
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "skipped";

export interface StringsSummary {
  total_found: number;
  found_by_encoding: Record<string, number>;
  stored: number;
  truncated: boolean;
}

export interface RunStep {
  index: number;
  tool: string;
  adapter: string;
  status: StepStatus;
  message: string | null;
  invocation_id: string | null;
  tool_version: string | null;
  adapter_version: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  timeout_seconds: number;
  failure_reason: string | null;
  raw_output_sha256: string | null;
  strings: StringsSummary | null;
  warnings: string[];
}

export interface Run {
  id: string;
  status: RunStatus;
  failure_reason: string | null;
  failure_message: string | null;
  cancel_requested: boolean;
  queued_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  bytasm_version: string;
  profile_id: string;
  profile_name: string;
  rule_set: { id: string; label: string; sha256: string };
  sample: {
    project_id: string;
    project_name: string;
    sample_id: string;
    sample_name: string;
    version_id: string;
    version_label: string | null;
    sha256: string;
    size_bytes: number;
    detected_format: string;
    admitted_under: string;
  };
  steps: RunStep[];
  summary?: string[];
  review?: Review | null;
  counts: { findings: number; evidence: number; strings: number };
}

export interface Evidence {
  id: number;
  kind: "byte_range" | "virtual_address";
  virtual_address?: number | null;
  virtual_address_hex?: string | null;
  pattern_id: string;
  file_offset: number | null;
  length: number | null;
  xor_key: number | null;
  excerpt_hex: string;
  excerpt_truncated: boolean;
  raw_json_pointer: string;
}

export interface Finding {
  id: string;
  kind: "yara_match" | "capability";
  tool?: string;
  title: string;
  rule_id: string;
  rule_namespace: string;
  rule_set_id: string;
  tags: string[];
  metadata: Array<[string, string | number | boolean]>;
  fingerprint: string;
  match_count: number;
  evidence_truncated: boolean;
  evidence: Evidence[];
}

export interface FindingFilters {
  tool?: string;
  kind?: string;
  q?: string;
  namespace?: string;
  [key: string]: string | undefined;
}

export interface Findings {
  run_id: string;
  run_status: string;
  run_message: string | null;
  total: number;
  filters: { tool: string | null; kind: string | null; q: string | null };
  available_tools: string[];
  available_kinds: string[];
  findings: Finding[];
  notices: string[];
}

export interface RunLog {
  run_id: string;
  entries: Array<{ seq: number; at: string | null; step_index: number | null; message: string }>;
  next_cursor: number;
  complete: boolean;
}

export type StringCategory = "url_like" | "path_like" | "other";
export type StringSort = "offset" | "length" | "value" | "category";

export interface StringsQuery {
  run_id?: string;
  category?: StringCategory;
  sort?: StringSort;
  query?: string;
  encoding?: "ascii" | "utf-16le";
  offset?: number;
  limit?: number;
  [key: string]: string | number | undefined;
}

export interface ExtractedString {
  category?: StringCategory;
  section?: { index: number; name: string } | null;
  offset: number;
  encoding: "ascii" | "utf-16le";
  length_chars: number;
  byte_length: number;
  value: string;
  value_truncated: boolean;
}

export interface StringsPage {
  category_counts?: Partial<Record<StringCategory, number>>;
  category_scope?: string;
  metadata_invocation_id?: string | null;
  version_id: string;
  run_id: string | null;
  run_status: string | null;
  invocation_id: string | null;
  tool_version: string | null;
  min_length: number;
  encodings: string[];
  summary: StringsSummary | null;
  query: string | null;
  encoding: string | null;
  matched: number;
  offset: number;
  limit: number;
  items: ExtractedString[];
  notices: string[];
}

export interface ImportMetadata {
  sample_id?: string;
  sample_name?: string;
  version_label?: string;
  declared_filename?: string;
  authorization: { basis: "owned_or_built"; statement: string };
}

/** base64url(JSON), as the X-Bytasm-Import header expects. */
export function encodeImportHeader(metadata: ImportMetadata): string {
  const bytes = new TextEncoder().encode(JSON.stringify(metadata));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface ActivityItem {
  annotation_target_type?: "sample_version" | "finding" | "evidence" | null;
  annotation_target_id?: string | null;
  annotation_id?: string | null;
  revision_id?: string | null;
  id: string;
  type: string;
  at: string;
  sample_version_id: string | null;
  run_id: string | null;
  status: string | null;
  reason: string | null;
}

export interface ActivityPage {
  items: ActivityItem[];
  next_offset: number | null;
}


export interface Review {
  selection_policy?: "source-order-v1" | "relevance-v1";
  selection_explanation?: string | null;
  template_version: string;
  run_id: string | null;
  version_id: string;
  total: number;
  capped: boolean;
  observations: Array<{ title?: string | null; key: string; tool: string; tool_version: string; adapter_version: string;
    rule_id: string; rule_version: string; rule_sha256: string; statement: string; hypothesis: string;
    source_href: string; locations: string[]; pointers: string[]; evidence_capped: boolean }>;
  glossary: Record<string, string>;
}

export interface GhidraDiagnostic {
  provider: "ghidra";
  available: boolean;
  analysis_enabled: boolean;
  status: "not_configured" | "installation_invalid" | "unsupported_version" | "java_missing" | "java_incompatible" | "unsupported_host" | "execution_unavailable" | "available" | "self_check_failed" | "isolation_unavailable";
  message: string;
  declared_ghidra_version: "12.2" | null;
  declared_java_major: number | null;
  verification: "metadata_only" | "headless_self_check";
  health_check: "not_run" | "passed" | "failed";
}
