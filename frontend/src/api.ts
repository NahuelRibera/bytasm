// Typed client for the Bytasm v0.1 local API (backend/src/bytasm/api/schemas.py).
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
  virtual_size: number;
  flags: string[];
  entropy: number | null;
  entropy_note: string | null;
}

export interface Sections {
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

async function get<T>(path: string): Promise<T> {
  return parse<T>(await fetch(path, { headers: { Accept: "application/json" } }));
}

export const api = {
  health: () => get<Health>("/api/v1/health"),
  projects: () => get<Project[]>("/api/v1/projects"),
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
};

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
