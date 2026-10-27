// A fetch stand-in for UI unit tests: routes requests to canned responses.
import { vi } from "vitest";
import type { Health, SampleVersion, Sections } from "../api";

export type Handler = (init: RequestInit | undefined, url: string) => Response | Promise<Response>;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" },
  });
}

export function installFetch(routes: Record<string, Handler>) {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init });
    const method = (init?.method ?? "GET").toUpperCase();
    const handler = routes[`${method} ${url}`];
    if (!handler) return json({ code: "not_found", title: "Not found", status: 404, detail: url }, 404);
    return handler(init, url);
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

export const PROJECT_ID = "a".repeat(32);
export const SAMPLE_ID = "b".repeat(32);
export const VERSION_ID = "c".repeat(32);
export const HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>';

export function health(mode: "fixtures" | "self_built" = "fixtures"): Health {
  return {
    status: "ok",
    bytasm_version: "0.0.1",
    input_policy: { mode, self_built_enabled: mode === "self_built" },
    max_upload_bytes: 64 * 1024 * 1024,
    parser_timeout_seconds: 30,
    platform: "linux",
    parser_memory_limit_enforced: true,
  };
}

export const project = {
  id: PROJECT_ID,
  name: "Demo",
  description: "",
  created_at: "2026-10-26T10:00:00Z",
  sample_count: 0,
};

export function version(overrides: Partial<SampleVersion> = {}): SampleVersion {
  return {
    id: VERSION_ID,
    project_id: PROJECT_ID,
    project_name: "Demo",
    sample_id: SAMPLE_ID,
    sample_name: "hello",
    version_label: "v1",
    sha256: "71f62a001edac210d19897a84c8b1217fa34ca5d3f94e1cc96e537ca1e4423c1",
    size_bytes: 14336,
    declared_filename: "hello_v1-x86_64.exe",
    detected_format: "PE",
    admitted_under: "fixture_manifest",
    manifest_entry: "bin/hello_v1-x86_64.exe",
    imported_at: "2026-10-26T10:00:00Z",
    authorization: {
      type: "self_attestation",
      basis: "owned_or_built",
      statement: "I built it.",
      terms_reference: null,
      recorded_at: "2026-10-26T10:00:00Z",
      notice: "It is not proof of permission.",
    },
    invocation: {
      tool: "lief",
      tool_version: "1.0.0",
      adapter: "metadata_lief",
      adapter_version: "0.1.0",
      status: "succeeded",
      exit_code: 0,
      duration_ms: 120,
      result_sha256: "d".repeat(64),
      entropy_method: "shannon-bits-per-byte",
    },
    header: {
      format: "PE",
      architecture: "x86_64",
      bitness: 64,
      endianness: "little",
      entry_point: 0x1400013f0,
      declared_header: { pe_machine: "AMD64", pe_timestamp: 0 },
      imported_libraries: ["KERNEL32.dll"],
    },
    warnings: [],
    counts: { sections: 2, imported_libraries: 1, imported_functions: 1, exports: 0 },
    ...overrides,
  };
}

export function sections(names: string[] = [".text", ".bss"]): Sections {
  return {
    entropy_method: "shannon-bits-per-byte",
    entropy_unit: "bits_per_byte",
    sections: names.map((name, index) => ({
      index,
      name,
      section_type: null,
      file_offset: 0x400 * (index + 1),
      raw_size: index === names.length - 1 ? 0 : 512,
      virtual_address: 0x1000 * (index + 1),
      virtual_size: 512,
      flags: ["MEM_READ"],
      entropy: index === names.length - 1 ? null : 5.123456,
      entropy_note: index === names.length - 1 ? "no file data" : null,
    })),
  };
}
