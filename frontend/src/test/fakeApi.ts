// A fetch stand-in for UI unit tests: routes requests to canned responses.
import { vi } from "vitest";
import type { Findings, Health, RuleSet, Run, RunStep, SampleVersion, Sections, StringsPage } from "../api";

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
    yara_x_version: "1.22.1",
    worker_last_seen_seconds: 1,
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

export const RUN_ID = "e".repeat(32);
export const RULE_SET_ID = "f".repeat(32);
export const URL_RULE_TEXT =
  'rule url_reference {\n  strings:\n    $https = "https://" ascii\n  condition:\n    $https\n}\n';

export function ruleSet(overrides: Partial<RuleSet> = {}): RuleSet {
  return {
    id: RULE_SET_ID,
    tool: "yara-x",
    name: "bytasm-rules",
    version: "0.2.0",
    label: "bytasm-rules@0.2.0",
    sha256: "9".repeat(64),
    source: "bytasm-repo",
    current: true,
    rule_count: 1,
    files: [{ name: "url_reference.yar", identifier: "url_reference", text: URL_RULE_TEXT }],
    installed_yara_x_version: "1.22.1",
    ...overrides,
  };
}

export function run(overrides: Partial<Run> = {}): Run {
  return {
    id: RUN_ID,
    status: "succeeded",
    failure_reason: null,
    failure_message: null,
    cancel_requested: false,
    queued_at: "2026-10-27T10:00:00.123456Z",
    started_at: "2026-10-27T10:00:01Z",
    finished_at: "2026-10-27T10:00:02Z",
    bytasm_version: "0.0.1",
    profile_id: "default-static",
    profile_name: "Default static profile (v0.2)",
    rule_set: { id: RULE_SET_ID, label: "bytasm-rules@0.2.0", sha256: "9".repeat(64) },
    sample: {
      project_id: PROJECT_ID,
      project_name: "Demo",
      sample_id: SAMPLE_ID,
      sample_name: "hello",
      version_id: VERSION_ID,
      version_label: "v1",
      sha256: "71f62a001edac210d19897a84c8b1217fa34ca5d3f94e1cc96e537ca1e4423c1",
      size_bytes: 14336,
      detected_format: "PE",
      admitted_under: "fixture_manifest",
    },
    steps: [step("strings"), step("yara-x")],
    counts: { findings: 1, evidence: 1, strings: 12 },
    ...overrides,
  };
}

export const STRINGS_INVOCATION_ID = "a".repeat(32);
export const YARA_INVOCATION_ID = "b".repeat(32);

export function step(tool: "strings" | "yara-x", overrides: Partial<RunStep> = {}): RunStep {
  const strings = tool === "strings";
  return {
    index: strings ? 0 : 1,
    tool,
    adapter: strings ? "strings_extract" : "yara_x_scan",
    status: "succeeded",
    message: null,
    invocation_id: strings ? STRINGS_INVOCATION_ID : YARA_INVOCATION_ID,
    tool_version: strings ? "bytasm 0.0.1" : "1.22.1",
    adapter_version: "0.1.0",
    started_at: "2026-10-27T10:00:01Z",
    finished_at: "2026-10-27T10:00:02Z",
    duration_ms: strings ? 30 : 42,
    timeout_seconds: 30,
    failure_reason: null,
    raw_output_sha256: (strings ? "7" : "8").repeat(64),
    strings: strings
      ? { total_found: 12, found_by_encoding: { ascii: 11, "utf-16le": 1 }, stored: 12, truncated: false }
      : null,
    warnings: [],
    ...overrides,
  };
}

export function stringsPage(overrides: Partial<StringsPage> = {}): StringsPage {
  return {
    version_id: VERSION_ID,
    run_id: RUN_ID,
    run_status: "succeeded",
    invocation_id: STRINGS_INVOCATION_ID,
    tool_version: "bytasm 0.0.1",
    min_length: 6,
    encodings: ["ascii", "utf-16le"],
    summary: { total_found: 2, found_by_encoding: { ascii: 1, "utf-16le": 1 }, stored: 2, truncated: false },
    query: null,
    encoding: null,
    matched: 2,
    offset: 0,
    limit: 100,
    items: [
      {
        offset: 512,
        encoding: "ascii",
        length_chars: 47,
        byte_length: 47,
        value: "bytasm fixture v1: https://example.invalid/help",
        value_truncated: false,
      },
      {
        offset: 640,
        encoding: "utf-16le",
        length_chars: 300,
        byte_length: 600,
        value: "<img src=x onerror=alert(1)>" + "W".repeat(228),
        value_truncated: true,
      },
    ],
    notices: ["Strings are observations, not findings."],
    ...overrides,
  };
}

export const NOTICES = [
  "A match means a rule's pattern was found in the file's bytes. It is an observation that needs human interpretation, not a conclusion.",
  "No match does not show that a file is safe: it only means none of these rules matched.",
];

export function findings(items: Findings["findings"] | null = null): Findings {
  return {
    run_id: RUN_ID,
    run_status: "succeeded",
    run_message: null,
    total: items ? items.length : 1,
    filters: { tool: null, kind: null, q: null },
    available_tools: ["yara-x"],
    available_kinds: ["yara_match"],
    notices: NOTICES,
    findings: items ?? [
      {
        id: "1".repeat(32),
        kind: "yara_match",
        title: "Contains text that looks like the start of a URL",
        rule_id: "url_reference",
        rule_namespace: "default",
        rule_set_id: RULE_SET_ID,
        tags: [],
        metadata: [["description", "Contains text that looks like the start of a URL"]],
        fingerprint: "2".repeat(64),
        match_count: 1,
        evidence_truncated: false,
        evidence: [
          {
            id: 1,
            kind: "byte_range",
            pattern_id: "$https",
            file_offset: 7699,
            length: 8,
            xor_key: null,
            excerpt_hex: "68747470733a2f2f",
            excerpt_truncated: false,
            raw_json_pointer: "/scan/matching_rules/0/patterns/1/matches/0",
          },
        ],
      },
    ],
  };
}
