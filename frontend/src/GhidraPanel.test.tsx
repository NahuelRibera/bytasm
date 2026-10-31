import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { AnalysisPanel } from "./AnalysisPanel";
import { GhidraPanel } from "./GhidraPanel";
import { ghidraApi, type GhidraDetail, type GhidraOverview } from "./ghidra-api";
import { HOSTILE, installFetch, json, run, RUN_ID, version, VERSION_ID } from "./test/fakeApi";
import { renderWithClient } from "./test/render";

const base = `/api/v1/runs/${RUN_ID}/ghidra`;
const address = { space: "ram", address: "00401000" };
const overview: GhidraOverview = {
  run_id: RUN_ID, project_id: "project", version_id: "version", input_sha256: "a".repeat(64), run_status: "succeeded", step_status: "succeeded", invocation_id: "invocation", available: true,
  provenance: { tool: "ghidra", tool_version: "12.2", adapter_version: "1", profile_sha256: "b".repeat(64), script_sha256: "c".repeat(64), raw_output_sha256: "d".repeat(64), language_id: "x86:LE:64:default", compiler: "gcc" },
  summary: { observations: [{ text: "Ghidra identified 30 functions.", citation: "/api/v1/invocations/invocation/raw#/functions" }], hypotheses: [], analyst_notes: [], recommendations: ["Inspect retained functions."], limitations: ["No runtime behavior was inspected."] },
  coverage: { completed: 1, total: 1 }, function_count: 30, stored_functions: 30, functions_truncated: true,
};
const detail: GhidraDetail = {
  run_id: RUN_ID, invocation_id: "invocation", index: 0, citation: "/api/v1/invocations/invocation/raw#/functions/0",
  function: { name: HOSTILE, namespace: "global", entry: address, body_size: 20, pseudocode: HOSTILE, pseudocode_status: "available", pseudocode_truncated: true, instructions_truncated: true, calls_truncated: false, limitations: ["Details are bounded."], instructions: [{ address, bytes_hex: "e800000000", text: HOSTILE }], calls: [{ source: address, target: { space: "ram", address: "00401020" } }] },
};
function setup(value = overview) {
  const calls = installFetch({
    [`GET ${base}`]: () => json(value),
    [`GET ${base}/functions?offset=0&limit=25`]: () => json({ run_id: RUN_ID, matched: 30, total: 30, offset: 0, limit: 25, items: [{ ...detail.function, index: 0 }] }),
    [`GET ${base}/functions?offset=25&limit=25`]: () => json({ run_id: RUN_ID, matched: 30, total: 30, offset: 25, limit: 25, items: [{ ...detail.function, name: "last_function", index: 25 }] }),
    [`GET ${base}/functions?q=absent&offset=0&limit=25`]: () => json({ run_id: RUN_ID, matched: 0, total: 30, offset: 0, limit: 25, items: [] }),
    [`GET ${base}/functions/0`]: () => json(detail),
  });
  return { calls, ...renderWithClient(<GhidraPanel run={run({ profile_id: "ghidra-static", profile_name: "Ghidra function review" })} />) };
}
it("links observations to original evidence and inspects escaped pseudocode, addresses and static calls", async () => {
  const user = userEvent.setup();
  const { container } = setup();
  expect(await screen.findByText("Ghidra identified 30 functions.")).toBeTruthy();
  expect(screen.getByRole("progressbar", { name: "Completed Ghidra steps" }).getAttribute("value")).toBe("1");
  expect(screen.getByRole("link", { name: /Why am I seeing this/ }).getAttribute("href")).toContain("/invocation/raw#/functions");
  expect(screen.getByText(/inventory reached its limit/)).toBeTruthy();
  await user.click(await screen.findByRole("button", { name: `Inspect ${HOSTILE}` }));
  const evidence = await screen.findByRole("region", { name: "Selected function evidence" });
  expect(await within(evidence).findByText("Decompiler approximation, not original source code. Status: available. Output was truncated.")).toBeTruthy();
  expect(within(evidence).getByRole("button", { name: "Copy function entry with address space" })).toBeTruthy();
  await user.click(within(evidence).getByText(/Assembly and instruction bytes/));
  expect(within(evidence).getByText("e800000000")).toBeTruthy();
  await user.click(within(evidence).getByText(/Static call relationships \(1 retained\)/));
  expect(within(evidence).getByRole("table", { name: `Direct static call evidence for ${HOSTILE}` })).toBeTruthy();
  expect(within(evidence).getByText(/They do not represent execution flow/)).toBeTruthy();
  expect(container.querySelector("script, img")).toBeNull();
  await user.click(within(evidence).getByRole("button", { name: "Close function" }));
  expect(document.activeElement).toBe(screen.getByRole("button", { name: `Inspect ${HOSTILE}` }));
});
it("uses bounded server pagination and describes empty filters without implying absence", async () => {
  const user = userEvent.setup(); const { calls } = setup();
  await user.click(await screen.findByRole("button", { name: "Next functions" }));
  expect(await screen.findByText("global::last_function")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Next functions" })).toHaveProperty("disabled", true);
  await user.type(screen.getByLabelText("Function name, namespace or address"), "absent");
  await user.click(screen.getByRole("button", { name: "Search functions" }));
  expect(await screen.findByText(/No stored function matches this search/)).toBeTruthy();
  expect(calls.some(call => call.url.endsWith("?q=absent&offset=0&limit=25"))).toBe(true);
});
it("keeps failed or cancelled work distinct from zero functions and offers no evidence export", async () => {
  const { calls } = setup({ ...overview, available: false, run_status: "cancelled", step_status: "cancelled", provenance: null, function_count: null, stored_functions: 0, coverage: { completed: 0, total: 1 }, summary: { ...overview.summary, observations: [] } });
  expect(await screen.findByText(/No completed Ghidra observations are available. Step status: cancelled/)).toBeTruthy();
  expect(screen.queryByRole("link", { name: "Export Ghidra report (JSON)" })).toBeNull();
  expect(calls.filter(call => call.url.includes("/functions"))).toHaveLength(0);
});
it("retains exact escaped run scope in attachment URLs", () => {
  expect(ghidraApi.exportUrl("a/b", "html")).toBe("/api/v1/runs/a%2Fb/ghidra/export?format=html");
});

it("offers the real Ghidra profile only after verified availability and submits its exact identifier", async () => {
  const user = userEvent.setup();
  const calls = installFetch({
    "GET /api/v1/tools": () => json({ tools: [], profiles: [{ id: "ghidra-static", name: "Ghidra static review", steps: ["ghidra"], limitations: "First 16 functions only." }], optional_providers: [{ provider: "ghidra", available: true, analysis_enabled: true, health_check: "passed" }] }),
    [`GET /api/v1/sample-versions/${VERSION_ID}/runs`]: () => json({ runs: [] }),
    "GET /api/v1/rule-sets/current": () => json({ code: "unavailable", status: 503, detail: "Rules unavailable", title: "Unavailable" }, 503),
    [`POST /api/v1/sample-versions/${VERSION_ID}/runs`]: () => json(run({ profile_id: "ghidra-static" }), 202),
  });
  renderWithClient(<AnalysisPanel version={version()} />);
  await screen.findByRole("option", { name: "Ghidra static review" });
  await user.selectOptions(screen.getByLabelText("Analysis profile"), "ghidra-static");
  await user.click(screen.getByRole("button", { name: "Run Ghidra static analysis…" }));
  await user.click(screen.getByRole("button", { name: "Start run" }));
  const post = calls.find(call => call.init?.method === "POST");
  expect(JSON.parse(String(post?.init?.body))).toEqual({ profile_id: "ghidra-static" });
});
it("keeps an unverified Ghidra profile out of the selection", async () => {
  installFetch({
    "GET /api/v1/tools": () => json({ tools: [], profiles: [{ id: "ghidra-static", name: "Ghidra static review", steps: ["ghidra"] }], optional_providers: [{ provider: "ghidra", available: false, analysis_enabled: false }] }),
    [`GET /api/v1/sample-versions/${VERSION_ID}/runs`]: () => json({ runs: [] }),
    "GET /api/v1/rule-sets/current": () => json({ code: "unavailable", status: 503, detail: "Rules unavailable", title: "Unavailable" }, 503),
  });
  renderWithClient(<AnalysisPanel version={version()} />);
  await screen.findByText("No analysis runs yet for this version.");
  expect(screen.queryByRole("option", { name: "Ghidra static review" })).toBeNull();
});

it("requests an explicit selected set through the typed API and links to its queued run", async () => {
  const user = userEvent.setup();
  const calls = installFetch({
    [`GET ${base}`]: () => json(overview),
    [`GET ${base}/functions?offset=0&limit=25`]: () => json({ run_id: RUN_ID, matched: 1, total: 1, offset: 0, limit: 25, items: [{ ...detail.function, index: 0 }] }),
    [`POST ${base}/inspections`]: () => json({ run_id: "selected-run", source_run_id: RUN_ID, reused: false }, 202),
  });
  renderWithClient(<GhidraPanel run={run({ profile_id: "ghidra-static" })} />);
  const request = await screen.findByRole("button", { name: "Request details (0/8 selected)" });
  expect(request).toHaveProperty("disabled", true);
  await user.click(await screen.findByRole("checkbox", { name: `Select ${HOSTILE} at ram:00401000` }));
  await user.click(screen.getByRole("button", { name: "Request details (1/8 selected)" }));
  expect((await screen.findByRole("link", { name: "Open selected-function run" })).getAttribute("href")).toBe("/runs/selected-run");
  const post = calls.find(call => call.init?.method === "POST");
  expect(JSON.parse(String(post?.init?.body))).toEqual({ indices: [0] });
  expect((post?.init?.headers as Record<string, string>)["X-Bytasm-Request"]).toBe("1");
  expect(screen.getByText(/Before exporting or sharing/)).toBeTruthy();
});

it("explores exact one-hop evidence with unresolved targets and partial limits", async () => {
  const user = userEvent.setup();
  installFetch({
    [`GET ${base}`]: () => json(overview),
    [`GET ${base}/functions?offset=0&limit=25`]: () => json({ run_id: RUN_ID, matched: 1, total: 1, offset: 0, limit: 25, items: [{ ...detail.function, index: 0 }] }),
    [`GET ${base}/functions/0`]: () => json(detail),
    [`GET ${base}/functions/0/relationships`]: () => json({ run_id: RUN_ID, center_index: 0, node_limit: 33, edge_limit: 32, retained_matches: 1, truncated: false, inventory_complete: false, limitations: ["Retained calls only."], edges: [{ source_index: 0, target_index: null, call_site: address, target: { space: "external", address: "00000001" }, reference_type: "direct_static_call", citation: "/api/v1/invocations/inv/raw#/functions/0/calls/0" }] }),
  });
  renderWithClient(<GhidraPanel run={run({ profile_id: "ghidra-static" })} />);
  await user.click(await screen.findByRole("button", { name: `Inspect ${HOSTILE}` }));
  await user.click(await screen.findByRole("button", { name: "Explore one-hop relationships" }));
  expect(await screen.findByText("No exact inventory entry; unresolved here")).toBeTruthy();
  expect(screen.getByText(/This view is partial/)).toBeTruthy();
  expect(screen.getByRole("link", { name: "Direct static call evidence 1" }).getAttribute("href")).toContain("#/functions/0/calls/0");
});
