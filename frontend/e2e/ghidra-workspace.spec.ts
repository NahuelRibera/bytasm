import { expect, test } from "@playwright/test";
import { FIXTURES_URL } from "../playwright.config";
import { expectNoAxeViolations } from "./helpers";

// Synthetic API documents exercise presentation only. This is not provider verification.
test("Ghidra evidence presentation is keyboard-accessible at 360 px with hostile text", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  const id = "e".repeat(32);
  const hostile = '<img src=x onerror="window.__pwned=1">';
  const address = { space: "ram", address: "00401000" };
  const fn = { name: hostile, namespace: "global", entry: address, body_size: 12, pseudocode: `void example() { /* ${hostile} */ }`, pseudocode_status: "available", pseudocode_truncated: false, instructions_truncated: false, calls_truncated: false, instructions: [{ address, bytes_hex: "c3", text: "RET" }], calls: [{ source: address, target: { space: "ram", address: "00401020" } }], limitations: [] };
  const sample = { project_id: "p", project_name: "Presentation test", sample_id: "s", sample_name: "Authored fixture", version_id: "v", version_label: "v1", sha256: "a".repeat(64), size_bytes: 1234, detected_format: "ELF", admitted_under: "fixtures" };
  const run = { id, status: "succeeded", failure_reason: null, failure_message: null, cancel_requested: false, queued_at: null, started_at: null, finished_at: null, bytasm_version: "0.4.0", profile_id: "ghidra-static", profile_name: "Ghidra static review", rule_set: { id: "rules", label: "No rule matching selected", sha256: "b".repeat(64) }, sample, steps: [{ index: 0, tool: "ghidra", adapter: "ghidra_headless", status: "succeeded", message: null, invocation_id: "inv", tool_version: "12.2", adapter_version: "1", started_at: null, finished_at: null, duration_ms: 100, timeout_seconds: 180, failure_reason: null, raw_output_sha256: "c".repeat(64), strings: null, warnings: [] }], counts: { findings: 0, evidence: 0, strings: 0 } };
  await page.route(`**/api/v1/runs/${id}`, route => route.fulfill({ json: run }));
  await page.route(`**/api/v1/runs/${id}/ghidra`, route => route.fulfill({ json: { run_id: id, project_id: "p", version_id: "v", input_sha256: sample.sha256, run_status: "succeeded", step_status: "succeeded", invocation_id: "inv", available: true, provenance: null, summary: { observations: [{ text: "Ghidra identified one function.", citation: "/api/v1/invocations/inv/raw#/functions" }], hypotheses: [], analyst_notes: [], recommendations: ["Inspect the retained functions."], limitations: ["No runtime behavior was inspected."] }, coverage: { completed: 1, total: 1 }, function_count: 1, stored_functions: 1, functions_truncated: false } }));
  await page.route(`**/api/v1/runs/${id}/ghidra/functions?*`, route => route.fulfill({ json: { run_id: id, matched: 1, total: 1, offset: 0, limit: 25, items: [{ ...fn, index: 0 }] } }));
  await page.route(`**/api/v1/runs/${id}/ghidra/functions/0`, route => route.fulfill({ json: { run_id: id, invocation_id: "inv", index: 0, citation: "/api/v1/invocations/inv/raw#/functions/0", function: fn } }));
  await page.goto(`${FIXTURES_URL}/runs/${id}`);
  await expect(page.getByRole("heading", { name: "What did the static analysis observe?" })).toBeVisible();
  const inspect = page.getByRole("button", { name: `Inspect ${hostile}` });
  await inspect.focus();
  await page.keyboard.press("Enter");
  const evidence = page.getByRole("region", { name: "Selected function evidence" });
  await expect(evidence.getByText("Ghidra pseudocode", { exact: true })).toBeVisible();
  await evidence.getByText("Static call relationships (1 retained)", { exact: true }).click();
  await expect(evidence.getByRole("table", { name: `Direct static call evidence for ${hostile}` })).toBeVisible();
  await expectNoAxeViolations(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
  await evidence.getByRole("button", { name: "Close function" }).click();
  await expect(inspect).toBeFocused();
});
