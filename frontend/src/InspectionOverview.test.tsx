import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { InspectionOverview } from "./InspectionOverview";
import { HOSTILE, RUN_ID, VERSION_ID, installFetch, json, run, step, version } from "./test/fakeApi";
import { renderWithClient } from "./test/render";
import type { Run, StepStatus } from "./api";

function open(runs: Run[], runId?: string, selected?: Run) {
  const calls = installFetch({
    [`GET /api/v1/sample-versions/${VERSION_ID}/runs`]: () => json({ runs }),
    [`GET /api/v1/runs/${runId}`]: () => selected ? json(selected) : json({ title: "Not found", status: 404 }, 404),
  });
  const view = renderWithClient(<InspectionOverview version={version()} runId={runId} />);
  return { ...view, calls };
}

describe("guided inspection overview", () => {
  it("explains metadata-only evidence and provides a real next action", async () => {
    open([]);
    expect(await screen.findByText("Header metadata only")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Choose a static inspection" }).getAttribute("href")).toBe("#pattern-matching");
    expect(screen.getByText(/publisher identity.*not been verified/i)).toBeTruthy();
    expect(screen.queryByText(/0 rule observations/)).toBeNull();
  });

  it("uses the latest failed run without falling back to an older success", async () => {
    open([run({ status: "failed", steps: [step("strings", { status: "failed", strings: null }), step("yara-x", { status: "skipped" })] }), run({ id: "a".repeat(32) })]);
    expect(await screen.findByText("Analysis could not complete")).toBeTruthy();
    expect(screen.getByText("Rule checks did not complete.")).toBeTruthy();
    expect(screen.queryByText(/1 rule observations/)).toBeNull();
  });

  it.each<StepStatus>(["queued", "running", "failed", "timed_out", "cancelled", "unsupported", "unavailable", "skipped"])("does not treat %s as a negative check", async status => {
    open([run({ status: "partial", steps: [step("yara-x", { status, message: HOSTILE })], counts: { findings: 0, evidence: 0, strings: 0 } })]);
    const table = await screen.findByRole("table", { name: "Checks in this run" });
    expect(within(table).getByText(HOSTILE)).toBeTruthy();
    expect(screen.getByText("Rule checks did not complete.")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("links observations to the exact run and discloses string caps", async () => {
    open([run({ steps: [step("strings", { strings: { total_found: 6000, stored: 5000, truncated: true, found_by_encoding: { ascii: 6000 } } }), step("yara-x")] })]);
    expect(await screen.findByText("Checks completed within their limits")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Inspect rule observations" }).getAttribute("href")).toBe(`/runs/${RUN_ID}#findings`);
    expect(screen.getByText(/Additional strings were not retained/)).toBeTruthy();
  });

  it("honors an explicitly selected run and never claims Ghidra found zero rules", async () => {
    const old = run({ id: "a".repeat(32), profile_id: "ghidra-static", steps: [ { ...step("strings"), tool: "ghidra", strings: null } ] });
    const { calls } = open([run()], old.id, old);
    expect(await screen.findByText(/Selected run from this page link/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Explore retained functions and limits" }).getAttribute("href")).toBe(`/runs/${old.id}`);
    expect(screen.queryByText(/rule observations recorded/)).toBeNull();
    expect(calls.every(call => !call.init?.method || call.init.method === "GET")).toBe(true);
  });

  it("shows reviewed observations as hypotheses with exact evidence links", async () => {
    open([run({ review: { template_version: "1", run_id: RUN_ID, version_id: VERSION_ID, total: 1, capped: false, glossary: {}, observations: [{ key: "finding", tool: "yara-x", tool_version: "1.22.1", adapter_version: "0.1", rule_id: "url_reference", rule_version: "0.2", rule_sha256: "a".repeat(64), statement: HOSTILE, hypothesis: "Text does not prove a request.", source_href: `/runs/${RUN_ID}#finding-source`, locations: ["File byte offset 64"], pointers: ["/scan/0"], evidence_capped: true }] } })]);
    expect(await screen.findByText(HOSTILE)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Inspect exact finding and evidence" }).getAttribute("href")).toBe(`/runs/${RUN_ID}#finding-source`);
    expect(screen.getByText("Possible interpretation:")).toBeTruthy();
    expect(screen.getByText("Text does not prove a request.")).toBeTruthy();
    expect(screen.getByText(/Source evidence is capped/)).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("refuses cross-version or changed-hash run evidence", async () => {
    const other = run({ sample: { ...run().sample, sha256: "0".repeat(64) } });
    open([], RUN_ID, other);
    expect(await screen.findByText(/Run evidence does not match this file/)).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Checks in this run" })).toBeNull();
  });

  it("shows an unavailable selected run without substituting the latest", async () => {
    open([run()], "a".repeat(32));
    expect(await screen.findByText("Run evidence could not be loaded")).toBeTruthy();
    expect(screen.queryByText("Checks completed within their limits")).toBeNull();
  });
});
