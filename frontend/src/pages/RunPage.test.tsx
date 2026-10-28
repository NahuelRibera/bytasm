import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import type { Findings, Run } from "../api";
import {
  HOSTILE,
  RULE_SET_ID,
  RUN_ID,
  findings,
  health,
  installFetch,
  json,
  ruleSet,
  run,
  step,
} from "../test/fakeApi";
import { renderWithClient } from "../test/render";

function openRun(r: Run = run(), f: Findings = findings(), extra = {}) {
  window.history.pushState({}, "", `/runs/${RUN_ID}`);
  const calls = installFetch({
    "GET /api/v1/health": () => json(health()),
    [`GET /api/v1/runs/${RUN_ID}`]: () => json(r),
    [`GET /api/v1/runs/${RUN_ID}/findings`]: () => json(f),
    [`GET /api/v1/rule-sets/${RULE_SET_ID}`]: () => json(ruleSet()),
    ...extra,
  });
  return { ...renderWithClient(<App />), calls };
}

describe("Analysis run page", () => {
  it("shows provenance, a match with its evidence, and what a match means", async () => {
    const user = userEvent.setup();
    openRun();
    expect(await screen.findByText(/1 rule matched/)).toBeTruthy();
    expect(screen.getAllByText("bytasm-rules@0.2.0").length).toBeGreaterThan(0);
    expect(screen.getByTestId("run-sample-sha256").textContent).toMatch(/^71f62a00/);
    expect(screen.getByText(/needs human interpretation/)).toBeTruthy();
    expect(screen.getByText(/does not show that a file is safe/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Inspect url_reference" }));
    const panel = await screen.findByRole("region", { name: /Evidence/ });
    expect(within(panel).getByText("0x1e13")).toBeTruthy();
    expect(within(panel).getByText("68 74 74 70 73 3a 2f 2f")).toBeTruthy();
    expect(within(panel).getByText("https://")).toBeTruthy();
    // The exact rule text from the rule set the run used.
    expect(await within(panel).findByText(/\$https = "https:\/\/" ascii/)).toBeTruthy();
    expect(document.activeElement?.id).toBe("evidence-heading");

    await user.click(within(panel).getByRole("button", { name: "Close evidence" }));
    expect(screen.queryByRole("region", { name: /Evidence/ })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Inspect url_reference" }));
    expect(document.body.textContent).not.toMatch(/malicious file|risk score|detected malware|severity/i);
  });

  it("states that no match is not evidence of safety", async () => {
    openRun(run({ counts: { findings: 0, evidence: 0, strings: 12 } }), findings([]));
    expect(await screen.findByText("No rule matched.")).toBeTruthy();
    expect(screen.getByText(/This is not evidence that the file is safe/)).toBeTruthy();
    expect(screen.queryByRole("table", { name: /Findings/ })).toBeNull();
  });

  it("renders hostile rule metadata, identifiers and excerpts as text", async () => {
    const user = userEvent.setup();
    const hostile = findings();
    const finding = hostile.findings[0]!;
    finding.title = HOSTILE;
    finding.rule_id = "url_reference";
    finding.metadata = [["description", HOSTILE]];
    finding.tags = [HOSTILE];
    finding.evidence[0]!.pattern_id = HOSTILE;
    // "<script>" as bytes: the ASCII preview must stay text.
    finding.evidence[0]!.excerpt_hex = "3c7363726970743e";
    const { container } = openRun(run(), hostile);
    await user.click(await screen.findByRole("button", { name: "Inspect url_reference" }));
    expect(screen.getAllByText(HOSTILE).length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText("<script>")).toBeTruthy();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("explains a failed run and shows no findings", async () => {
    openRun(
      run({
        status: "failed",
        failure_reason: "nonzero_exit",
        failure_message: "The strings extractor process failed. No step kept any results.",
        steps: [
          step("strings", { status: "failed", raw_output_sha256: null, strings: null, message: "x" }),
          step("yara-x", { status: "timed_out", raw_output_sha256: null }),
        ],
        counts: { findings: 0, evidence: 0, strings: 0 },
      }),
    );
    expect(await screen.findByText("The run did not complete")).toBeTruthy();
    expect(screen.getByText(/No step kept any results/)).toBeTruthy();
    expect(screen.getAllByText("Timed out").length).toBe(1);
    expect(screen.getAllByText(/Not analysed/).length).toBe(2);
    expect(screen.queryByRole("table", { name: /Findings/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Download the raw/ })).toBeNull();
  });

  it("marks a partial run clearly and offers only what completed", async () => {
    const message =
      "Partial result: YARA-X did not complete. YARA-X did not finish within the time limit. " +
      "Results from strings are complete and kept. This run has no findings: absence of a " +
      "YARA-X match does not mean the pattern is absent.";
    openRun(
      run({
        status: "partial",
        failure_reason: "timeout",
        failure_message: message,
        steps: [
          step("strings"),
          step("yara-x", {
            status: "timed_out",
            raw_output_sha256: null,
            message: "YARA-X did not finish within the time limit. No results from this step were kept.",
          }),
        ],
        counts: { findings: 0, evidence: 0, strings: 12 },
      }),
    );
    const banner = await screen.findByTestId("partial-banner");
    expect(within(banner).getByText("Partial result")).toBeTruthy();
    expect(within(banner).getByText(message)).toBeTruthy();
    expect(screen.getAllByText("Partial").length).toBeGreaterThan(0);
    expect(screen.getByText(/YARA-X did not complete in this run, so there are no findings/)).toBeTruthy();
    expect(screen.getByText(/No results from this step were kept/)).toBeTruthy();
    const links = screen.getAllByRole("link", { name: /Download the raw/ });
    expect(links.map((link) => link.getAttribute("href"))).toEqual([
      `/api/v1/invocations/${"a".repeat(32)}/raw`,
    ]);
    expect(screen.getByRole("link", { name: /Search the strings/ }).getAttribute("href")).toContain(
      "?tab=strings",
    );
  });

  it("shows which steps finished before a cancel", async () => {
    openRun(
      run({
        status: "cancelled",
        cancel_requested: true,
        failure_message:
          "Cancelled. strings finished before the cancel and its results are kept; steps that had not finished kept nothing.",
        steps: [
          step("strings"),
          step("yara-x", {
            status: "skipped",
            invocation_id: null,
            tool_version: null,
            raw_output_sha256: null,
            message: "Not run (YARA-X): the run was cancelled first.",
          }),
        ],
        counts: { findings: 0, evidence: 0, strings: 12 },
      }),
    );
    expect(await screen.findByText("Run cancelled")).toBeTruthy();
    expect(screen.getByText("Skipped")).toBeTruthy();
    expect(screen.getByText("Not run (YARA-X): the run was cancelled first.")).toBeTruthy();
  });

  it("shows the technical log on demand and filters findings by search", async () => {
    const user = userEvent.setup();
    const { calls } = openRun(run(), findings(), {
      [`GET /api/v1/runs/${RUN_ID}/log`]: () =>
        json({
          run_id: RUN_ID,
          entries: [{ seq: 0, at: null, step_index: null, message: "Run queued with profile default-static." }],
          next_cursor: 0,
          complete: true,
        }),
      [`GET /api/v1/runs/${RUN_ID}/findings?q=nothing`]: () => json({ ...findings([]), total: 1 }),
    });
    await user.click(await screen.findByText("Technical log"));
    expect(await screen.findByText(/Run queued with profile default-static/)).toBeTruthy();
    await user.type(screen.getByLabelText("Search findings"), "nothing{Enter}");
    expect(await screen.findByText(/No finding matches/)).toBeTruthy();
    expect(screen.getByText(/0 of 1 shown/)).toBeTruthy();
    expect(calls.some((call) => call.url.endsWith("/findings?q=nothing"))).toBe(true);
  });

  it("cancels an active run once and disables the button while it stops", async () => {
    const user = userEvent.setup();
    const running = run({
      status: "running",
      finished_at: null,
      steps: [step("strings"), step("yara-x", { status: "running", invocation_id: null })],
      counts: { findings: 0, evidence: 0, strings: 12 },
    });
    const { calls } = openRun(running, findings([]), {
      [`POST /api/v1/runs/${RUN_ID}/cancel`]: () => json({ ...running, cancel_requested: true }, 202),
    });
    const button = await screen.findByRole("button", { name: "Cancel run" });
    await user.click(button);
    expect(await screen.findByRole("button", { name: "Cancelling…" })).toHaveProperty("disabled", true);
    expect(screen.getByText(/Cancellation requested/)).toBeTruthy();
    const posts = calls.filter((call) => call.init?.method === "POST");
    expect(posts).toHaveLength(1);
    expect(new Headers(posts[0]!.init?.headers).get("X-Bytasm-Request")).toBe("1");
  });

  it("warns when no worker is running for a queued run", async () => {
    window.history.pushState({}, "", `/runs/${RUN_ID}`);
    installFetch({
      "GET /api/v1/health": () => json({ ...health(), worker_last_seen_seconds: null }),
      [`GET /api/v1/runs/${RUN_ID}`]: () =>
        json(run({ status: "queued", started_at: null, finished_at: null })),
    });
    renderWithClient(<App />);
    expect(await screen.findByText(/No analysis worker seems to be running/)).toBeTruthy();
    await waitFor(() => expect(screen.getAllByText("Queued").length).toBeGreaterThan(0));
  });
});
