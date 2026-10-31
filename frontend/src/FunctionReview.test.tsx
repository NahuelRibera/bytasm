import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { FunctionReview } from "./FunctionReview";
import { installFetch, json } from "./test/fakeApi";
import { renderWithClient } from "./test/render";
import type { GhidraDetail } from "./ghidra-api";

it("keeps analyst text after a stale-save conflict without changing evidence", async () => {
  const detail = { run_id: "a".repeat(32), invocation_id: "b".repeat(32), index: 0,
    function: { pseudocode: null } } as GhidraDetail;
  const url = `/api/v1/runs/${detail.run_id}/ghidra/functions/0/review`;
  const calls = installFetch({
    [`GET ${url}`]: () => json({ identity: detail, current: null, revisions: [],
      history_capped: false, notice: "Reviewed is not harmless." }),
    [`POST ${url}`]: () => json({ code: "annotation_stale", status: 409, detail: "A newer revision exists." }, 409),
  });
  renderWithClient(<FunctionReview detail={detail} />);
  await userEvent.click(screen.getByText("Analyst review, bookmark and notes"));
  await userEvent.type(await screen.findByLabelText("Analyst note"), "Keep my investigation text");
  await userEvent.click(screen.getByRole("button", { name: "Save immutable revision" }));
  expect(await screen.findByText("A newer revision exists.")).toBeTruthy();
  expect((screen.getByLabelText("Analyst note") as HTMLTextAreaElement).value).toBe("Keep my investigation text");
  const posted = calls.find(call => call.init?.method === "POST");
  expect(JSON.parse(String(posted?.init?.body)).expected_revision).toBe(0);
  expect(detail.function.pseudocode).toBeNull();
});

describe("function review source identity", () => {
  it("does not render an editor for another invocation", async () => {
    const detail = { run_id: "a".repeat(32), invocation_id: "b".repeat(32), index: 0,
      function: { pseudocode: null } } as GhidraDetail;
    installFetch({ [`GET /api/v1/runs/${detail.run_id}/ghidra/functions/0/review`]: () => json({
      identity: { run_id: detail.run_id, invocation_id: "c".repeat(32) }, current: null,
      revisions: [], notice: "Mismatched source", history_capped: false,
    }) });
    renderWithClient(<FunctionReview detail={detail} />);
    expect(screen.queryByLabelText("Analyst note")).toBeNull();
  });
});


it("preserves an existing citation when only a bookmark changes", async () => {
  const citation = { text_sha256: "d".repeat(64), start_line: 1, end_line: 1 };
  const detail = { run_id: "a".repeat(32), invocation_id: "b".repeat(32), index: 0,
    function: { pseudocode: "return 1;" } } as GhidraDetail;
  const url = `/api/v1/runs/${detail.run_id}/ghidra/functions/0/review`;
  const workspace = { identity: detail, current: { revision: 1, alias: "", bookmarked: false,
    collections: [], state: "in_progress", note: "My cited note", citation },
    revisions: [], history_capped: false, notice: "Exact output scope." };
  const calls = installFetch({ [`GET ${url}`]: () => json(workspace),
    [`POST ${url}`]: () => json(workspace) });
  renderWithClient(<FunctionReview detail={detail} />);
  await userEvent.click(screen.getByText("Analyst review, bookmark and notes"));
  const preserve = await screen.findByLabelText("Preserve the existing exact-text citation (uncheck to remove)");
  expect((preserve as HTMLInputElement).checked).toBe(true);
  await userEvent.click(screen.getByLabelText("Bookmark this exact function"));
  await userEvent.click(screen.getByRole("button", { name: "Save immutable revision" }));
  const posted = calls.find(call => call.init?.method === "POST");
  expect(JSON.parse(String(posted?.init?.body)).citation).toEqual(citation);
});
