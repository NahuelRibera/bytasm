import { act, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { PinnedReview } from "./PinnedReview";
import { VERSION_ID, installFetch, json, version } from "./test/fakeApi";
import { renderWithClient } from "./test/render";

const snapshot = { id: "a".repeat(32), sample: { version_id: VERSION_ID, sha256: version().sha256,
  size_bytes: version().size_bytes }, scope: "combined", exact_run_id: null, supersedes_id: null,
  created_at: "2026-10-31T10:00:00Z", catalog_version: "review-2", sources: [], observations: [],
  observations_total: 0, observations_capped: false, unknowns: ["Runtime behavior is unknown."],
  selection_explanation: "Reading order is not threat probability." };

describe("pinned review", () => {
  it("does not create a review on browse and previews only explicitly selected privacy policy", async () => {
    const calls = installFetch({
      [`GET /api/v1/sample-versions/${VERSION_ID}/reviews`]: () => json({ items: [], next_offset: null }),
      [`POST /api/v1/sample-versions/${VERSION_ID}/reviews`]: () => json(snapshot),
      [`GET /api/v1/reviews/${snapshot.id}`]: () => json(snapshot),
      [`POST /api/v1/reviews/${snapshot.id}/export/preview`]: () => json({ document: { strings: [] }, sha256: "b".repeat(64), size_bytes: 100 }),
    });
    renderWithClient(<PinnedReview version={version()} />);
    expect(calls.every(call => !call.init?.method || call.init.method === "GET")).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Create combined review" }));
    expect(await screen.findByText("Combined review")).toBeTruthy();
    expect(screen.getByText("Runtime behavior is unknown.")).toBeTruthy();
    await userEvent.click(screen.getByText("Preview and export this pinned review"));
    expect((screen.getByLabelText("Readable text values (may be private)") as HTMLInputElement).checked).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Preview export" }));
    expect(await screen.findByRole("button", { name: "Download previewed JSON" })).toBeTruthy();
    const call = calls.find(call => call.url.endsWith("/export/preview"));
    expect(JSON.parse(String(call?.init?.body)).string_values).toBe(false);
    await userEvent.click(screen.getByLabelText("Technical details"));
    expect(screen.queryByRole("button", { name: "Download previewed JSON" })).toBeNull();
  });
  it("cancels an in-flight download when privacy changes", async () => {
    let complete!: (value: Response) => void;
    let signal: AbortSignal | undefined;
    const createUrl = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createUrl });
    installFetch({
      [`GET /api/v1/sample-versions/${VERSION_ID}/reviews`]: () => json({ items: [], next_offset: null }),
      [`POST /api/v1/sample-versions/${VERSION_ID}/reviews`]: () => json(snapshot),
      [`GET /api/v1/reviews/${snapshot.id}`]: () => json(snapshot),
      [`POST /api/v1/reviews/${snapshot.id}/export/preview`]: () => json({ document: { strings: [] }, sha256: "b".repeat(64), size_bytes: 100 }),
      [`POST /api/v1/reviews/${snapshot.id}/export/json`]: init => {
        signal = init?.signal ?? undefined;
        return new Promise<Response>(resolve => { complete = resolve; });
      },
    });
    renderWithClient(<PinnedReview version={version()} />);
    await userEvent.click(screen.getByRole("button", { name: "Create combined review" }));
    await screen.findByText("Combined review");
    await userEvent.click(screen.getByText("Preview and export this pinned review"));
    await userEvent.click(screen.getByRole("button", { name: "Preview export" }));
    await userEvent.click(await screen.findByRole("button", { name: "Download previewed JSON" }));
    await userEvent.click(screen.getByLabelText("Readable text values (may be private)"));
    expect(signal?.aborted).toBe(true);
    await act(async () => { complete(json({ private: "must not download" })); });
    expect(createUrl).not.toHaveBeenCalled();
  });

});
