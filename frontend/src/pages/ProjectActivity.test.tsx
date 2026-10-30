import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ProjectActivity } from "./ProjectActivity";
import { installFetch, json, PROJECT_ID, RUN_ID, VERSION_ID } from "../test/fakeApi";
import { renderWithClient } from "../test/render";

const base = `/api/v1/projects/${PROJECT_ID}/activity`;
const types = ["project.created", "sample_version.imported", "analysis_run.queued", "analysis_run.running", "analysis_run.succeeded", "analysis_run.partial", "analysis_run.failed", "analysis_run.cancelled", "analysis_run.cancel_requested", "other"];
const items = types.map((type, index) => ({ id: String(index), type, at: "2026-10-29T12:00:00Z", sample_version_id: type === "project.created" ? null : VERSION_ID, run_id: type.startsWith("analysis_run") ? RUN_ID : null, status: null, reason: type === "analysis_run.failed" ? "worker_interrupted" : null }));

describe("Project activity", () => {
  it("links finding and evidence annotations to their exact source", async () => {
    installFetch({ [`GET ${base}?offset=0&limit=25`]: () => json({ items: [
      { ...items[0], id: "finding-event", type: "annotation.created", annotation_id: "note",
        sample_version_id: VERSION_ID, run_id: RUN_ID,
        annotation_target_type: "finding", annotation_target_id: "finding-one" },
      { ...items[0], id: "evidence-event", type: "annotation.revised", annotation_id: "note2",
        sample_version_id: VERSION_ID, run_id: RUN_ID,
        annotation_target_type: "evidence", annotation_target_id: "7" },
    ], next_offset: null }) });
    renderWithClient(<ProjectActivity projectId={PROJECT_ID} />);
    const links = await screen.findAllByRole("link", { name: "View analyst annotations" });
    expect(links.map((link) => link.getAttribute("href"))).toEqual([
      `/runs/${RUN_ID}?annotations=1#finding-finding-one`,
      `/runs/${RUN_ID}?annotations=1#evidence-7`,
    ]);
  });

  it("renders event labels and links, then loads the next page", async () => {
    const user = userEvent.setup();
    installFetch({
      [`GET ${base}?offset=0&limit=25`]: () => json({ items, next_offset: 25 }),
      [`GET ${base}?offset=25&limit=25`]: () => json({ items: [{ ...items[0], id: "next" }], next_offset: null }),
    });
    renderWithClient(<ProjectActivity projectId={PROJECT_ID} />);
    expect(await screen.findByText("Analysis completed")).toBeTruthy();
    for (const label of ["Project created", "Sample version imported", "Analysis queued", "Analysis started", "Analysis partially completed", "Analysis failed", "Analysis cancelled", "Cancellation requested", "Activity recorded"]) {
      expect(screen.getByText(label)).toBeTruthy();
    }
    expect(screen.getByText("The analysis worker stopped.")).toBeTruthy();
    expect(screen.getAllByRole("link", { name: "View run" })[0]!.getAttribute("href")).toBe(`/runs/${RUN_ID}`);
    expect(screen.getAllByRole("link", { name: "View sample version" })[0]!.getAttribute("href")).toBe(`/versions/${VERSION_ID}`);
    await user.click(screen.getByRole("button", { name: "Load more activity" }));
    expect(await screen.findAllByText("Project created")).toHaveLength(2);
    expect(screen.queryByRole("button", { name: "Load more activity" })).toBeNull();
  });

  it("shows loading and empty states", async () => {
    installFetch({ [`GET ${base}?offset=0&limit=25`]: () => json({ items: [], next_offset: null }) });
    renderWithClient(<ProjectActivity projectId={PROJECT_ID} />);
    expect(screen.getByRole("status").textContent).toContain("Loading activity…");
    expect(await screen.findByText("No activity recorded yet.")).toBeTruthy();
  });

  it("shows an error without inventing activity", async () => {
    installFetch({ [`GET ${base}?offset=0&limit=25`]: () => Promise.reject(new TypeError("Failed to fetch")) });
    renderWithClient(<ProjectActivity projectId={PROJECT_ID} />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText("Project created")).toBeNull();
  });
});
