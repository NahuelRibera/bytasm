import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ComparePage } from "./ComparePage";
import { CATEGORIES, type CategoryDiff, type Change, type Comparison } from "../compare-api";
import { installFetch, json, PROJECT_ID, SAMPLE_ID, VERSION_ID, RUN_ID } from "../test/fakeApi";
import { renderWithClient } from "../test/render";

const older = "d".repeat(32);
const oldest = "f".repeat(32);
const foreign = "1".repeat(32);
const samplesUrl = `/api/v1/projects/${PROJECT_ID}/samples`;
const compareUrl = (a = older, b = VERSION_ID, offset = 0) =>
  `/api/v1/compare?a=${a}&b=${b}&offset=${offset}&limit=50`;
const versions = [
  { id: oldest, version_label: "First", imported_at: "2026-10-27T12:00:00Z" },
  { id: VERSION_ID, version_label: "Newest", imported_at: "2026-10-29T12:00:00Z" },
  { id: older, version_label: "Previous", imported_at: "2026-10-28T12:00:00Z" },
].map((item) => ({ ...item, sha256: "a".repeat(64), size_bytes: 30, detected_format: "PE", architecture: "x86_64", admitted_under: "fixtures" }));
const samples = [
  { id: SAMPLE_ID, name: "Demo binary", versions },
  { id: "2".repeat(32), name: "Other sample", versions: [{ ...versions[0], id: foreign, version_label: "Foreign version" }] },
];
const blankDiff: CategoryDiff = {
  status: "comparable",
  reason: null,
  a_status: "succeeded",
  b_status: "succeeded",
  added: 0,
  removed: 0,
  changed: 0,
  total_rows: 0,
  rows: [],
  next_offset: null,
};
function comparison(overrides: Partial<Comparison> = {}): Comparison {
  const side = { sample_id: SAMPLE_ID, project_id: PROJECT_ID, sha256: "a".repeat(64), run_id: RUN_ID, run_status: "succeeded" };
  return {
    a: { ...side, version_id: older },
    b: { ...side, version_id: VERSION_ID },
    identical_content: false,
    warnings: [],
    categories: Object.fromEntries(CATEGORIES.map((category) => [category, { ...blankDiff }])),
    ...overrides,
  };
}
function changedRows(): Change[] {
  return [
    { key: "New section", change: "added", before: null, after: { name: ".new" }, after_ref: { run_id: RUN_ID } },
    { key: "Removed import", change: "removed", before: { library: "old.dll" }, after: null, before_ref: { run_id: RUN_ID } },
    { key: "<script>alert(1)</script>", change: "changed", before: { size_bytes: 10 }, after: { size_bytes: 20 }, before_ref: { run_id: RUN_ID }, after_ref: { run_id: RUN_ID } },
  ];
}
function setup(extra = {}) {
  installFetch({
    [`GET ${samplesUrl}`]: () => json(samples),
    [`GET ${compareUrl()}`]: () => json(comparison()),
    ...extra,
  });
  renderWithClient(<ComparePage projectId={PROJECT_ID} sampleId={SAMPLE_ID} />);
}

describe("Version comparison", () => {
  it("defaults to the chronologically newest versions with mixed timestamp precision", async () => {
    const mixed = versions.map((v, i) => ({ ...v, imported_at: [
      "2026-10-29T12:00:00Z", "2026-10-29T12:00:00.000002Z", "2026-10-29T12:00:00.000001Z"
    ][i] }));
    setup({ [`GET ${samplesUrl}`]: () => json([{ ...samples[0], versions: mixed }]) });
    const b = await screen.findByRole("combobox", { name: "Version B" });
    expect((b as HTMLSelectElement).value).toBe(VERSION_ID);
    expect((screen.getByRole("combobox", { name: "Version A" }) as HTMLSelectElement).value).toBe(older);
  });

  it("loads sample versions and defaults to the newest two in the same sample", async () => {
    const user = userEvent.setup();
    setup({ [`GET ${compareUrl(oldest)}`]: () => json(comparison()) });
    expect(screen.getByRole("status").textContent).toContain("Loading versions");
    const a = await screen.findByRole("combobox", { name: "Version A" });
    const b = screen.getByRole("combobox", { name: "Version B" });
    expect((a as HTMLSelectElement).value).toBe(older);
    expect((b as HTMLSelectElement).value).toBe(VERSION_ID);
    expect(within(a).getAllByRole("option").map((option) => option.textContent)).toEqual([
      "Newest · aaaaaaaaaaaa", "Previous · aaaaaaaaaaaa", "First · aaaaaaaaaaaa",
    ]);
    expect(screen.queryByRole("option", { name: /Foreign version/ })).toBeNull();
    expect(screen.getByRole("link", { name: "View version A" }).getAttribute("href")).toBe(`/versions/${older}`);
    expect(screen.getByRole("link", { name: "View version B" }).getAttribute("href")).toBe(`/versions/${VERSION_ID}`);
    expect(screen.getByRole("link", { name: "← Project" }).getAttribute("href")).toBe(`/projects/${PROJECT_ID}`);
    await user.selectOptions(a, oldest);
    expect(screen.getByRole("link", { name: "View version A" }).getAttribute("href")).toBe(`/versions/${oldest}`);
    expect(await screen.findByText("No differences in this category.")).toBeTruthy();
  });

  it("shows comparison loading before empty results arrive", async () => {
    setup({ [`GET ${compareUrl()}`]: () => new Promise<Response>(() => {}) });
    expect((await screen.findByRole("status")).textContent).toContain("Loading versions");
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain("Comparing versions…"));
  });

  it("shows empty sample states", async () => {
    setup({ [`GET ${samplesUrl}`]: () => json([{ ...samples[0], versions: [versions[0]] }]) });
    expect(await screen.findByText("Import another version of this sample to compare it.")).toBeTruthy();
    expect(screen.queryByRole("combobox")).toBeNull();
  });

  it("does not compare a sample outside the selected project", async () => {
    setup({ [`GET ${samplesUrl}`]: () => json([]) });
    expect(await screen.findByText("No sample with this ID in this project.")).toBeTruthy();
  });

  it("reports sample fetch errors", async () => {
    setup({ [`GET ${samplesUrl}`]: () => Promise.reject(new TypeError("Offline")) });
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByRole("combobox")).toBeNull();
  });

  it("reports comparison errors without presenting an empty comparison", async () => {
    setup({ [`GET ${compareUrl()}`]: () => json({ detail: "Comparison unavailable.", title: "Unavailable", status: 503 }, 503) });
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText("No differences in this category.")).toBeNull();
    expect((screen.getByRole("button", { name: "Export comparison JSON report" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("renders additions, removals and changes as text with version source links", async () => {
    const data = comparison();
    data.categories.metadata = { ...blankDiff, added: 1, removed: 1, changed: 1, total_rows: 3, rows: changedRows() };
    setup({ [`GET ${compareUrl()}`]: () => json(data) });
    expect(await screen.findByText("+ Added")).toBeTruthy();
    expect(screen.getByText("− Removed")).toBeTruthy();
    expect(screen.getByText("~ Changed")).toBeTruthy();
    expect(screen.getByText("<script>alert(1)</script>")).toBeTruthy();
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getByText("old.dll")).toBeTruthy();
    expect(screen.getByText(".new")).toBeTruthy();
    expect(screen.getAllByText("Not present")).toHaveLength(2);
    expect(screen.getByText("metadata: +1 added · −1 removed · ~1 changed")).toBeTruthy();
    expect(screen.getAllByRole("link", { name: "Inspect source A" })[0]!.getAttribute("href")).toBe(`/versions/${older}`);
    expect(screen.getAllByRole("link", { name: "Inspect source B" })[0]!.getAttribute("href")).toBe(`/versions/${VERSION_ID}`);
  });

  it("switches category buttons and links findings and evidence to their source runs", async () => {
    const user = userEvent.setup();
    const data = comparison();
    data.categories.findings = { ...blankDiff, added: 1, total_rows: 1, rows: [{ key: "Finding added", change: "added", before: null, after: { rule: "matched" }, after_ref: { run_id: RUN_ID, finding_id: "finding-one" } }] };
    data.categories.evidence = { ...blankDiff, removed: 1, total_rows: 1, rows: [{ key: "Evidence removed", change: "removed", before: { offset: 12 }, after: null, before_ref: { run_id: RUN_ID, evidence_id: 7 } }] };
    setup({ [`GET ${compareUrl()}`]: () => json(data) });
    await screen.findByText("No differences in this category.");
    const navigation = screen.getByRole("navigation", { name: "Comparison categories" });
    expect(within(navigation).getAllByRole("button")).toHaveLength(8);
    await user.click(within(navigation).getByRole("button", { name: "Findings" }));
    expect(await screen.findByText("Finding added")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Findings" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("link", { name: "Inspect source B" }).getAttribute("href")).toBe(`/runs/${RUN_ID}#finding-finding-one`);
    await user.click(within(navigation).getByRole("button", { name: "Evidence" }));
    expect(await screen.findByText("Evidence removed")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Inspect source A" }).getAttribute("href")).toBe(`/runs/${RUN_ID}#evidence-7`);
  });

  it.each(["unavailable", "incompatible"] as const)("explains %s category results", async (status) => {
    const data = comparison();
    data.categories.metadata = { ...blankDiff, status, reason: `Metadata is ${status}.`, a_status: "failed", b_status: "succeeded" };
    setup({ [`GET ${compareUrl()}`]: () => json(data) });
    expect(await screen.findByText(`Metadata is ${status}.`)).toBeTruthy();
    expect(screen.getByText(`metadata: ${status}`)).toBeTruthy();
    expect(screen.getByText("Step A: failed · Step B: succeeded")).toBeTruthy();
    expect(screen.queryByText("No differences in this category.")).toBeNull();
  });

  it("shows partial analysis status, warnings and the identical bytes notice", async () => {
    const data = comparison({ identical_content: true, warnings: ["Strings extraction was truncated."] });
    data.a.run_status = "partial";
    data.b.run_status = null;
    setup({ [`GET ${compareUrl()}`]: () => json(data) });
    expect(await screen.findByText("Analysis A: partial · Analysis B: not run")).toBeTruthy();
    expect(screen.getByText("Strings extraction was truncated.")).toBeTruthy();
    expect(screen.getByText(/The versions contain identical bytes/)).toBeTruthy();
    expect(screen.getByText("No differences in this category.")).toBeTruthy();
  });

  it("paginates bounded changes and resets the page on category selection", async () => {
    const user = userEvent.setup();
    const first = comparison();
    first.categories.metadata = { ...blankDiff, total_rows: 51, next_offset: 50, rows: Array.from({ length: 50 }, (_, index) => ({ key: `Change ${index}`, change: "added", before: null, after: { value: index } })) };
    const last = comparison();
    last.categories.metadata = { ...blankDiff, total_rows: 51, rows: [{ key: "Final change", change: "added", before: null, after: { value: "last" } }] };
    setup({ [`GET ${compareUrl()}`]: () => json(first), [`GET ${compareUrl(older, VERSION_ID, 50)}`]: () => json(last) });
    expect(await screen.findByText("1–50 of 51")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Previous changes" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "Next changes" }));
    expect(await screen.findByText("Final change")).toBeTruthy();
    expect(screen.getByText("51–51 of 51")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Next changes" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "Previous changes" }));
    expect(await screen.findByText("1–50 of 51")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Next changes" }));
    await screen.findByText("Final change");
    await user.click(screen.getByRole("button", { name: "Sections" }));
    expect(await screen.findByText("No differences in this category.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Previous changes" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
