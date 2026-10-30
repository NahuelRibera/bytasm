import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderWithClient } from "./test/render";
import { installFetch, json, sections, stringsPage, version, VERSION_ID } from "./test/fakeApi";
import { SectionMap, sectionTotal } from "./SectionMap";
import { ReviewPanel } from "./ReviewPanel";
import { VersionPage } from "./pages/VersionPage";

it("sizes sections against an explicit denominator and labels entropy as a measurement", () => {
  const data = sections().sections;
  expect(sectionTotal(data)).toBe(data.reduce((sum, section) => sum + section.raw_size, 0));
  expect(sectionTotal([{ ...data[0]!, raw_size: -1 }])).toBeNull();
  expect(sectionTotal([])).toBe(0);
  renderWithClient(<SectionMap sections={data} versionId={VERSION_ID} invocationId="import-record" />);
  expect(screen.getByText(/Overlaps are not deduplicated/)).toBeTruthy();
  expect(screen.getAllByRole("img").every(image => Boolean(image.getAttribute("aria-label")))).toBe(true);
  expect(screen.getByText(/scale 0–8/)).toBeTruthy();
});

it("does not invent a size percentage for zero raw data", () => {
  renderWithClient(<SectionMap sections={[{ ...sections().sections[0]!, raw_size: 0, entropy: null }]} versionId={VERSION_ID} />);
  expect(screen.getByText(/size bars are omitted/)).toBeTruthy();
  expect(screen.queryByRole("img")).toBeNull();
});

it("keeps hypotheses, source links and capped evidence distinct from analyst conclusions", () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const { container } = renderWithClient(<ReviewPanel review={{ template_version: "1", run_id: "run", version_id: VERSION_ID, total: 15, capped: true, glossary: { Hypothesis: "Possible interpretation" }, observations: [{ key: "finding", tool: "capa", tool_version: "10.0.0", adapter_version: "0.1.0", rule_id: hostile, rule_version: "10.0.0", rule_sha256: "a".repeat(64), statement: "A rule matched.", hypothesis: "This may indicate a reference.", source_href: "/runs/run#finding-source", locations: ["Virtual address 0x123"], pointers: ["/rules/rule/0"], evidence_capped: true }] }} />);
  expect(screen.getByRole("link", { name: "Inspect exact finding and evidence" }).getAttribute("href")).toBe("/runs/run#finding-source");
  expect(screen.getByText(hostile)).toBeTruthy();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getByText(/Evidence display is capped/)).toBeTruthy();
  expect(screen.getByText(/1 of 15 observations/)).toBeTruthy();
});

it("hides path-like string values until explicit disclosure and keeps URLs as text", async () => {
  const path = "C:\\Users\\private\\file.pdb";
  const page = stringsPage();
  const data = { ...page, category_counts: { path_like: 1, other: 1 }, items: [
    { ...page.items[0]!, value: path, category: "path_like" },
    { ...page.items[1]!, value: "javascript:alert(1)", category: "other" },
  ] };
  installFetch({
    [`GET /api/v1/sample-versions/${VERSION_ID}`]: () => json(version()),
    [`GET /api/v1/sample-versions/${VERSION_ID}/sections`]: () => json(sections()),
    [`GET /api/v1/sample-versions/${VERSION_ID}/strings?limit=1`]: () => json(data),
    [`GET /api/v1/sample-versions/${VERSION_ID}/strings?offset=0&limit=100`]: () => json(data),
    [`GET /api/v1/sample-versions/${VERSION_ID}/reports?offset=0&limit=25`]: () => json({ items: [], next_offset: null }),
  });
  const { container } = renderWithClient(<VersionPage versionId={VERSION_ID} />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("tab", { name: /Strings/ }));
  expect(await screen.findByText(/Path-like text hidden/)).toBeTruthy();
  expect(screen.queryByText(path)).toBeNull();
  expect(screen.getByText("javascript:alert(1)")).toBeTruthy();
  expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
  await user.click(screen.getByRole("checkbox", { name: /Show path-like values/ }));
  expect(screen.getByText(path)).toBeTruthy();
});
