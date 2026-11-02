// M2 Journey pieces: the file map instrument, deterministic decoration, breadcrumbs, section index
// and the project workspace spine.
import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";
import type { Section } from "./api";
import { mulberry32 } from "./art/binaryField";
import { FileMap } from "./FileMap";
import { Breadcrumbs, SectionIndex } from "./shell";
import { PROJECT_ID, health, installFetch, json, project } from "./test/fakeApi";
import { renderWithClient } from "./test/render";

function section(index: number, name: string, file_offset: number, raw_size: number): Section {
  return {
    index,
    name,
    section_type: null,
    file_offset,
    raw_size,
    virtual_address: 0,
    virtual_size: raw_size,
    flags: [],
    entropy: null,
    entropy_note: null,
  };
}

afterEach(() => window.history.pushState({}, "", "/"));

describe("FileMap", () => {
  it("summarises sections and matched ranges by file offset, counting overlaps once", () => {
    render(
      <FileMap
        title="Where the matched bytes sit in the file"
        size={1000}
        sections={[section(0, ".text", 100, 400), section(1, ".data", 300, 400), section(2, ".empty", 900, 0)]}
        marks={[
          { key: "a", offset: 150, length: 8, group: "f1", label: "rule_a · $a" },
          { key: "b", offset: 50, length: 4, group: "f2", label: "rule_b · $b" },
        ]}
        selectedGroup="f1"
      />,
    );
    const map = screen.getByRole("img");
    expect(map.getAttribute("aria-label")).toBe(
      "Where the matched bytes sit in the file. File of 1,000 bytes; 2 sections with raw data; 2 matched byte ranges, 1 inside a section.",
    );
    // .text and .data overlap from 300 to 500: the union covers 100..700, so 400 bytes lie outside.
    expect(screen.getByText("outside every section (400 B)")).toBeTruthy();
    expect(within(screen.getByRole("list", { name: "Sections on the map" })).getByText(".data")).toBeTruthy();
  });

  it("draws nothing for an unusable file size", () => {
    const { container } = render(<FileMap title="Sections" size={0} sections={[]} />);
    expect(container.firstChild).toBeNull();
  });
});

describe("Decoration", () => {
  it("draws the binary field from a seeded sequence, so every render is identical", () => {
    const first = mulberry32(42);
    const second = mulberry32(42);
    const a = Array.from({ length: 8 }, first);
    expect(Array.from({ length: 8 }, second)).toEqual(a);
    expect(a.every((value) => value >= 0 && value < 1)).toBe(true);
  });
});

describe("Navigation", () => {
  it("renders a breadcrumb trail whose last item is the current page", () => {
    renderWithClient(<Breadcrumbs items={[{ to: "/", label: "Projects" }, { to: `/projects/${PROJECT_ID}`, label: "Demo" }]} current="Run 1234" />);
    const trail = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(trail).getAllByRole("link").map((link) => link.getAttribute("href"))).toEqual(["/", `/projects/${PROJECT_ID}`]);
    expect(within(trail).getByText("Run 1234").closest("li")?.getAttribute("aria-current")).toBe("page");
  });

  it("indexes a long page with grouped anchor links", () => {
    render(
      <SectionIndex
        label="Run sections"
        entries={[
          { id: "coverage", label: "Coverage", group: "Understand" },
          { id: "findings", label: "Findings and evidence", group: "Investigate" },
        ]}
      />,
    );
    const index = screen.getByRole("navigation", { name: "Run sections" });
    expect(within(index).getByRole("link", { name: /Coverage/ }).getAttribute("href")).toBe("#coverage");
    expect(within(index).getByRole("link", { name: /Findings and evidence/ }).getAttribute("href")).toBe("#findings");
  });

  it("shows the approved isotipo in the top bar and marks Projects on project pages", async () => {
    window.history.pushState({}, "", `/projects/${PROJECT_ID}`);
    installFetch({
      "GET /api/v1/health": () => json(health()),
      [`GET /api/v1/projects/${PROJECT_ID}`]: () => json(project),
      [`GET /api/v1/projects/${PROJECT_ID}/samples`]: () =>
        json([
          {
            id: "b".repeat(32),
            name: "hello",
            versions: [
              { id: "c".repeat(32), version_label: "v2", sha256: "2".repeat(64), size_bytes: 2048, detected_format: "ELF", architecture: "x86_64", admitted_under: "fixture_manifest", imported_at: "2026-10-27T10:00:00Z" },
              { id: "d".repeat(32), version_label: "v1", sha256: "1".repeat(64), size_bytes: 1024, detected_format: "ELF", architecture: "x86_64", admitted_under: "fixture_manifest", imported_at: "2026-10-26T10:00:00Z" },
            ],
          },
        ]),
      [`GET /api/v1/projects/${PROJECT_ID}/activity?offset=0&limit=25`]: () => json({ items: [], next_offset: null }),
    });
    renderWithClient(<App />);
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Projects" }).getAttribute("aria-current")).toBe("page");
    // Versions sit on the spine oldest first, and two versions offer the real comparison.
    const spine = await screen.findByRole("region", { name: "Versions of hello" });
    expect(within(spine).getAllByRole("link").map((link) => link.textContent)).toEqual(["v1", "v2"]);
    expect(screen.getByRole("link", { name: "Compare versions of hello" })).toBeTruthy();
    expect(within(screen.getByRole("navigation", { name: "Breadcrumb" })).getByRole("link", { name: "Projects" })).toBeTruthy();
  });
});
