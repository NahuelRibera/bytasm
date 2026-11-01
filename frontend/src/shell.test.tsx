import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";
import { PROJECT_ID, health, installFetch, json, project } from "./test/fakeApi";
import { renderWithClient } from "./test/render";

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.atmosphere;
});

function openAt(path: string, routes: Parameters<typeof installFetch>[0] = {}) {
  window.history.pushState({}, "", path);
  installFetch({ "GET /api/v1/health": () => json(health()), ...routes });
  return renderWithClient(<App />);
}

describe("App shell", () => {
  it("marks the current section in the main navigation", async () => {
    openAt("/rules", { "GET /api/v1/rule-sets/current": () => json({}, 500) });
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Rules" }).getAttribute("aria-current")).toBe("page");
    expect(within(nav).getByRole("link", { name: "Projects" }).getAttribute("aria-current")).toBeNull();
  });

  it("keeps the input policy and Bytasm's limits reachable from the status bar", async () => {
    openAt("/", { "GET /api/v1/projects": () => json([]) });
    const bar = screen.getByRole("contentinfo");
    expect(await within(bar).findByText(/Input policy: fixtures only/)).toBeTruthy();
    expect(await within(bar).findByText("API ok")).toBeTruthy();
    expect(within(bar).getByText("Limits").closest("details")).toBeTruthy();
    expect(within(bar).getByText(/never runs the files it imports/)).toBeTruthy();
    expect(within(bar).getByText(/Rule matches are observations, not verdicts/)).toBeTruthy();
  });

  it("reduces atmosphere on request and remembers the choice", async () => {
    const user = userEvent.setup();
    openAt("/", { "GET /api/v1/projects": () => json([]) });
    const toggle = screen.getByRole("button", { name: "Reduce atmosphere" });
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
    expect(document.documentElement.dataset.atmosphere).toBe("on");
    await user.click(toggle);
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
    expect(document.documentElement.dataset.atmosphere).toBe("off");
    expect(window.localStorage.getItem("bytasm.atmosphere")).toBe("off");
  });
});

describe("Character placements", () => {
  it("shows the crow beside the empty project list, hidden from assistive technology", async () => {
    const { container } = openAt("/", { "GET /api/v1/projects": () => json([]) });
    expect(await screen.findByRole("heading", { name: "No projects yet" })).toBeTruthy();
    const art = container.querySelector('[data-character="crow"]');
    expect(art?.getAttribute("aria-hidden")).toBe("true");
    expect(art?.className).toContain("art-crow-cutout");
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows the scavenger when a project has no samples", async () => {
    const { container } = openAt(`/projects/${PROJECT_ID}`, {
      [`GET /api/v1/projects/${PROJECT_ID}`]: () => json(project),
      [`GET /api/v1/projects/${PROJECT_ID}/samples`]: () => json([]),
      [`GET /api/v1/projects/${PROJECT_ID}/activity?offset=0&limit=25`]: () => json({ items: [], next_offset: null }),
    });
    expect(await screen.findByText("No samples yet.")).toBeTruthy();
    expect(container.querySelector('[data-character="scavenger"]')?.getAttribute("aria-hidden")).toBe("true");
  });

  it("shows the headless knight on an unknown address", () => {
    const { container } = openAt("/nowhere");
    expect(screen.getByRole("heading", { level: 1, name: "Not found" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Back to projects" })).toBeTruthy();
    const art = container.querySelector('[data-character="nohead"]');
    expect(art?.className).toContain("art-nohead-field");
  });

  it("never places character art on a project that has samples", async () => {
    const { container } = openAt(`/projects/${PROJECT_ID}`, {
      [`GET /api/v1/projects/${PROJECT_ID}`]: () => json(project),
      [`GET /api/v1/projects/${PROJECT_ID}/samples`]: () =>
        json([{ id: "a".repeat(32), name: "hello", created_at: "2026-10-26T10:00:00Z", versions: [] }]),
      [`GET /api/v1/projects/${PROJECT_ID}/activity?offset=0&limit=25`]: () => json({ items: [], next_offset: null }),
    });
    expect(await screen.findByRole("article", { name: "Sample hello" })).toBeTruthy();
    expect(container.querySelector(".binary-art")).toBeNull();
  });
});
