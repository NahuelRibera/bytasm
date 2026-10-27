import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { PROJECT_ID, health, installFetch, json, project } from "../test/fakeApi";
import { renderWithClient } from "../test/render";

describe("Projects and project pages", () => {
  it("shows an empty state, then creates a project with the custom header", async () => {
    const user = userEvent.setup();
    const calls = installFetch({
      "GET /api/v1/health": () => json(health()),
      "GET /api/v1/projects": () => json([]),
      "POST /api/v1/projects": () => json(project, 201),
      [`GET /api/v1/projects/${PROJECT_ID}`]: () => json(project),
      [`GET /api/v1/projects/${PROJECT_ID}/samples`]: () => json([]),
    });
    renderWithClient(<App />);
    expect(await screen.findByText(/No projects yet/)).toBeTruthy();
    await user.type(screen.getByLabelText("Name"), "Demo");
    await user.click(screen.getByRole("button", { name: "Create project" }));
    await waitFor(() => expect(window.location.pathname).toBe(`/projects/${PROJECT_ID}`));
    const post = calls.find((call) => call.init?.method === "POST")!;
    expect((post.init!.headers as Record<string, string>)["X-Bytasm-Request"]).toBe("1");
    expect(await screen.findByText(/No samples yet/)).toBeTruthy();
    expect(screen.getAllByRole("link", { name: "Import a binary" }).length).toBeGreaterThan(0);
  });

  it("explains when the API cannot be reached", async () => {
    installFetch({
      "GET /api/v1/health": () => json(health()),
      "GET /api/v1/projects": () => Promise.reject(new TypeError("Failed to fetch")),
    });
    renderWithClient(<App />);
    expect((await screen.findByRole("alert")).textContent).toContain("make serve or make compose-up");
  });
});
