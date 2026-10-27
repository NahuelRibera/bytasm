import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { PROJECT_ID, VERSION_ID, health, installFetch, json, project, version } from "../test/fakeApi";
import { renderWithClient } from "../test/render";

function decodeHeader(value: string): unknown {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0))));
}

function openImport(routes: Parameters<typeof installFetch>[0] = {}) {
  window.history.pushState({}, "", `/projects/${PROJECT_ID}/import`);
  const calls = installFetch({
    "GET /api/v1/health": () => json(health()),
    [`GET /api/v1/projects/${PROJECT_ID}`]: () => json(project),
    [`GET /api/v1/projects/${PROJECT_ID}/samples`]: () => json([]),
    [`GET /api/v1/sample-versions/${VERSION_ID}`]: () => json(version()),
    [`GET /api/v1/sample-versions/${VERSION_ID}/sections`]: () =>
      json({ entropy_method: "x", entropy_unit: "bits_per_byte", sections: [] }),
    ...routes,
  });
  renderWithClient(<App />);
  return calls;
}

const fixture = () => new File([new Uint8Array([0x4d, 0x5a, 1, 2, 3])], "hello_v1-x86_64.exe");

describe("Import page", () => {
  it("states the input policy and the self-attestation notice up front", async () => {
    openImport();
    expect(await screen.findByRole("heading", { name: "Import a binary" })).toBeTruthy();
    expect(screen.getByText(/Up to 64 MiB\. PE and ELF files only/)).toBeTruthy();
    expect(screen.getByText(/Do not import downloaded, received, third-party, or suspicious/)).toBeTruthy();
    expect(screen.getAllByText(/Bytasm never runs the files it imports/).length).toBeGreaterThan(0);
    expect(screen.getByText(/only files listed in Bytasm's fixture manifest/)).toBeTruthy();
    expect(screen.getByText(/not proof of permission/)).toBeTruthy();
    expect(screen.getByText(/cannot be changed from the browser/)).toBeTruthy();
    // There is no control to change the policy.
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("sends the raw file with the metadata header and the custom request header", async () => {
    const user = userEvent.setup();
    const calls = openImport({
      [`POST /api/v1/projects/${PROJECT_ID}/imports`]: () => json({ sample_version: version() }, 201),
    });
    await screen.findByRole("heading", { name: "Import a binary" });
    await user.upload(screen.getByLabelText("File"), fixture());
    expect((screen.getByLabelText("Sample name") as HTMLInputElement).value).toBe("hello_v1-x86_64");
    await user.type(screen.getByLabelText("Version label (optional)"), "v1");
    await user.type(screen.getByLabelText("Statement"), "I built it from fixtures/src.");
    await user.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(window.location.pathname).toBe(`/versions/${VERSION_ID}`));
    const post = calls.find((call) => call.init?.method === "POST")!;
    const headers = post.init!.headers as Record<string, string>;
    expect(headers["X-Bytasm-Request"]).toBe("1");
    expect(headers["Content-Type"]).toBe("application/octet-stream");
    expect(decodeHeader(headers["X-Bytasm-Import"]!)).toEqual({
      authorization: { basis: "owned_or_built", statement: "I built it from fixtures/src." },
      declared_filename: "hello_v1-x86_64.exe",
      version_label: "v1",
      sample_name: "hello_v1-x86_64",
    });
    expect(post.init!.body).toBeInstanceOf(File);
  });

  it("shows a policy refusal with its fixed message and technical details", async () => {
    const user = userEvent.setup();
    openImport({
      [`POST /api/v1/projects/${PROJECT_ID}/imports`]: () =>
        json(
          {
            type: "urn:bytasm:error:input_policy",
            code: "input_policy",
            title: "Refused by the input policy",
            status: 403,
            detail: "This version only accepts Bytasm's test fixtures. The file was not parsed or stored.",
            request_id: "f".repeat(32),
          },
          403,
        ),
    });
    await screen.findByRole("heading", { name: "Import a binary" });
    await user.upload(screen.getByLabelText("File"), fixture());
    await user.type(screen.getByLabelText("Statement"), "mine");
    await user.click(screen.getByRole("button", { name: "Import" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Refused by the input policy");
    expect(alert.textContent).toContain("not parsed or stored");
    expect(alert.textContent).toContain("f".repeat(32));
    expect(window.location.pathname).toBe(`/projects/${PROJECT_ID}/import`);
  });

  it("refuses an oversized or empty file before uploading", async () => {
    const user = userEvent.setup();
    const calls = openImport();
    await screen.findByRole("heading", { name: "Import a binary" });
    const big = new File(["x"], "big.bin");
    Object.defineProperty(big, "size", { value: 64 * 1024 * 1024 + 1 });
    await user.upload(screen.getByLabelText("File"), big);
    await user.type(screen.getByLabelText("Statement"), "mine");
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect((await screen.findByRole("alert")).textContent).toContain("64 MiB");

    await user.upload(screen.getByLabelText("File"), new File([], "empty.bin"));
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect((await screen.findByRole("alert")).textContent).toContain("empty");
    expect(calls.some((call) => call.init?.method === "POST")).toBe(false);
  });

  it("requires the authorisation statement", async () => {
    const user = userEvent.setup();
    const calls = openImport();
    await screen.findByRole("heading", { name: "Import a binary" });
    await user.upload(screen.getByLabelText("File"), fixture());
    await user.click(screen.getByRole("button", { name: "Import" }));
    expect((await screen.findByRole("alert")).textContent).toContain("statement is required");
    expect(calls.some((call) => call.init?.method === "POST")).toBe(false);
  });
});
