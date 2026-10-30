import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AnnotationsPanel } from "./AnnotationsPanel";
import { installFetch, json, VERSION_ID, RUN_ID } from "../test/fakeApi";
import { renderWithClient } from "../test/render";

const list = `/api/v1/annotations?target_type=sample_version&target_id=${VERSION_ID}&offset=0&limit=25`;
const targets = `/api/v1/sample-versions/${VERSION_ID}/citation-targets?offset=0&limit=100`;
const cite = {
  target_type: "finding",
  target_id: "finding-one",
  run_id: RUN_ID,
  version_id: VERSION_ID,
  label: "Matched rule"
};
const note = {
  id: "note-one",
  revision_id: "rev-one",
  revision: 1,
  target_type: "sample_version",
  target_id: VERSION_ID,
  version_id: VERSION_ID,
  kind: "note",
  body: "<img src=x onerror=alert(1)>",
  confidence: null,
  author: {
    id: "local",
    display_name: "Local analyst"
  },
  created_at: "2026-10-29T12:00:00Z",
  cites: [cite]
};

function setup(extra = {}) {
  installFetch({
    [`GET ${list}`]: () => json({
      items: [note],
      next_offset: null
    }),
    [`GET ${targets}`]: () => json({
      items: [cite],
      next_offset: null
    }),
    ...extra
  });
  renderWithClient(<AnnotationsPanel versionId={VERSION_ID} />);
}

describe("Annotations", () => {
  it("renders plain text, citation links and paginated history", async () => {
    const user = userEvent.setup();
    setup({
      "GET /api/v1/annotations/note-one/revisions?offset=0&limit=25": () => json({
        items: [note],
        next_offset: 25
      }),
      "GET /api/v1/annotations/note-one/revisions?offset=25&limit=25": () => json({
        items: [{
            ...note,
            revision_id: "older",
            body: "Earlier observation"
          }],
        next_offset: null
      })
    });
    expect(await screen.findByText(note.body)).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("Local analyst")).toBeTruthy();
    expect(screen.getByRole("link", {
      name: "Matched rule"
    }).getAttribute("href")).toBe(`/runs/${RUN_ID}#finding-finding-one`);
    await user.click(screen.getByRole("button", {
      name: "Revision history"
    }));
    await user.click(await screen.findByRole("button", {
      name: "Load more revisions"
    }));
    expect(await screen.findByText("Earlier observation")).toBeTruthy();
  });

  it("validates then creates a cited conclusion", async () => {
    const user = userEvent.setup();
    let payload: unknown;
    setup({
      "POST /api/v1/annotations": (request: RequestInit | undefined) => {
        expect(new Headers(request?.headers).get("X-Bytasm-Request")).toBe("1");
        payload = JSON.parse(request?.body as string);
        return json({
          ...note,
          body: "Reasoned statement"
        });
      }
    });
    await user.click(screen.getByRole("button", {
      name: "Add note"
    }));
    await user.selectOptions(screen.getByLabelText("Kind"), "conclusion");
    await user.type(screen.getByLabelText("Annotation text"), "Reasoned statement");
    await user.click(screen.getByRole("button", {
      name: "Save annotation"
    }));
    expect(screen.getByRole("alert").textContent).toContain("confidence and at least one citation");
    await user.selectOptions(screen.getByLabelText("Confidence"), "likely");
    await user.click(await screen.findByRole("checkbox", {
      name: /Matched rule/
    }));
    await user.click(screen.getByRole("button", {
      name: "Save annotation"
    }));
    expect(await screen.findByText("Annotation saved.")).toBeTruthy();
    expect(payload).toMatchObject({
      target_type: "sample_version",
      target_id: VERSION_ID,
      kind: "conclusion",
      body: "Reasoned statement",
      confidence: "likely",
      cites: [{
          target_type: "finding",
          target_id: "finding-one"
        }]
    });
  });

  it("preserves a revision draft on conflict", async () => {
    const user = userEvent.setup();
    let payload: unknown;
    setup({
      "POST /api/v1/annotations/note-one/revisions": (request: RequestInit | undefined) => {
        payload = JSON.parse(request?.body as string);
        return json({
          detail: "A newer revision exists.",
          status: 409
        }, 409);
      }
    });
    await user.click(await screen.findByRole("button", {
      name: "Revise"
    }));
    await user.clear(screen.getByLabelText("Annotation text"));
    await user.type(screen.getByLabelText("Annotation text"), "Revised observation");
    await user.click(screen.getByRole("button", {
      name: "Save revision"
    }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect((screen.getByLabelText("Annotation text") as HTMLTextAreaElement).value).toBe("Revised observation");
    expect(payload).toMatchObject({
      expected_revision: 1,
      body: "Revised observation"
    });
  });

  it("shows loading, empty state and paginates lists", async () => {
    const user = userEvent.setup();
    setup({
      [`GET ${list}`]: () => json({
        items: [],
        next_offset: 25
      }),
      [`GET ${list.replace("offset=0", "offset=25")}`]: () => json({
        items: [note],
        next_offset: null
      }),
      [`GET ${targets}`]: () => json({
        items: [],
        next_offset: 100
      }),
      [`GET ${targets.replace("offset=0", "offset=100")}`]: () => json({
        items: [cite],
        next_offset: null
      })
    });
    expect(screen.getByRole("status").textContent).toContain("Loading annotations");
    expect(await screen.findByText("No annotations yet.")).toBeTruthy();
    await user.click(screen.getByRole("button", {
      name: "Load more annotations"
    }));
    expect(await screen.findByText(note.body)).toBeTruthy();
    await user.click(screen.getByRole("button", {
      name: "Add note"
    }));
    await user.click(await screen.findByRole("button", {
      name: "Load more citation targets"
    }));
    expect(await screen.findByRole("checkbox", {
      name: /Matched rule/
    })).toBeTruthy();
  });

  it("saves revisions without changing their target", async () => {
    const user = userEvent.setup();
    let payload: Record<string, unknown> | undefined;
    setup({
      "POST /api/v1/annotations/note-one/revisions": (request: RequestInit | undefined) => {
        payload = JSON.parse(request?.body as string);
        return json({
          ...note,
          revision: 2,
          revision_id: "rev-two",
          body: "Updated note"
        });
      }
    });
    await user.click(await screen.findByRole("button", {
      name: "Revise"
    }));
    await user.clear(screen.getByLabelText("Annotation text"));
    await user.type(screen.getByLabelText("Annotation text"), "Updated note");
    await user.click(screen.getByRole("button", {
      name: "Save revision"
    }));
    expect(await screen.findByText("Annotation saved.")).toBeTruthy();
    expect(payload).toEqual({
      expected_revision: 1,
      body: "Updated note",
      kind: "note",
      confidence: null,
      cites: [{
          target_type: "finding",
          target_id: "finding-one"
        }]
    });
    expect(screen.queryByLabelText("Annotation text")).toBeNull();
  });

  it("rejects whitespace text before sending a note", async () => {
    const user = userEvent.setup();
    setup();
    await user.click(screen.getByRole("button", {
      name: "Add note"
    }));
    await user.type(screen.getByLabelText("Annotation text"), "   ");
    await user.click(screen.getByRole("button", {
      name: "Save annotation"
    }));
    expect(screen.getByRole("alert").textContent).toContain("1–4000 characters");
    expect(screen.getByLabelText("Annotation text").getAttribute("maxlength")).toBe("4000");
  });

  it("bounds citations at twenty and links evidence in its source run", async () => {
    const user = userEvent.setup();
    const choices = Array.from({
      length: 21
    }, (_, index) => ({
      ...cite,
      target_type: "evidence",
      target_id: String(index),
      label: `Evidence choice ${index}`
    }));
    setup({
      [`GET ${targets}`]: () => json({
        items: choices,
        next_offset: null
      }),
      [`GET ${list}`]: () => json({
        items: [{
            ...note,
            cites: [choices[0]]
          }],
        next_offset: null
      })
    });
    expect((await screen.findByRole("link", {
      name: "Evidence choice 0"
    })).getAttribute("href")).toBe(`/runs/${RUN_ID}#evidence-0`);
    await user.click(screen.getByRole("button", {
      name: "Add note"
    }));
    const boxes = await screen.findAllByRole("checkbox");
    for (const box of boxes.slice(0, 20))
      await user.click(box);
    expect((boxes[20] as HTMLInputElement).disabled).toBe(true);
    await user.click(boxes[0]!);
    expect((boxes[20] as HTMLInputElement).disabled).toBe(false);
  });

  it("clears confidence when a conclusion becomes a note", async () => {
    const user = userEvent.setup();
    let payload: unknown;
    setup({
      [`GET ${list}`]: () => json({
        items: [{
            ...note,
            kind: "conclusion",
            confidence: "likely"
          }],
        next_offset: null
      }),
      "POST /api/v1/annotations/note-one/revisions": (request: RequestInit | undefined) => {
        payload = JSON.parse(request?.body as string);
        return json({
          ...note,
          revision: 2
        });
      }
    });
    await user.click(await screen.findByRole("button", {
      name: "Revise"
    }));
    await user.selectOptions(screen.getByLabelText("Kind"), "note");
    expect((screen.getByLabelText("Confidence") as HTMLSelectElement).value).toBe("");
    await user.click(screen.getByRole("button", {
      name: "Save revision"
    }));
    expect(await screen.findByText("Annotation saved.")).toBeTruthy();
    expect(payload).toMatchObject({
      kind: "note",
      confidence: null
    });
  });

  it("reuses a creation request token for an unchanged retry", async () => {
    const user = userEvent.setup();
    const tokens: string[] = [];
    setup({
      "POST /api/v1/annotations": (request: RequestInit | undefined) => {
        tokens.push(JSON.parse(request?.body as string).request_id);
        return Promise.reject(new TypeError("Offline"));
      },
    });
    await user.click(screen.getByRole("button", { name: "Add note" }));
    await user.type(screen.getByLabelText("Annotation text"), "Observation");
    await user.click(screen.getByRole("button", { name: "Save annotation" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Save annotation" }));
    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(tokens[1]).toBe(tokens[0]);
    await user.type(screen.getByLabelText("Annotation text"), " changed");
    await user.click(screen.getByRole("button", { name: "Save annotation" }));
    expect(tokens).toHaveLength(3);
    expect(tokens[2]).not.toBe(tokens[0]);
  });

  it("shows fetch errors", async () => {
    setup({
      [`GET ${list}`]: () => Promise.reject(new TypeError("Offline"))
    });
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});
