import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FunctionReferences } from "./FunctionReferences";
import type { GhidraFunction } from "./ghidra-api";

describe("function references", () => {
  it("distinguishes historical uncaptured references from an empty ghidra-3 capture", () => {
    const fn = { references: [], body_ranges: [] };
    const view = render(<FunctionReferences fn={fn} protocolVersion="ghidra-2" />);
    expect(screen.getByText(/were not captured by this source/)).toBeTruthy();
    expect(screen.queryByText(/No outgoing string/)).toBeNull();
    view.rerender(<FunctionReferences fn={fn} protocolVersion="ghidra-3" />);
    expect(screen.getByText(/No outgoing string/)).toBeTruthy();
    expect(screen.queryByText(/were not captured by this source/)).toBeNull();
  });
  it("keeps exact address spaces and inert text with a complete retained table", () => {
    const address = (address: string) => ({ space: "ram", address });
    const fn = { body_ranges: [{ start: address("100"), end: address("110"), provenance: "ghidra_function_body" }], references: [{ source: address("101"), target: address("200"), kind: "string", reference_type: "DATA", provenance: "ghidra_instruction_reference", preview: "<img src=x>", target_name: "value", resolved_external_target: { space: "external", address: "10" }, resolved_external_provenance: "ghidra_function_thunk" }], references_truncated: true } as GhidraFunction;
    const result = render(<FunctionReferences fn={fn} protocolVersion="ghidra-3" />);
    expect(screen.getByRole("table", { name: "Exact retained instruction references" })).toBeTruthy();
    expect(screen.getByText("<img src=x>")).toBeTruthy();
    expect(result.container.querySelector("img")).toBeNull();
    expect(screen.getByText(/Additional references may exist/)).toBeTruthy();
    expect(screen.getByText("ram:101 → ram:200")).toBeTruthy();
    expect(screen.getByText("external:10")).toBeTruthy();
    expect(screen.getByText(/Resolved via thunk; original instruction target remains ram:200/)).toBeTruthy();
  });
});
