import { useMutation } from "@tanstack/react-query";
import { ErrorPanel } from "./components";
import { ghidraApi } from "./ghidra-api";
import { Link } from "./router";

/** This explicit action starts a fresh, bounded static analysis in the worker. */
export function FunctionSelection({ runId, indices, clear }: {
  runId: string; indices: number[]; clear: () => void;
}) {
  const request = useMutation({ mutationFn: (selection: number[]) => ghidraApi.inspect(runId, selection) });
  return <section className="function-selection" aria-label="Selected-function inspection">
    <h4>Inspect a selected set</h4>
    <p>Select up to eight inventory entries. A request starts a fresh bounded Ghidra analysis in the offline worker and retains details for that set. It can take up to three minutes. The source run stays unchanged.</p>
    <p className="hint">Matching active or completed requests reuse the exact job. Failed or cancelled requests can be retried. Cancel a queued or running job from its run page.</p>
    <div className="actions">
      <button type="button" className="button button-primary" disabled={!indices.length || request.isPending}
        onClick={() => request.mutate([...indices])}>Request details ({indices.length}/8 selected)</button>
      <button type="button" className="button" disabled={!indices.length || request.isPending} onClick={clear}>Clear selection</button>
    </div>
    {request.isPending && <p role="status">Checking the worker and recording the inspection request…</p>}
    {request.isError && <ErrorPanel title="Selected inspection could not be requested" error={request.error} />}
    {request.data && <p role="status">Inspection for function records {request.variables?.join(", ")}. {request.data.reused ? "An exact matching inspection already exists." : "The selected inspection was queued."} <Link to={`/runs/${request.data.run_id}`}>Open selected-function run</Link></p>}
  </section>;
}
