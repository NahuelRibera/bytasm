import { useQuery } from "@tanstack/react-query";
import { ErrorPanel, Loading } from "./components";
import { addressLabel, loadRelationships } from "./ghidra-api";

export function FunctionRelationships({ runId, index, inspect }: {
  runId: string; index: number; inspect: (index: number) => void;
}) {
  const query = useQuery({ queryKey: ["ghidra-relationships", runId, index], queryFn: () => loadRelationships(runId, index) });
  if (query.isPending) return <Loading label="Loading one-hop static relationships…" />;
  if (query.isError) return <ErrorPanel title="Static relationships could not be loaded" error={query.error} />;
  const data = query.data;
  return <section aria-label="One-hop static call relationships">
    <h4>Static call relationships: one hop</h4>
    <p>Scope: run <code>{runId}</code>, function record {index}. {data.edges.length} of {data.retained_matches} matching retained references shown; at most {data.node_limit} nodes and {data.edge_limit} edges. Incoming references include retained records only.</p>
    {(!data.inventory_complete || !data.reference_windows_complete || data.truncated) && <p className="notice">This view is partial. Unshown relationships and inventory entries may exist.</p>}
    {data.edges.length === 0 ? <p>No matching direct call references were retained in this scope. This does not establish that calls are absent.</p> : <>
      <figure className="ghidra-call-map"><svg viewBox={`0 0 640 ${Math.min(data.edges.length, 8) * 44}`} aria-hidden="true" focusable="false">{data.edges.slice(0, 8).map((edge, row) => <g key={row} transform={`translate(0 ${row * 44})`}><rect x="1" y="4" width="270" height="30" rx="4" /><text x="12" y="24">{addressLabel(edge.call_site)}</text><path d="M280 19h65m-8-6 8 6-8 6" /><rect x="355" y="4" width="284" height="30" rx="4" /><text x="366" y="24">{addressLabel(edge.target)}</text></g>)}</svg><figcaption>Call-site → target address; first {Math.min(data.edges.length, 8)} retained edges drawn. Use the table to inspect evidence and expand one hop from another function.</figcaption></figure>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="One-hop relationship table"><table className="table"><caption>Retained direct static call references for run {runId}</caption><thead><tr><th scope="col">Source function</th><th scope="col">Call-site address</th><th scope="col">Target address</th><th scope="col">Target function</th><th scope="col">Provenance</th></tr></thead><tbody>{data.edges.map((edge, row) => <tr key={row}><td><button className="button" type="button" onClick={() => inspect(edge.source_index)}>Inspect source {edge.source_index}</button></td><td><code>{addressLabel(edge.call_site)}</code></td><td><code>{addressLabel(edge.target)}</code></td><td>{edge.target_index === null ? "No exact inventory entry; unresolved here" : <button className="button" type="button" onClick={() => inspect(edge.target_index!)}>Inspect target {edge.target_index}</button>}</td><td><a href={edge.citation}>Direct static call evidence <span className="sr-only">{row + 1}</span></a></td></tr>)}</tbody></table></div>
    </>}
    <ul className="hint">{data.limitations.map(item => <li key={item}>{item}</li>)}</ul>
  </section>;
}
