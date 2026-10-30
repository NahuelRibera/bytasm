import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import type { Run } from "./api";
import { CopyButton, ErrorPanel, KeyValues, Loading } from "./components";
import { addressLabel, ghidraApi, type GhidraDetail, type GhidraFunction } from "./ghidra-api";

const ACTIVE = new Set(["queued", "running"]);

/** File-derived strings are React text nodes; no HTML, URLs or scripts are inferred. */
export function GhidraPanel({ run }: { run: Run }) {
  const overview = useQuery({
    queryKey: ["ghidra", run.id, run.status, run.steps.map(step => step.status).join()],
    queryFn: () => ghidraApi.overview(run.id),
    refetchInterval: ACTIVE.has(run.status) ? 2000 : false,
  });
  if (overview.isPending) return <Loading label="Loading Ghidra observations…" />;
  if (overview.isError) return <ErrorPanel error={overview.error} title="Ghidra observations could not be loaded" />;
  const record = overview.data;
  return <section className="card ghidra-workspace" aria-labelledby="ghidra-heading">
    <h2 id="ghidra-heading">What did the static analysis observe?</h2>
    <p className="hint">Project {run.sample.project_name}; version {run.sample.version_label ?? run.sample.version_id}; run <code>{record.run_id}</code>.</p>
    <p>Ghidra examines program structure without running this file. A function is a group of instructions that Ghidra identified; it may be incomplete or incorrect.</p>
    <div className="ghidra-summary">
      <section aria-labelledby="ghidra-observations"><h3 id="ghidra-observations">Verified observations</h3>
        {record.summary.observations.length ? <ul>{record.summary.observations.map((item, index) => <li key={index}>{item.text} <a href={item.citation}>Why am I seeing this? <span className="sr-only">Observation {index + 1}</span></a></li>)}</ul> : <p>No completed Ghidra observations are available. Step status: {record.step_status.replaceAll("_", " ")}.</p>}
      </section>
      <section><h3>Evidence-based hypotheses</h3><p>No behavior or intent is inferred from this function inventory. Static references do not establish that code executed.</p></section>
      <section><h3>Analyst notes and conclusions</h3><p>Ghidra's observations are machine-generated. Analyst-authored notes remain in the version's annotation workspace.</p></section>
      <section><h3>Recommended next steps</h3><ul>{record.summary.recommendations.map((text, index) => <li key={index}>{text}</li>)}</ul></section>
      <section><h3>Unknowns and limits</h3><ul>{record.summary.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul></section>
    </div>
    <section className="ghidra-coverage" aria-labelledby="ghidra-coverage-heading">
      <h3 id="ghidra-coverage-heading">Analysis coverage</h3>
      <p>{record.coverage.completed} of {record.coverage.total} selected Ghidra steps completed in this run. This measures completed work, not safety.</p>
      <progress aria-label="Completed Ghidra steps" value={record.coverage.completed} max={Math.max(record.coverage.total, 1)} />
      <p>{record.stored_functions} function records stored{record.function_count === null ? "; total identified is unavailable" : ` of ${record.function_count} identified`}.{record.functions_truncated && " The inventory reached its limit; missing records do not establish absence."}</p>
    </section>
    {record.available && <>
      <div className="actions"><a className="button" href={ghidraApi.exportUrl(run.id, "json")} download>Export Ghidra report (JSON)</a><a className="button" href={ghidraApi.exportUrl(run.id, "html")} download>Export Ghidra report (HTML)</a></div>
      <FunctionInventory runId={run.id} />
    </>}
    {record.provenance && <details className="ghidra-provenance"><summary>Exact Ghidra provenance</summary><KeyValues items={[
      ["Ghidra", record.provenance.tool_version], ["Adapter", record.provenance.adapter_version],
      ["Language", record.provenance.language_id], ["Ghidra compiler specification", record.provenance.compiler],
      ["Provider host", record.provenance.provider_host ? `${record.provenance.provider_host.os} ${record.provenance.provider_host.architecture}` : "Not recorded"],
      ["Profile SHA-256", <code className="hash">{record.provenance.profile_sha256}</code>],
      ["Script SHA-256", <code className="hash">{record.provenance.script_sha256}</code>],
      ["Output SHA-256", <code className="hash">{record.provenance.raw_output_sha256}</code>],
    ]} /></details>}
    <details><summary>Terms used in this workspace</summary><dl>
      <dt>Pseudocode</dt><dd>Ghidra's approximation of instructions as readable code. It is not the original source code.</dd>
      <dt>Disassembly</dt><dd>Machine instructions displayed as assembly text, with their addresses and bytes.</dd>
      <dt>Address space</dt><dd>The named memory space to which an address belongs. An address is not a file offset.</dd>
      <dt>Static call relationship</dt><dd>A direct call reference recorded by Ghidra. It is not a runtime trace or proof the call occurred.</dd>
    </dl></details>
  </section>;
}

function FunctionInventory({ runId }: { runId: string }) {
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const openers = useRef<Record<number, HTMLButtonElement | null>>({});
  const inventory = useQuery({ queryKey: ["ghidra-functions", runId, query, offset], queryFn: () => ghidraApi.functions(runId, query, offset) });
  const detail = useQuery({ queryKey: ["ghidra-function", runId, selected], queryFn: () => ghidraApi.detail(runId, selected!), enabled: selected !== null });
  return <section aria-labelledby="ghidra-functions-heading">
    <h3 id="ghidra-functions-heading">Inspect function evidence</h3>
    <p>Search the stored inventory, then inspect a function. This profile extracts details for only the first 16 functions in Ghidra inventory order. Other functions remain inventory records; opening them does not start additional analysis.</p>
    <form role="search" aria-label="Search Ghidra functions" className="filter-row" onSubmit={event => { event.preventDefault(); setOffset(0); setQuery(search.trim()); setSelected(null); }}>
      <label>Function name<input value={search} maxLength={128} onChange={event => setSearch(event.target.value)} /></label><button className="button" type="submit">Search functions</button>
    </form>
    {inventory.isPending && <Loading label="Loading function inventory…" />}
    {inventory.isError && <ErrorPanel error={inventory.error} title="Function inventory could not be loaded" />}
    {inventory.data && <>
      <p role="status">{inventory.data.matched === 0 ? "No stored function matches this search." : `Showing ${inventory.data.offset + 1}–${inventory.data.offset + inventory.data.items.length} of ${inventory.data.matched} matching function records.`} Inventory scope: this run, {inventory.data.total} stored records.</p>
      {inventory.data.items.length > 0 && <div className="table-scroll" tabIndex={0} role="region" aria-label="Ghidra function inventory"><table className="table"><caption className="sr-only">Stored functions for run {runId}</caption><thead><tr><th scope="col">Function</th><th scope="col">Entry address</th><th scope="col">Body size</th><th scope="col">Pseudocode</th><th scope="col">Evidence</th></tr></thead><tbody>{inventory.data.items.map(item => <tr key={item.index}><td className="untrusted">{item.namespace && `${item.namespace}::`}{item.name}{item.external && <span className="hint"> (external)</span>}{(item.name_truncated || item.namespace_truncated) && <span className="hint"> (name truncated)</span>}</td><td><code>{addressLabel(item.entry)}</code></td><td>{item.body_size === null ? "Unavailable" : `${item.body_size} addresses`}</td><td>{item.pseudocode_status.replaceAll("_", " ")}{item.pseudocode_truncated && " (truncated)"}</td><td><button type="button" className="button" ref={element => { openers.current[item.index] = element; }} aria-expanded={selected === item.index} onClick={() => setSelected(item.index)}>Inspect <span className="sr-only">{item.name}</span></button></td></tr>)}</tbody></table></div>}
      <div className="actions"><button type="button" className="button" disabled={offset === 0 || inventory.isFetching} onClick={() => { setOffset(Math.max(0, offset - 25)); setSelected(null); }}>Previous functions</button><button type="button" className="button" disabled={offset + inventory.data.limit >= inventory.data.matched || inventory.isFetching} onClick={() => { setOffset(offset + 25); setSelected(null); }}>Next functions</button></div>
    </>}
    {selected !== null && <div className="ghidra-function-detail" role="region" aria-label="Selected function evidence">
      <button type="button" className="button" onClick={() => { const previous = selected; setSelected(null); openers.current[previous]?.focus(); }}>Close function</button>
      {detail.isPending && <Loading label="Loading function evidence…" />}
      {detail.isError && <ErrorPanel error={detail.error} title="Function evidence could not be loaded" />}
      {detail.data && <FunctionDetail detail={detail.data} />}
    </div>}
  </section>;
}

function FunctionDetail({ detail }: { detail: GhidraDetail }) {
  const fn = detail.function;
  return <>
    <h4 className="untrusted">{fn.name}{fn.name_truncated && " (name truncated)"}</h4>
    <p><code>{addressLabel(fn.entry)}</code> <CopyButton value={addressLabel(fn.entry)} label="Copy function entry with address space" /> <a href={detail.citation}>Original function record</a></p>
    {fn.limitations.length > 0 && <ul className="notice">{fn.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>}
    <h4>Ghidra pseudocode</h4><p className="hint">Decompiler approximation, not original source code. Status: {fn.pseudocode_status.replaceAll("_", " ")}.{fn.pseudocode_truncated && " Output was truncated."}</p>
    {fn.pseudocode === null ? <p>No pseudocode was retained for this function.</p> : <pre className="ghidra-code" tabIndex={0} aria-label="Ghidra pseudocode"><code>{fn.pseudocode}</code></pre>}
    <details><summary>Assembly and instruction bytes ({fn.instructions.length} retained)</summary>
      {fn.instructions_truncated && <p className="notice">Instruction output reached its limit. This is not a complete function listing.</p>}
      {fn.instructions.length === 0 ? <p>No instructions were retained.</p> : <div className="table-scroll" tabIndex={0} role="region" aria-label="Assembly listing"><table className="table"><caption>Instructions returned by Ghidra</caption><thead><tr><th scope="col">Address</th><th scope="col">Bytes (hex)</th><th scope="col">Instruction</th></tr></thead><tbody>{fn.instructions.map((item, index) => <tr key={index}><td><code>{addressLabel(item.address)}</code></td><td><code>{item.bytes_hex}</code>{item.bytes_truncated && " (bytes truncated)"}</td><td><code>{item.text}</code>{item.text_truncated && " (text truncated)"}</td></tr>)}</tbody></table></div>}
    </details>
    <StaticCalls fn={fn} />
  </>;
}

function StaticCalls({ fn }: { fn: GhidraFunction }) {
  const shown = fn.calls.slice(0, 8);
  return <details><summary>Static call relationships ({fn.calls.length} retained)</summary>
    <p>Direct static call references from this function. Arrows point from the call-site address to the recorded target. They do not represent execution flow.</p>
    {fn.calls_truncated && <p className="notice">Call references reached their limit; this list is incomplete.</p>}
    {fn.calls.length === 0 ? <p>No direct static call references were retained. This does not establish that this function makes no calls.</p> : <>
      <figure className="ghidra-call-map"><svg viewBox={`0 0 640 ${shown.length * 44}`} aria-hidden="true" focusable="false">{shown.map((edge, index) => <g key={index} transform={`translate(0 ${index * 44})`}><rect x="1" y="4" width="270" height="30" rx="4" /><text x="12" y="24">{addressLabel(edge.source)}</text><path d="M280 19h65m-8-6 8 6-8 6" /><rect x="355" y="4" width="284" height="30" rx="4" /><text x="366" y="24">{addressLabel(edge.target)}</text></g>)}</svg><figcaption>{shown.length} of {fn.calls.length} retained relationships drawn. The table below provides all retained addresses and directions.</figcaption></figure>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Static call relationships"><table className="table"><caption>Direct static call evidence for {fn.name}</caption><thead><tr><th scope="col">Source call-site</th><th scope="col">Target address</th></tr></thead><tbody>{fn.calls.map((edge, index) => <tr key={index}><td><code>{addressLabel(edge.source)}</code></td><td><code>{addressLabel(edge.target)}</code></td></tr>)}</tbody></table></div>
    </>}
  </details>;
}
