import { FunctionReferences } from "./FunctionReferences";
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { type SampleVersion } from "./api";
import { ErrorPanel, formatDate } from "./components";
import { defaultPrivacy, reviewApi, type PinnedReview as Review, type PrivacyPolicy } from "./review-api";

export function PinnedReview({ version, runId }: { version: SampleVersion; runId?: string }) {
  const [reviewId, setReviewId] = useState<string | null>(() => {
    const value = new URLSearchParams(window.location.search).get("review_id");
    return value && /^[0-9a-f]{32}$/.test(value) ? value : null;
  });
  const [created, setCreated] = useState<Review | null>(null);
  const stored = useQuery({ queryKey: ["pinned-review", reviewId],
    queryFn: () => reviewApi.get(reviewId!), enabled: Boolean(reviewId) });
  const [historyOffset, setHistoryOffset] = useState(0);
  const history = useQuery({ queryKey: ["review-history", version.id, historyOffset], queryFn: () => reviewApi.history(version.id, historyOffset) });
  const pin = (value: Review) => {
    setCreated(value); setReviewId(value.id); comparison.reset();
    const url = new URL(window.location.href);
    url.searchParams.set("review_id", value.id);
    window.history.replaceState({}, "", url);
    void history.refetch();
  };
  const [runOffset, setRunOffset] = useState(0);
  const [compareId, setCompareId] = useState("");
  const comparison = useMutation({ mutationFn: () => reviewApi.compare(reviewId!, compareId) });
  const create = useMutation({ mutationFn: (exact: boolean) => reviewApi.create(version.id, exact ? runId : undefined, runOffset), onSuccess: pin });
  const refresh = useMutation({ mutationFn: () => reviewApi.refresh(reviewId!), onSuccess: pin });
  const review = created?.id === reviewId ? created : stored.data;
  const matches = review && review.sample.version_id === version.id && review.sample.sha256 === version.sha256 && review.sample.size_bytes === version.size_bytes;
  return <section className="card pinned-review" aria-labelledby="pinned-review-title">
    <h2 id="pinned-review-title">Pinned investigation review</h2>
    <p>Combine stored checks for this exact file into a review that stays fixed. Tools may have run separately. Newer unsuccessful attempts remain visible.</p>
    <div className="actions">
      <button className="button" disabled={create.isPending} onClick={() => create.mutate(false)}>Create combined review</button>
      {runId && <button className="button" disabled={create.isPending} onClick={() => create.mutate(true)}>Pin exact run</button>}
    </div>
    <details><summary>Choose a bounded source-run window</summary><p>Combined reviews inspect at most 200 stored runs in one window. Current offset: {runOffset}. Choosing another window changes the evidence scope.</p><button className="button" disabled={runOffset === 0} onClick={() => setRunOffset(Math.max(0, runOffset - 200))}>Newer source window</button><button className="button" disabled={runOffset >= 100000} onClick={() => setRunOffset(runOffset + 200)}>Older source window</button></details>
    {history.data && history.data.items.length > 0 && <details><summary>Saved reviews</summary><ul>{history.data.items.map(item => <li key={item.id}><button className="button" onClick={() => { setCreated(null); setReviewId(item.id); comparison.reset(); }}>{formatDate(item.created_at)} · {item.id.slice(0, 8)}</button></li>)}</ul><nav aria-label="Saved review pages"><button className="button" disabled={historyOffset === 0} onClick={() => setHistoryOffset(Math.max(0, historyOffset - 25))}>Newer reviews</button><span role="status"> Page {Math.floor(historyOffset / 25) + 1} </span><button className="button" disabled={history.data.next_offset === null} onClick={() => setHistoryOffset(history.data!.next_offset!)}>Older reviews</button></nav></details>}
    {create.isError && <ErrorPanel error={create.error} title="Could not pin review" />}
    {stored.isError && <ErrorPanel error={stored.error} title="Could not read pinned review" />}
    {refresh.isError && <ErrorPanel error={refresh.error} title="Could not refresh review" />}
    {review && !matches && <p role="alert">Pinned review does not match this exact file. No observations are shown.</p>}
    {review && matches && <>
      <p><strong>{review.scope === "combined" ? "Combined review" : "Exact run"}</strong> · pinned {formatDate(review.created_at)}. <button className="button" disabled={refresh.isPending} onClick={() => refresh.mutate()}>Refresh into a new review</button></p>
      <p className="hint">Review <code>{review.id}</code>{review.supersedes_id && <> · supersedes <code>{review.supersedes_id}</code></>}. Catalog {review.catalog_version}. Source integrity was checked when pinned; this document does not recheck live outputs.</p>
      <Established review={review} />
      <details><summary>Technical sources and latest attempts</summary><div className="table-scroll" tabIndex={0} role="region" aria-label="Pinned review sources"><table className="table">
        <caption>Selected sources and latest attempts at pin time</caption><thead><tr><th scope="col">Check</th><th scope="col">Retained source</th><th scope="col">Latest attempt</th></tr></thead>
        <tbody>{review.sources.map(source => <tr key={source.tool}><th scope="row">{source.tool}</th><td>{source.selected ? <><a href={source.tool === "lief" ? `#metadata` : `/runs/${source.selected.run_id}`}>Source run {source.selected.run_id.slice(0, 8)}</a><details><summary>Source provenance and limits</summary><p>Invocation <code>{source.selected.invocation_id}</code> · tool {source.selected.tool_version} · adapter {source.selected.adapter_version}</p><p>Output <code className="hash">{source.selected.output_sha256}</code></p><pre>{JSON.stringify({ limits: source.selected.limits, retention: source.selected.retention }, null, 2)}</pre>{source.selected.warnings.map((warning, index) => <p key={index}>{warning}</p>)}<p>Bounded retained output; completion does not imply complete coverage.</p></details></> : source.unavailable_reason}</td><td>{source.latest_attempt ? <><a href={source.tool === "lief" ? `#metadata` : `/runs/${source.latest_attempt.run_id}`}>{source.latest_attempt.status}</a> (run: {source.latest_attempt.run_status}){source.selected && source.selected.run_id !== source.latest_attempt.run_id && <p>Newer attempt; older evidence retained.</p>}</> : "No attempt in scope"}</td></tr>)}</tbody>
      </table></div></details>
      {(review.source_run_offset !== undefined || review.source_runs_more) && <p>Source-run window starts at {review.source_run_offset ?? 0}.{review.source_runs_more && " More runs exist outside this window."}</p>}
      <details><summary>Compare with another pinned review</summary><label>Saved review to compare <select value={history.data?.items.some(item => item.id === compareId) ? compareId : ""} onChange={event => { setCompareId(event.target.value); comparison.reset(); }}><option value="">Choose from this history page</option>{history.data?.items.filter(item => item.id !== reviewId).map(item => <option key={item.id} value={item.id}>{formatDate(item.created_at)} · {item.id.slice(0, 8)}</option>)}</select></label><p>Use the saved-review page controls to reach older choices. For another compatible version, paste its full review ID.</p><label>Other review ID <input value={compareId} onChange={event => { setCompareId(event.target.value); comparison.reset(); }} maxLength={32} /></label><button className="button" disabled={!/^[0-9a-f]{32}$/.test(compareId) || comparison.isPending} onClick={() => comparison.mutate()}>Compare pinned evidence</button>{comparison.isError && <ErrorPanel error={comparison.error} title="Could not compare reviews" />}{comparison.data && <section aria-label="Pinned review comparison"><ExportValue value={comparison.data} /></section>}</details>
      <h3>Useful observations</h3><p className="hint">{review.selection_explanation}</p>
      {review.observations.length === 0 && <p>No rule observations were retained in this scope. This does not establish absence of behavior.</p>}
      {review.observations.slice(0, 3).map(item => <article key={item.id}><h4>{item.title}</h4><p>{item.statement}</p><p>{item.hypothesis}</p><details><summary>Why this matters, alternatives and evidence</summary><p>{item.why_it_matters}</p><ul>{item.alternatives.map(text => <li key={text}>{text}</li>)}</ul><p>{item.conditions}</p><ul>{item.limitations.map(text => <li key={text}>{text}</li>)}</ul><p>{item.next_step}</p><a href={`/runs/${item.run_id}#finding-${item.finding_id}`}>Inspect exact finding and evidence</a><p>Invocation <code>{item.invocation_id}</code> · rule <code>{item.rule_id}</code>{item.evidence_capped && " · evidence capped"}.</p></details></article>)}
      <details><summary>All {review.observations.length} retained observations</summary>{review.observations.map(item => <p key={item.id}>{item.question}: <a href={`/runs/${item.run_id}#finding-${item.finding_id}`}>{item.title}</a> — {item.statement}</p>)}</details>
      {review.observations_capped && <p>Observation view is capped; additional findings exist in source runs.</p>}
      {review.import_observations && review.import_observations.length > 0 && <section><h3>Questions raised by declared imports</h3><p>These names come from the file's import inventory. They are weaker evidence than a verified code reference. Categories with no retained supporting imports are omitted.</p>{review.import_observations.map(item => <details key={item.category}><summary>{item.title}</summary><p>{item.observation}</p><p>Legitimate alternative: {item.alternative}</p><p>{item.limitation}</p><p>{item.next_step}</p><p>Exact retained names: {item.supporting_names.join(", ")}</p><p>Source record pointers: {item.pointers.join(", ")}</p><a href={`/api/v1/invocations/${item.invocation_id}/raw`} download>Download source metadata JSON (may contain private text)</a></details>)}</section>}
      <h3>Important unknowns</h3><ul>{review.unknowns.map(text => <li key={text}>{text}</li>)}</ul>
      <ReviewExport key={review.id} review={review} />
    </>}
  </section>;
}

function ReviewExport({ review }: { review: Review }) {
  const downloadAbort = useRef<AbortController | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  useEffect(() => () => downloadAbort.current?.abort(), []);
  const [policy, setPolicy] = useState<PrivacyPolicy>(defaultPrivacy);
  const preview = useMutation({ mutationFn: (selection: PrivacyPolicy) => reviewApi.preview(review.id, selection) });
  const labels: Record<keyof PrivacyPolicy, string> = {
    analyst_notes: "Analyst function notes and overlays", overview: "Overview", observations: "Observations", technical_details: "Technical details",
    string_values: "Readable text values (may be private)", original_names: "Original filename",
    mask_sensitive_values: "Mask plausible secrets and private home paths (heuristic)",
  };
  const download = (format: "json" | "html") => {
    if (!preview.data) return;
    // Serialize the exact preview document using the server's canonical JSON convention.
    // The canonical download itself is requested server-side below, avoiding serializer drift.
    downloadAbort.current?.abort();
    const controller = new AbortController();
    downloadAbort.current = controller;
    setDownloadError(null);
    void fetch(`/api/v1/reviews/${review.id}/export/${format}`, { signal: controller.signal, method: "POST", headers: {
      "X-Bytasm-Request": "1", "Content-Type": "application/json",
    }, body: JSON.stringify(preview.variables) }).then(async response => {
      if (!response.ok) throw new Error("Export failed");
      const blob = await response.blob();
      if (controller.signal.aborted) return;
      const url = URL.createObjectURL(blob); const link = document.createElement("a");
      link.href = url; link.download = `bytasm-review-${review.id}.${format}`; link.click();
      URL.revokeObjectURL(url);
    }).catch(() => { if (!controller.signal.aborted) setDownloadError("Export failed. Preview again before retrying."); });
  };
  return <details><summary>Preview and export this pinned review</summary>
    <p>Original evidence remains stored locally. This export excludes raw outputs, reconstructed code and machine symbols. Analyst function notes require explicit inclusion.</p>
    <fieldset><legend>Content included in exported bytes</legend>{(Object.keys(labels) as Array<keyof PrivacyPolicy>).map(key => <label key={key}><input type="checkbox" checked={policy[key]} onChange={event => { downloadAbort.current?.abort(); setDownloadError(null); setPolicy({ ...policy, [key]: event.target.checked }); preview.reset(); }} /> {labels[key]}</label>)}</fieldset>
    <button className="button" disabled={preview.isPending} onClick={() => preview.mutate(policy)}>Preview export</button>
    {preview.isError && <ErrorPanel error={preview.error} title="Could not preview export" />}
    {downloadError && <p role="alert">{downloadError}</p>}
    {preview.data && JSON.stringify(preview.variables) === JSON.stringify(policy) && <><p>Review {review.id} · JSON SHA-256 <code className="hash">{preview.data.sha256}</code> · {preview.data.size_bytes} bytes</p><section aria-label="Exact export preview" className="review-human-preview"><h4>Human-readable export preview</h4><p>This view contains only the exact previewed derivative. Expand the technical JSON to inspect its field names and values.</p><ExportValue value={preview.data.document} /></section><details><summary>Technical JSON of this exact export</summary><pre className="review-export-preview" tabIndex={0}>{JSON.stringify(preview.data.document, null, 2)}</pre></details><button className="button" onClick={() => download("json")}>Download previewed JSON</button><button className="button" onClick={() => download("html")}>Download standalone HTML</button></>}
  </details>;
}

function ExportValue({ value }: { value: unknown }) {
  if (value === null) return <span>None</span>;
  if (Array.isArray(value)) return value.length ? <ol>{value.map((item, index) => <li key={index}><ExportValue value={item} /></li>)}</ol> : <span>None retained</span>;
  if (typeof value === "object") return <dl>{Object.entries(value).map(([key, item]) => {
    const label = key.replaceAll("_", " ");
    const technical = /(?:_id|_sha256|_version|_offset|_pointer)$/.test(key) || ["sources", "sample", "provenance", "identity", "evidence", "limits", "retention", "profile", "privacy_policy", "source_selection_policy", "structure", "function_evidence", "strings"].includes(key);
    return <div key={key}>{technical ? <><dt className="sr-only">{label}</dt><dd><details><summary>{label}</summary><ExportValue value={item} /></details></dd></> : <><dt><strong>{label}</strong></dt><dd><ExportValue value={item} /></dd></>}</div>;
  })}</dl>;
  return <span className="untrusted">{String(value)}</span>;
}

function Established({ review }: { review: Review }) {
  return <section aria-labelledby="established-title"><h3 id="established-title">What we could establish</h3><p>Answers use the evidence captured in this pinned review. Declared capabilities do not establish execution, intent or safety.</p>
    {!review.answers && <p>This historical review has no pinned question interpretations. Its original observations remain available below.</p>}
    {review.answers?.map(answer => <article key={answer.id}><h4>{answer.title}</h4>{answer.observations.map((item, index) => <div key={index}><p><strong>Observation ({item.level.replaceAll("_", " ")}):</strong> {item.observation}</p><p><strong>Why it matters:</strong> {item.why_it_matters}</p><p><strong>Alternative:</strong> {item.alternative}</p><p><strong>Missing evidence:</strong> {item.missing}</p><p><strong>Next action:</strong> {item.next_action}</p><details><summary>Exact pinned evidence</summary><ExportValue value={item.evidence} /></details></div>)}<p><strong>Missing evidence:</strong> {answer.missing}</p><p><strong>Next action:</strong> {answer.next_action}</p></article>)}
    {review.structure && <details><summary>File structure captured in this review</summary><ExportValue value={review.structure} /></details>}
    {review.function_evidence && <details><summary>Pinned function references ({review.function_evidence.length})</summary><p>Retained static evidence at pin time. Address spaces are preserved; addresses are not file offsets.</p>{review.function_evidence.map((item, index) => <article key={index}><h4>{item.name}</h4><a href={`/runs/${item.run_id}?ghidra_function=${item.function_index}#ghidra`}>Inspect source run {item.run_id.slice(0, 8)}, function {item.function_index}</a><FunctionReferences fn={item} protocolVersion={item.protocol_version} /><details><summary>Source provenance</summary><p>Invocation <code>{item.invocation_id}</code> · output <code className="hash">{item.output_sha256}</code> · pointer <code>{item.pointer}</code></p></details></article>)}</details>}
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Checks and limits"><table className="table"><caption>Checks and limits at pin time</caption><thead><tr><th scope="col">Check</th><th scope="col">Evidence available</th><th scope="col">Limits and interpretation</th></tr></thead><tbody>{review.sources.map(source => <tr key={source.tool}><th scope="row">{source.tool}</th><td>{source.selected?.status ?? source.unavailable_reason ?? "No retained source"}</td><td>{source.selected ? <>{source.selected.completeness}. {source.selected.warnings.join(" ")}<details><summary>Exact bounds</summary><ExportValue value={{ limits: source.selected.limits, retention: source.selected.retention ?? null }} /></details></> : "This check supplies no evidence for the answers above."}</td></tr>)}</tbody></table></div>
  </section>;
}
