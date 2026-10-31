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
  const history = useQuery({ queryKey: ["review-history", version.id], queryFn: () => reviewApi.history(version.id) });
  const pin = (value: Review) => {
    setCreated(value); setReviewId(value.id);
    const url = new URL(window.location.href);
    url.searchParams.set("review_id", value.id);
    window.history.replaceState({}, "", url);
    void history.refetch();
  };
  const create = useMutation({ mutationFn: (exact: boolean) => reviewApi.create(version.id, exact ? runId : undefined), onSuccess: pin });
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
    {history.data && history.data.items.length > 0 && <details><summary>Saved reviews</summary><ul>{history.data.items.map(item => <li key={item.id}><button className="button" onClick={() => { setCreated(null); setReviewId(item.id); }}>{formatDate(item.created_at)} · {item.id.slice(0, 8)}</button></li>)}</ul>{history.data.next_offset !== null && <p>More reviews exist; use a saved review link to open older records.</p>}</details>}
    {create.isError && <ErrorPanel error={create.error} title="Could not pin review" />}
    {stored.isError && <ErrorPanel error={stored.error} title="Could not read pinned review" />}
    {refresh.isError && <ErrorPanel error={refresh.error} title="Could not refresh review" />}
    {review && !matches && <p role="alert">Pinned review does not match this exact file. No observations are shown.</p>}
    {review && matches && <>
      <p><strong>{review.scope === "combined" ? "Combined review" : "Exact run"}</strong> · pinned {formatDate(review.created_at)}. <button className="button" disabled={refresh.isPending} onClick={() => refresh.mutate()}>Refresh into a new review</button></p>
      <p className="hint">Review <code>{review.id}</code>{review.supersedes_id && <> · supersedes <code>{review.supersedes_id}</code></>}. Catalog {review.catalog_version}. Source integrity was checked when pinned; this document does not recheck live outputs.</p>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Pinned review sources"><table className="table">
        <caption>Selected sources and latest attempts at pin time</caption><thead><tr><th scope="col">Check</th><th scope="col">Retained source</th><th scope="col">Latest attempt</th></tr></thead>
        <tbody>{review.sources.map(source => <tr key={source.tool}><th scope="row">{source.tool}</th><td>{source.selected ? <><a href={source.tool === "lief" ? `#metadata` : `/runs/${source.selected.run_id}`}>Source run {source.selected.run_id.slice(0, 8)}</a><details><summary>Source provenance and limits</summary><p>Invocation <code>{source.selected.invocation_id}</code> · tool {source.selected.tool_version} · adapter {source.selected.adapter_version}</p><p>Output <code className="hash">{source.selected.output_sha256}</code></p><pre>{JSON.stringify({ limits: source.selected.limits, retention: source.selected.retention }, null, 2)}</pre>{source.selected.warnings.map((warning, index) => <p key={index}>{warning}</p>)}<p>Bounded retained output; completion does not imply complete coverage.</p></details></> : source.unavailable_reason}</td><td>{source.latest_attempt ? <><a href={source.tool === "lief" ? `#metadata` : `/runs/${source.latest_attempt.run_id}`}>{source.latest_attempt.status}</a> (run: {source.latest_attempt.run_status}){source.selected && source.selected.run_id !== source.latest_attempt.run_id && <p>Newer attempt; older evidence retained.</p>}</> : "No attempt in scope"}</td></tr>)}</tbody>
      </table></div>
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
    {preview.data && JSON.stringify(preview.variables) === JSON.stringify(policy) && <><p>Review {review.id} · JSON SHA-256 <code className="hash">{preview.data.sha256}</code> · {preview.data.size_bytes} bytes</p><pre className="review-export-preview" tabIndex={0} aria-label="Exact export preview">{JSON.stringify(preview.data.document, null, 2)}</pre><button className="button" onClick={() => download("json")}>Download previewed JSON</button><button className="button" onClick={() => download("html")}>Download standalone HTML</button></>}
  </details>;
}
