import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ApiError } from "./api";
import { ErrorPanel } from "./components";
import type { GhidraDetail } from "./ghidra-api";

type ReviewState = "unreviewed" | "in_progress" | "reviewed";
interface Citation { text_sha256: string; start_line: number; end_line: number }
interface Revision { citation?: Citation | null; revision: number; alias: string; bookmarked: boolean; collections: string[];
  state: ReviewState; note: string; created_at: string }
interface Workspace { identity: { run_id: string; invocation_id: string; output_sha256: string };
  current: Revision | null; revisions: Revision[]; history_capped: boolean; next_offset?: number | null; notice: string }
async function request(path: string, body?: unknown): Promise<Workspace> {
  const response = await fetch(path, body === undefined ? undefined : { method: "POST",
    headers: { "X-Bytasm-Request": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new ApiError(await response.json());
  return response.json() as Promise<Workspace>;
}
export function FunctionReview({ detail }: { detail: GhidraDetail }) {
  const url = `/api/v1/runs/${detail.run_id}/ghidra/functions/${detail.index}/review`;
  const [offset, setOffset] = useState(0);
  const result = useQuery({ queryKey: ["function-review", detail.run_id, detail.index, offset], queryFn: () => request(`${url}${offset ? `?offset=${offset}` : ""}`) });
  return <details className="function-review"><summary>Analyst review, bookmark and notes</summary>
    {result.isError && <ErrorPanel error={result.error} title="Function review unavailable; the source may have changed" />}
    {result.data && result.data.identity.run_id === detail.run_id && result.data.identity.invocation_id === detail.invocation_id && <>
      <p>{result.data.notice}</p>
      <FunctionReviewEditor key={result.data.current?.revision ?? 0} workspace={result.data} detail={detail} url={url} onSaved={() => { void result.refetch(); }} />
      <button className="button" onClick={() => { void result.refetch(); }}>Reload current revision</button>
      <details><summary>Retained revision history</summary>{result.data.revisions.map(item => <article key={item.revision}><h5>Revision {item.revision} · {item.state.replaceAll("_", " ")}</h5><p>Local alias: {item.alias || "None"}</p><p className="untrusted">{item.note || "No note"}</p></article>)}<nav aria-label="Function revision pages"><button className="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 25))}>Newer revisions</button><span role="status"> Revisions {offset + 1}–{offset + result.data.revisions.length} </span><button className="button" disabled={result.data.next_offset == null} onClick={() => setOffset(result.data!.next_offset!)}>Older revisions</button></nav></details>
    </>}
  </details>;
}
function FunctionReviewEditor({ workspace, detail, url, onSaved }: { workspace: Workspace; detail: GhidraDetail; url: string; onSaved: () => void }) {
  const current = workspace.current;
  const [alias, setAlias] = useState(current?.alias ?? "");
  const [bookmarked, setBookmarked] = useState(current?.bookmarked ?? false);
  const [collections, setCollections] = useState(current?.collections.join(", ") ?? "");
  const [state, setState] = useState<ReviewState>(current?.state ?? "unreviewed");
  const [note, setNote] = useState(current?.note ?? "");
  const [cite, setCite] = useState(Boolean(current?.citation));
  const save = useMutation({ mutationFn: async () => {
    let citation: Citation | null = cite ? current?.citation ?? null : null;
    if (cite && !citation && detail.function.pseudocode) {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(detail.function.pseudocode));
      citation = { text_sha256: Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join(""), start_line: 1, end_line: detail.function.pseudocode.split(/\r?\n/).length };
      // Python splitlines excludes a terminal newline from the line count.
      if (detail.function.pseudocode.endsWith("\n")) citation.end_line--;
    }
    return request(url, { expected_revision: current?.revision ?? 0, alias, bookmarked,
      collections: collections.split(",").map(s => s.trim()).filter(Boolean), state, note, citation });
  }, onSuccess: onSaved });
  return <form onSubmit={event => { event.preventDefault(); save.mutate(); }}>
    <label>Local display alias <input value={alias} maxLength={128} onChange={event => setAlias(event.target.value)} /></label>
    <label><input type="checkbox" checked={bookmarked} onChange={event => setBookmarked(event.target.checked)} /> Bookmark this exact function</label>
    <label>Collections (comma separated; up to 16) <input value={collections} maxLength={1040} onChange={event => setCollections(event.target.value)} /></label>
    <label>Review state <select value={state} onChange={event => setState(event.target.value as ReviewState)}><option value="unreviewed">Unreviewed</option><option value="in_progress">In progress</option><option value="reviewed">Reviewed by analyst</option></select></label>
    <label>Analyst note <textarea value={note} maxLength={4000} onChange={event => setNote(event.target.value)} /></label>
    {detail.function.pseudocode && <label><input type="checkbox" checked={cite} onChange={event => setCite(event.target.checked)} /> {current?.citation ? "Preserve the existing exact-text citation (uncheck to remove)" : "Cite all retained reconstructed code, bound to its exact text digest"}</label>}
    {current?.citation && <p>Existing citation: lines {current.citation.start_line}–{current.citation.end_line}, text SHA-256 <code className="hash">{current.citation.text_sha256}</code>.</p>}
    <p>Reviewed is a workflow state, not a threat or safety classification. Notes are included in a pinned review export only when explicitly selected.</p>
    <button className="button" disabled={save.isPending}>Save immutable revision</button>
    {save.isError && <ErrorPanel error={save.error} title="Could not save review; retain your text and reload if another revision exists" />}
  </form>;
}
