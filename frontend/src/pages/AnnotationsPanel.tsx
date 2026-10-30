import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";
import {
  annotationsApi,
  type Annotation,
  type AnnotationDraft,
  type AnnotationKind,
  type AnnotationTarget,
  type CitationTarget,
  type Confidence,
} from "../annotations-api";
import { Empty, ErrorPanel, Loading, formatDate } from "../components";

const citationKey = (cite: { target_type: string; target_id: string }) =>
  `${cite.target_type}:${cite.target_id}`;

function CitationLinks({ cites }: { cites: CitationTarget[] }) {
  if (cites.length === 0) return null;
  return (
    <ul aria-label="Citations">
      {cites.map((cite) => (
        <li key={citationKey(cite)}>
          <a href={`/runs/${encodeURIComponent(cite.run_id)}#${cite.target_type}-${encodeURIComponent(cite.target_id)}`}>
            {cite.label}
          </a>{" "}
          <span className="muted">({cite.target_type}, source run)</span>
        </li>
      ))}
    </ul>
  );
}

function AnnotationText({ item }: { item: Annotation }) {
  return (
    <>
      <p>
        <span className="badge">{item.author.display_name}</span> · {item.kind} · Revision {item.revision}
      </p>
      <p className="annotation-body">
        {item.body}
      </p>
      {item.confidence && <p>Confidence: {item.confidence}</p>}
      <CitationLinks cites={item.cites} />
      <time dateTime={item.created_at} className="muted">{formatDate(item.created_at)}</time>
    </>
  );
}

function History({ id }: { id: string }) {
  const history = useInfiniteQuery({
    queryKey: ["annotation-history", id],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => annotationsApi.history(id, pageParam),
    getNextPageParam: (page) => page.next_offset ?? undefined,
  });
  return (
    <section aria-label="Revision history">
      {history.isPending && <Loading label="Loading revisions…" />}
      {history.isError && <ErrorPanel error={history.error} />}
      <ol>
        {history.data?.pages.flatMap((page) => page.items).map((item) => (
          <li key={item.revision_id}><AnnotationText item={item} /></li>
        ))}
      </ol>
      {history.hasNextPage && (
        <button type="button" className="button" disabled={history.isFetchingNextPage}
          onClick={() => void history.fetchNextPage()}>
          Load more revisions
        </button>
      )}
    </section>
  );
}

function Card({ item, revise }: { item: Annotation; revise: () => void }) {
  const [history, setHistory] = useState(false);
  return (
    <article className="analyst-annotation">
      <AnnotationText item={item} />
      <div className="actions">
        <button type="button" className="button" onClick={revise}>Revise</button>
        <button type="button" className="button" aria-expanded={history}
          onClick={() => setHistory(!history)}>
          Revision history
        </button>
      </div>
      {history && <History id={item.id} />}
    </article>
  );
}

interface EditorProps {
  versionId: string;
  editing: Annotation | null;
  save: (draft: AnnotationDraft) => void;
  cancel: () => void;
  pending: boolean;
  error: unknown;
}

function Editor({ versionId, editing, save, cancel, pending, error }: EditorProps) {
  const id = useId();
  const [kind, setKind] = useState<AnnotationKind>(editing?.kind ?? "note");
  const [body, setBody] = useState(editing?.body ?? "");
  const [confidence, setConfidence] = useState<Confidence>(editing?.confidence ?? null);
  const [selected, setSelected] = useState<CitationTarget[]>(editing?.cites ?? []);
  const [validation, setValidation] = useState("");
  const targets = useInfiniteQuery({
    queryKey: ["annotation-targets", versionId],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => annotationsApi.targets(versionId, pageParam),
    getNextPageParam: (page) => page.next_offset ?? undefined,
  });
  const options = new Map(selected.map((cite) => [citationKey(cite), cite]));
  for (const cite of targets.data?.pages.flatMap((page) => page.items) ?? []) {
    options.set(citationKey(cite), cite);
  }

  function submit() {
    if (!body.trim() || body.length > 4000) {
      setValidation("Enter annotation text of 1–4000 characters.");
      return;
    }
    if (selected.length > 20) {
      setValidation("Select at most 20 citations.");
      return;
    }
    if (kind === "conclusion" && (!confidence || selected.length === 0)) {
      setValidation("A conclusion needs confidence and at least one citation.");
      return;
    }
    setValidation("");
    save({
      kind,
      body,
      confidence: kind === "conclusion" ? confidence : null,
      cites: selected.map(({ target_type, target_id }) => ({ target_type, target_id })),
    });
  }

  return (
    <form className="annotation-form" onSubmit={(event) => { event.preventDefault(); submit(); }}>
      <h3>{editing ? "Revise annotation" : "Add annotation"}</h3>
      <label htmlFor={`${id}-kind`}>Kind</label>
      <select id={`${id}-kind`} value={kind} onChange={(event) => {
        const nextKind = event.target.value as AnnotationKind;
        setKind(nextKind);
        if (nextKind !== "conclusion") setConfidence(null);
      }}>
        <option value="note">Note</option>
        <option value="interpretation">Interpretation</option>
        <option value="conclusion">Conclusion</option>
      </select>
      <label htmlFor={`${id}-body`}>Annotation text</label>
      <textarea id={`${id}-body`} value={body} maxLength={4000} rows={5}
        onChange={(event) => setBody(event.target.value)} />
      <p className="hint">
        {body.length}/4000 characters. Analyst annotations are separate from tool findings.
      </p>
      <label htmlFor={`${id}-confidence`}>Confidence</label>
      <select id={`${id}-confidence`} disabled={kind !== "conclusion"} value={confidence ?? ""}
        onChange={(event) => setConfidence((event.target.value || null) as Confidence)}>
        <option value="">No confidence selected</option>
        <option value="tentative">Tentative</option>
        <option value="likely">Likely</option>
        <option value="well-supported">Well-supported</option>
      </select>
      <fieldset>
        <legend>Cite findings or evidence</legend>
        <p className="hint">Select up to 20. Conclusions require a citation and confidence.</p>
        {targets.isPending && <Loading label="Loading citation targets…" />}
        {targets.isError && <ErrorPanel error={targets.error} />}
        {targets.isSuccess && options.size === 0 && <p>No citation targets available.</p>}
        {Array.from(options.values()).map((cite) => {
          const checked = selected.some((item) => citationKey(item) === citationKey(cite));
          return (
            <label className="annotation-citation-option" key={citationKey(cite)}>
              <input type="checkbox" checked={checked} disabled={!checked && selected.length >= 20}
                onChange={() => setSelected(checked
                  ? selected.filter((item) => citationKey(item) !== citationKey(cite))
                  : [...selected, cite])} />
              {cite.label} <span className="muted">({cite.target_type}, source run)</span>
            </label>
          );
        })}
        {targets.hasNextPage && (
          <button type="button" className="button" disabled={targets.isFetchingNextPage}
            onClick={() => void targets.fetchNextPage()}>
            Load more citation targets
          </button>
        )}
      </fieldset>
      {validation && <p role="alert">{validation}</p>}
      {error != null && <ErrorPanel error={error} />}
      <div className="actions">
        <button type="submit" className="button primary" disabled={pending}>
          {pending ? "Saving…" : editing ? "Save revision" : "Save annotation"}
        </button>
        <button type="button" className="button" disabled={pending} onClick={cancel}>Cancel</button>
      </div>
    </form>
  );
}

interface PanelProps {
  versionId: string;
  targetType: AnnotationTarget;
  targetId: string;
}

export function AnnotationsPanel({ versionId, targetType = "sample_version", targetId = versionId }: {
  versionId: string;
  targetType?: AnnotationTarget;
  targetId?: string;
}) {
  // A target change remounts the panel so drafts cannot cross target boundaries.
  return (
    <Panel key={`${versionId}:${targetType}:${targetId}`} versionId={versionId}
      targetType={targetType} targetId={targetId} />
  );
}

function Panel({ versionId, targetType, targetId }: PanelProps) {
  const heading = useId();
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Annotation | null>(null);
  const [saved, setSaved] = useState(false);
  const creationRequest = useRef<{ signature: string; id: string } | null>(null);
  const queryKey = ["annotations", targetType, targetId];
  const annotations = useInfiniteQuery({
    queryKey,
    initialPageParam: 0,
    queryFn: ({ pageParam }) => annotationsApi.list(targetType, targetId, pageParam),
    getNextPageParam: (page) => page.next_offset ?? undefined,
  });
  const mutation = useMutation({
    mutationFn: (draft: AnnotationDraft) => {
      if (editing) return annotationsApi.revise(editing.id, editing.revision, draft);
      const signature = JSON.stringify(draft);
      if (creationRequest.current?.signature !== signature) {
        creationRequest.current = { signature, id: crypto.randomUUID().replaceAll("-", "") };
      }
      return annotationsApi.create(targetType, targetId, draft, creationRequest.current.id);
    },
    onSuccess: () => {
      setOpen(false);
      setEditing(null);
      setSaved(true);
      void client.invalidateQueries({ queryKey });
      void client.invalidateQueries({ queryKey: ["annotation-history"] });
    },
  });
  const items = annotations.data?.pages.flatMap((page) => page.items) ?? [];

  function startEditing(item: Annotation | null) {
    creationRequest.current = null;
    setEditing(item);
    setOpen(true);
    setSaved(false);
    mutation.reset();
  }

  return (
    <section aria-labelledby={heading} className="annotations-panel">
      <h2 id={heading}>Analyst annotations</h2>
      <p className="hint">Notes, interpretations, and cited conclusions by the local analyst.</p>
      {saved && <p role="status">Annotation saved.</p>}
      {!open && (
        <button type="button" className="button" onClick={() => startEditing(null)}>Add note</button>
      )}
      {open && (
        <Editor key={editing?.revision_id ?? "new"} versionId={versionId} editing={editing}
          save={(draft) => mutation.mutate(draft)} cancel={() => setOpen(false)}
          pending={mutation.isPending} error={mutation.error} />
      )}
      {annotations.isPending && <Loading label="Loading annotations…" />}
      {annotations.isError && <ErrorPanel error={annotations.error} />}
      {annotations.isSuccess && items.length === 0 && <Empty>No annotations yet.</Empty>}
      {items.map((item) => <Card key={item.id} item={item} revise={() => startEditing(item)} />)}
      {annotations.hasNextPage && (
        <button type="button" className="button" disabled={annotations.isFetchingNextPage}
          onClick={() => void annotations.fetchNextPage()}>
          Load more annotations
        </button>
      )}
    </section>
  );
}
