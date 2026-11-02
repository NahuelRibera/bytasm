import { useMutation, useQuery } from "@tanstack/react-query";
import { Breadcrumbs } from "../shell";
import { useState } from "react";
import { api, type VersionSummary } from "../api";
import { compareApi, CATEGORIES, type Category, type Change } from "../compare-api";
import { Empty, ErrorPanel, Loading, Notice, PageMast } from "../components";
import { Link, navigate } from "../router";
import { MastScene, TwinLights } from "../art/MastArt";

export function ComparePage({ projectId, sampleId }: { projectId: string; sampleId: string }) {
  const samples = useQuery({ queryKey: ["samples", projectId], queryFn: () => api.samples(projectId) });
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.project(projectId) });
  if (samples.isPending) return <Loading label="Loading versions…" />;
  if (samples.isError) return <ErrorPanel error={samples.error} />;
  const sample = samples.data.find((item) => item.id === sampleId);
  if (!sample) return <Empty>No sample with this ID in this project.</Empty>;
  return (
    <>
      <Breadcrumbs
        items={[
          { to: "/", label: "Projects" },
          { to: `/projects/${projectId}`, label: project.data?.name ?? "Project", untrusted: true },
        ]}
        current={`Compare ${sample.name}`}
      />
      <PageMast
        eyebrow={
          <>
            <b>∷</b> Version comparison
          </>
        }
        title={
          <>
            Compare <span className="untrusted">{sample.name}</span>
          </>
        }
        lede="Static differences between versions of the same sample."
        art={<MastScene kind="architecture" ornament={<TwinLights />} />}
      />
      {sample.versions.length < 2 ? <Empty>Import another version of this sample to compare it.</Empty> :
        <ComparisonView key={sampleId} versions={sample.versions} />}
    </>
  );
}

function ComparisonView({ versions }: { versions: VersionSummary[] }) {
  const timestamp = (value: string) => value.replace(/(?:\.(\d+))?Z$/, (_match, fraction: string | undefined) => `.${(fraction ?? "").padEnd(6, "0")}Z`);
  const ordered = [...versions].sort((a, b) => timestamp(b.imported_at).localeCompare(timestamp(a.imported_at)) || b.id.localeCompare(a.id));
  const [a, setA] = useState(ordered[1]!.id);
  const [b, setB] = useState(ordered[0]!.id);
  const [category, setCategory] = useState<Category>("metadata");
  const [offset, setOffset] = useState(0);
  const result = useQuery({ queryKey: ["compare", a, b, category, offset], queryFn: () => compareApi.compare(a, b, category, offset) });
  const report = useMutation({ mutationFn: () => compareApi.report(a, b), onSuccess: (data) => {
    const link = document.createElement("a"); link.href = data.download_url; link.download = "";
    document.body.append(link); link.click(); link.remove();
  } });
  const preview = useMutation({ mutationFn: () => compareApi.report(a, b), onSuccess: data => navigate(`/reports/${data.id}`) });
  const diff = result.data?.categories[category];
  const choose = (side: "a" | "b", value: string) => { if (side === "a") setA(value); else setB(value); setOffset(0); report.reset(); };
  const title = (name: string) => name[0]!.toUpperCase() + name.slice(1);
  const version = (id: string) => ordered.find((v) => v.id === id);
  return (
    <>
      {/* The bench: version A on the left, version B on the right, read as one instrument. */}
      <div className="compare-bench">
        {(["a", "b"] as const).map((side) => {
          const chosen = version(side === "a" ? a : b);
          const run = result.data?.[side].run_status;
          return <div className={`compare-slot compare-slot-${side}`} key={side}>
            <span className="compare-slot-mark" aria-hidden="true">{side.toUpperCase()}</span>
            <label>
              Version {side.toUpperCase()}
              <select aria-label={`Version ${side.toUpperCase()}`} value={side === "a" ? a : b} onChange={(e) => choose(side, e.target.value)}>
                {ordered.map((v) => <option key={v.id} value={v.id}>{v.version_label ?? "Unlabelled"} · {v.sha256.slice(0, 12)}</option>)}
              </select>
            </label>
            <p className="compare-slot-meta" aria-hidden="true">
              <span>{side === "a" ? "Before" : "After"}</span>
              {chosen && <span className="mono">{chosen.sha256.slice(0, 16)}…</span>}
              {result.data && <span>analysis {run ?? "not run"}</span>}
            </p>
            <Link to={`/versions/${side === "a" ? a : b}`}>View version {side.toUpperCase()}</Link>
          </div>;
        })}
        <span className="compare-axis" aria-hidden="true" />
      </div>
      {result.data && <p className="compare-runs sr-only">Analysis A: {result.data.a.run_status ?? "not run"} · Analysis B: {result.data.b.run_status ?? "not run"}</p>}
      <p className="hint">Entropy is measured in bits per byte. These differences do not establish safety or changes in behaviour.</p>
      <nav className="compare-categories" aria-label="Comparison categories">
        {CATEGORIES.map((name) => {
          const value = result.data?.categories[name];
          return <button className="compare-tab" type="button" key={name} aria-pressed={category === name}
            onClick={() => { setCategory(name); setOffset(0); }}>
            {title(name)}
            {value && (value.status === "comparable"
              ? <span className="compare-tab-counts" aria-hidden="true">
                  <span className="delta-added">+{value.added}</span>
                  <span className="delta-removed">−{value.removed}</span>
                  <span className="delta-changed">~{value.changed}</span>
                </span>
              : <span className="compare-tab-state" aria-hidden="true">{value.status}</span>)}
          </button>;
        })}
      </nav>
      {result.isPending && <Loading label="Comparing versions…" />}
      {result.isError && <ErrorPanel error={result.error} />}
      {result.data && <>
        {result.data.identical_content && <Notice label="Identical bytes">The versions contain identical bytes. Compatible results have no content differences.</Notice>}
        {result.data.warnings.map((warning) => <Notice tone="warn" label="Limitation" key={warning}>{warning}</Notice>)}
        <div className="compare-summary sr-only" role="group" aria-label="Comparison summary">
          {Object.entries(result.data.categories).map(([name, value]) => <p key={name}>{name}: {value.status === "comparable" ? `+${value.added} added · −${value.removed} removed · ~${value.changed} changed` : value.status}</p>)}
        </div>
      </>}
      {diff && <section aria-labelledby="diff-heading" className="compare-diff">
        <div className="compare-diff-head">
          <h2 id="diff-heading">{title(category)}</h2>
          <p className="hint">Step A: {diff.a_status} · Step B: {diff.b_status}</p>
        </div>
        {diff.status !== "comparable" ? <Notice label="Not comparable">{diff.reason ?? "These results cannot be compared."}</Notice> : <>
          {diff.total_rows === 0 && <Empty>No differences in this category.</Empty>}
          <ol className="comparison-changes">
            {diff.rows.map((row) => <ChangeRow key={row.key} row={row} a={a} b={b} category={category} />)}
          </ol>
          <div className="pagination">
            <button className="button" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous changes</button>
            <span>{diff.total_rows ? `${offset + 1}–${Math.min(offset + diff.rows.length, diff.total_rows)} of ${diff.total_rows}` : "0 changes"}</span>
            <button className="button" type="button" disabled={diff.next_offset === null} onClick={() => setOffset(diff.next_offset ?? offset)}>Next changes</button>
          </div>
        </>}
      </section>}
      <div className="export compare-export">
        <button className="button" disabled={report.isPending || preview.isPending || !result.data} onClick={() => preview.mutate()}>{preview.isPending ? "Creating preview…" : "Preview comparison report"}</button>
        <p className="hint">Comparison reports may include changed string values and analyst text. Review them before sharing.</p>
        <button className="button button-primary" type="button" disabled={report.isPending || !result.data} onClick={() => report.mutate()}>Export comparison JSON report</button>
        {report.isError && <ErrorPanel error={report.error} />}
        {preview.isError && <ErrorPanel error={preview.error} />}
        {report.isSuccess && <p role="status">Comparison report exported.</p>}
      </div>
    </>
  );
}

function ChangeRow({ row, a, b, category }: { row: Change; a: string; b: string; category: Category }) {
  return <li className={`card change-row change-${row.change}`}>
    <div className="change-head">
      <h3>{row.change === "added" ? "+ Added" : row.change === "removed" ? "− Removed" : "~ Changed"}</h3>
      <p className="untrusted change-key">{category === "strings" ? row.key : displayKey(row.key)}</p>
    </div>
    {(["before_ref", "after_ref"] as const).map((side) => {
      const ref = row[side];
      if (!ref) return null;
      const hash = ref.evidence_id ? `#evidence-${ref.evidence_id}` : ref.finding_id ? `#finding-${ref.finding_id}` : "";
      const destination = ["metadata", "sections", "imports", "exports"].includes(category) ? `/versions/${side === "before_ref" ? a : b}` : `/runs/${ref.run_id}${hash}`;
      return <p key={side}><a href={destination}>Inspect source {side === "before_ref" ? "A" : "B"}</a></p>;
    })}
    <div className="change-sides"><ChangeValues label="Before (A)" values={row.before} /><ChangeValues label="After (B)" values={row.after} /></div>
  </li>;
}
function displayKey(value: string): string {
  try {
    const parsed: unknown = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.map((part) => typeof part === "string" ? displayKey(part) : Array.isArray(part) ? part.join(", ") : String(part ?? "unassociated")).join(" · ");
  } catch { /* A normal field, symbol or section name. */ }
  return value;
}

function DisplayValue({ value, field = "" }: { value: unknown; field?: string }) {
  if (value === null) return <>Not available</>;
  if (field === "entropy" && typeof value === "number") return <>{value} bits/byte (measurement)</>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <>None recorded</>;
    if (value.every((item) => typeof item !== "object")) return <>{value.map(String).join(", ")}</>;
    return <ol>{value.map((item, index) => <li key={index}><DisplayValue value={item} /></li>)}</ol>;
  }
  if (typeof value === "object") return <dl className="diff-values">{Object.entries(value).map(([key, item]) => <div key={key}>
    <dt>{key.replaceAll("_", " ")}</dt><dd><DisplayValue value={item} field={key} /></dd>
  </div>)}</dl>;
  return <>{String(value)}</>;
}

function ChangeValues({ label, values }: { label: string; values: Record<string, unknown> | null }) {
  return <div className="change-side"><h4>{label}</h4>{values === null ? <p>Not present</p> : <DisplayValue value={values} />}</div>;
}
