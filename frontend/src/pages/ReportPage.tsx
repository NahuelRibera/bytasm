import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { ErrorPanel, Loading } from "../components";

function Value({ value }: { value: unknown }) {
  if (value === null) return <>Not available</>;
  if (Array.isArray(value)) return <ol>{value.map((item, i) => <li key={i}><Value value={item} /></li>)}</ol>;
  if (typeof value === "object") return <dl className="diff-values">{Object.entries(value as Record<string, unknown>).map(([key, item]) => <div key={key}><dt>{key}</dt><dd><Value value={key === "virtual_address" && typeof (value as Record<string, unknown>).virtual_address_hex === "string" ? (value as Record<string, unknown>).virtual_address_hex : item} /></dd></div>)}</dl>;
  return <>{String(value)}</>;
}

export function ReportPage({ reportId }: { reportId: string }) {
  const query = useQuery({ queryKey: ["report", reportId], queryFn: () => api.reportDocument(reportId) });
  if (query.isPending) return <Loading label="Loading report snapshot…" />;
  if (query.isError) return <ErrorPanel error={query.error} />;
  const report = query.data;
  return <><h1>Report preview</h1><p>Stored JSON snapshot · schema {String(report.schema_version)}. Downloads use this snapshot, not later database changes.</p>
    <section className="card" aria-labelledby="plain-report"><h2 id="plain-report">Analysis in plain language</h2>{Array.isArray(report.summary) && report.summary.map((text, i) => <p key={i}>{String(text)}</p>)}</section>
    <p className="notice">Comparison reports may include changed strings and analyst text. Review before sharing.</p>
    <div className="actions"><a className="button" href={`/api/v1/reports/${reportId}/download`} download>Download JSON</a>
      {report.schema_version === 4 && <><a className="button" href={`/api/v1/reports/${reportId}/html`} download>Download standalone HTML</a>
        <a href={`/api/v1/reports/${reportId}/html?download=false`} target="_blank" rel="noreferrer">Open offline-style HTML preview</a></>}</div>
    {Object.entries(report).filter(([key]) => key !== "summary").map(([key, value]) => <section className="card" key={key}><h2>{key}</h2><Value value={value} /></section>)}</>;
}
