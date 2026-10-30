import { useInfiniteQuery, useMutation } from "@tanstack/react-query";
import { api } from "./api";
import { ErrorPanel, Loading } from "./components";
import { Link, navigate } from "./router";

export function ReportLibrary({ versionId }: { versionId: string }) {
  const reports = useInfiniteQuery({ queryKey: ["reports", versionId], initialPageParam: 0,
    queryFn: ({ pageParam }) => api.reportHistory(versionId, pageParam), getNextPageParam: page => page.next_offset ?? undefined });
  const preview = useMutation({ mutationFn: () => api.createReport(versionId), onSuccess: report => navigate(`/reports/${report.id}`) });
  return <section className="card" aria-label="Report library"><h2>Reports</h2>
    <p>Preview a verified snapshot, then choose JSON or standalone HTML.</p>
    <button className="button" disabled={preview.isPending} onClick={() => preview.mutate()}>Preview new report</button>
    {preview.isError && <ErrorPanel error={preview.error} />}{reports.isPending && <Loading label="Loading reports…" />}{reports.isError && <ErrorPanel error={reports.error} />}
    {reports.data?.pages.every(page => page.items.length === 0) && <p>No reports yet.</p>}
    <ul>{reports.data?.pages.flatMap(page => page.items).map(report => <li key={report.id}><Link to={`/reports/${report.id}`}>{report.generated_at} · {report.scope?.kind ?? "sample_version"}</Link> · SHA-256 <code>{report.sha256.slice(0,16)}…</code></li>)}</ul>
    {reports.hasNextPage && <button className="button" disabled={reports.isFetchingNextPage} onClick={() => void reports.fetchNextPage()}>Load more reports</button>}
  </section>;
}
