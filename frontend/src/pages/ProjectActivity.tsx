import { useInfiniteQuery } from "@tanstack/react-query";
import { useRef } from "react";
import { api } from "../api";
import { Empty, ErrorPanel, Loading, formatDate } from "../components";
import { Link } from "../router";

const LABELS: Record<string, string> = {
  "annotation.created": "Analyst annotation added",
  "annotation.revised": "Analyst annotation revised",
  "project.created": "Project created",
  "sample_version.imported": "Sample version imported",
  "analysis_run.queued": "Analysis queued",
  "analysis_run.running": "Analysis started",
  "analysis_run.succeeded": "Analysis completed",
  "analysis_run.partial": "Analysis partially completed",
  "analysis_run.failed": "Analysis failed",
  "analysis_run.cancelled": "Analysis cancelled",
  "analysis_run.cancel_requested": "Cancellation requested",
};

export function ProjectActivity({ projectId }: { projectId: string }) {
  const list = useRef<HTMLOListElement>(null);
  const activity = useInfiniteQuery({
    queryKey: ["project-activity", projectId],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.activity(projectId, pageParam),
    getNextPageParam: (page) => page.next_offset ?? undefined,
  });
  const items = activity.data?.pages.flatMap((page) => page.items) ?? [];

  async function loadMore() {
    const firstNew = items.length;
    const result = await activity.fetchNextPage();
    if (result.isSuccess) {
      // Move keyboard focus into the newly loaded page, including the final page.
      requestAnimationFrame(() => {
        (list.current?.children[firstNew] as HTMLElement | undefined)?.focus();
      });
    }
  }

  return (
    <section aria-labelledby="activity-heading">
      <h2 id="activity-heading">Activity</h2>
      {activity.isPending && <Loading label="Loading activity…" />}
      {activity.isError && <ErrorPanel error={activity.error} />}
      {activity.isSuccess && items.length === 0 && <Empty>No activity recorded yet.</Empty>}
      {items.length > 0 && (
        <ol className="activity-list" ref={list} aria-label="Project activity">
          {items.map((item) => (
            <li key={item.id} tabIndex={-1}>
              <p>{LABELS[item.type] ?? "Activity recorded"}</p>
              <time className="muted" dateTime={item.at}>{formatDate(item.at)}</time>
              {item.reason === "worker_interrupted" && <p className="hint">The analysis worker stopped.</p>}
              {item.reason && item.reason !== "worker_interrupted" && (
                <p className="hint">Some steps could not finish. Open the run for details.</p>
              )}
              {item.annotation_id && item.sample_version_id ? (
                <p><Link to={item.run_id && item.annotation_target_type && item.annotation_target_id
                  ? `/runs/${item.run_id}?annotations=1#${item.annotation_target_type}-${item.annotation_target_id}`
                  : `/versions/${item.sample_version_id}?annotations=1`}>View analyst annotations</Link></p>
              ) : item.run_id ? (
                <p><Link to={`/runs/${item.run_id}`}>View run</Link></p>
              ) : item.sample_version_id ? (
                <p><Link to={`/versions/${item.sample_version_id}`}>View sample version</Link></p>
              ) : null}
            </li>
          ))}
        </ol>
      )}
      {activity.hasNextPage && (
        <button className="button" type="button" disabled={activity.isFetchingNextPage} onClick={() => void loadMore()}>
          {activity.isFetchingNextPage ? "Loading more activity…" : "Load more activity"}
        </button>
      )}
    </section>
  );
}
