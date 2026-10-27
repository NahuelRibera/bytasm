import { useMutation } from "@tanstack/react-query";
import { api } from "./api";
import { ErrorPanel } from "./components";

/** Generate the versioned JSON report, then download it as an attachment. */
export function ExportReportButton({ versionId }: { versionId: string }) {
  const exportReport = useMutation({
    mutationFn: () => api.createReport(versionId),
    onSuccess: (report) => {
      const link = document.createElement("a");
      link.href = report.download_url;
      link.download = "";
      document.body.append(link);
      link.click();
      link.remove();
    },
  });
  return (
    <div className="export">
      <button
        type="button"
        className="button button-primary"
        onClick={() => exportReport.mutate()}
        disabled={exportReport.isPending}
      >
        {exportReport.isPending ? "Exporting…" : "Export JSON report"}
      </button>
      <div aria-live="polite" className="hint">
        {exportReport.isSuccess && (
          <>
            Report exported · SHA-256 <code>{exportReport.data.sha256.slice(0, 16)}…</code>
          </>
        )}
      </div>
      {exportReport.isError && (
        <ErrorPanel error={exportReport.error} title="The report was not exported" />
      )}
    </div>
  );
}
