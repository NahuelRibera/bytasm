import { useQuery } from "@tanstack/react-query";
import { api, rawOutputUrl, type Run, type SampleVersion, type StepStatus } from "./api";
import { ErrorPanel, Loading, StatusPill, formatBytes, formatDate } from "./components";
import { Link } from "./router";

const STEP_MEANING: Record<StepStatus, string> = {
  queued: "Waiting; no result yet.",
  running: "Still reading the file; no final result yet.",
  succeeded: "Completed within the tool's recorded limits.",
  failed: "The check failed; absence of a pattern is unknown.",
  timed_out: "The time limit was reached; the check is incomplete.",
  cancelled: "Stopped before completion; no negative result can be inferred.",
  unsupported: "This check cannot inspect this file type or architecture.",
  unavailable: "The required tool or worker controls were unavailable.",
  skipped: "This check was not performed.",
};

/** Stored evidence only. Never selects an older success to conceal a newer failure. */
export function InspectionOverview({ version, runId }: { version: SampleVersion; runId?: string }) {
  const runs = useQuery({
    queryKey: ["runs", version.id],
    queryFn: () => api.runs(version.id),
    enabled: !runId,
    refetchInterval: query => query.state.data?.runs.some(r => ["queued", "running"].includes(r.status)) ? 2000 : false,
  });
  const selected = useQuery({
    queryKey: ["run", runId],
    queryFn: () => api.run(runId!),
    enabled: Boolean(runId),
    refetchInterval: query => query.state.data && ["queued", "running"].includes(query.state.data.status) ? 2000 : false,
  });
  const result = runId ? selected : runs;
  const run = runId ? selected.data : runs.data?.runs[0];
  const matches = !run || (run.sample.version_id === version.id && run.sample.sha256 === version.sha256 && run.sample.size_bytes === version.size_bytes);

  return <section className="card inspection-overview" aria-labelledby="inspection-overview">
    <p className="eyebrow">Start here · static inspection</p>
    <h2 id="inspection-overview">What do we know about this file?</h2>
    <p className="inspection-intro">This {formatBytes(version.size_bytes)} file appears to be {version.detected_format}. Its header declares {version.header.architecture}, {version.header.bitness}-bit, {version.header.endianness} endian. <a href="#metadata">Inspect the header evidence</a>.</p>
    <p className="hint">File names and authorisation are unverified claims. The publisher identity and authenticity have not been verified. <a href="#identity">Check the exact file hash</a>.</p>
    {result.isPending && <Loading label="Checking recorded analysis scope…" />}
    {result.isError && <ErrorPanel error={result.error} title="Run evidence could not be loaded" />}
    {!matches && <p className="error" role="alert">Run evidence does not match this file. No run observations are shown. Return to this version without a run selection or inspect the original run.</p>}
    {result.isSuccess && matches && <OverviewEvidence version={version} run={run} explicitlySelected={Boolean(runId)} />}
  </section>;
}

function OverviewEvidence({ version, run, explicitlySelected }: { version: SampleVersion; run?: Run; explicitlySelected: boolean }) {
  const complete = run?.steps.filter(step => step.status === "succeeded") ?? [];
  const ruleChecks = complete.filter(step => ["yara-x", "capa"].includes(step.tool));
  const strings = complete.find(step => step.tool === "strings")?.strings;
  const review = run?.review?.run_id === run?.id && run?.review?.version_id === version.id ? run?.review : undefined;
  const observations = review?.observations.filter(item => complete.some(step => step.tool === item.tool)).slice(0, 3) ?? [];
  const ghidra = run?.profile_id === "ghidra-static";
  const state = !run ? "Header metadata only"
    : run.status === "queued" || run.status === "running" ? "Inspection is still in progress"
    : run.status === "failed" ? "Analysis could not complete"
    : run.status === "cancelled" ? "Inspection was cancelled"
    : run.status === "partial" || complete.length !== run.steps.length || !run.steps.length ? "Some checks are incomplete"
    : "Checks completed within their limits";
  return <>
    <div className="inspection-state" aria-live="polite">
      <h3>{state}</h3>
      <p>{run ? `${complete.length} of ${run.steps.length} selected checks completed. Results below belong only to this run.` : "Bytasm read the file's structure at import. No analysis run is recorded; rule patterns and printable text have not been checked."}</p>
    </div>
    {run && <>
      <p className="hint">{explicitlySelected ? "Selected run from this page link" : "Latest recorded run"} · <Link to={`/runs/${run.id}`}><code>{run.id}</code></Link> · {run.profile_name} (<code>{run.profile_id}</code>) · queued {run.queued_at ? formatDate(run.queued_at) : "time not recorded"}. <StatusPill status={run.status} /></p>
      <div className="table-scroll" role="region" aria-label="Inspection checks" tabIndex={0}>
        <table className="table">
          <caption>Checks in this run</caption>
          <thead><tr><th scope="col">Check / source</th><th scope="col">Status</th><th scope="col">What this means</th></tr></thead>
          <tbody>{run.steps.map(step => <tr key={step.index}>
            <th scope="row">{step.tool}<div className="hint">{step.tool_version ?? "Version not recorded"}</div>
              <details><summary>Exact step provenance</summary>
                <p>Step index <code>{step.index}</code> · adapter <code>{step.adapter}</code> {step.adapter_version ?? "(version not recorded)"} · invocation <code>{step.invocation_id ?? "not recorded"}</code>.</p>
                <p>Output SHA-256 <code className="hash">{step.raw_output_sha256 ?? "not recorded"}</code>.</p>
                <p>Wall deadline {step.timeout_seconds} s · duration {step.duration_ms === null ? "not recorded" : `${step.duration_ms} ms`}.</p>
                {step.invocation_id && step.raw_output_sha256 && <a href={rawOutputUrl(step.invocation_id)} download>Download validated {step.tool} JSON (may contain private text)</a>}
              </details>
            </th>
            <td><StatusPill status={step.status} /></td>
            <td>{STEP_MEANING[step.status]}{step.message && <p className="untrusted">{step.message}</p>}{step.warnings.length > 0 && <ul>{step.warnings.map((warning, i) => <li key={i}>{warning}</li>)}</ul>}</td>
          </tr>)}</tbody>
        </table>
      </div>
      <div className="inspection-observations">
        <h3>What was observed</h3>
        {ghidra ? <p>Function evidence has a separate bounded scope. <Link to={`/runs/${run.id}`}>Explore retained functions and limits</Link> to check inventory caps, reconstructed pseudocode, instruction bytes and direct calls. A completed job does not establish whole-program coverage.</p>
          : ruleChecks.length ? <p>{run.counts.findings} rule observations recorded across {ruleChecks.length} completed rule checks. {run.counts.findings === 0 ? "No matches in these checks cannot establish that the file is harmless. " : "A pattern match does not show that a behavior happened. "}<Link to={`/runs/${run.id}#findings`}>Inspect rule observations</Link>.</p>
          : <p>Rule checks did not complete.</p>}
        {observations.length > 0 && <>
          <p className="hint">First {observations.length} of {review?.total} recorded observations in source order; this is not a severity ranking. Reviewed templates {review?.template_version}.</p>
          {observations.map(item => <article className="review-observation" key={item.key}>
            <h4>{item.rule_id}</h4><p><strong>Observed:</strong> {item.statement}</p>
            <p><strong>Possible interpretation:</strong> {item.hypothesis}</p>
            <p>{item.tool} {item.tool_version} · <a href={item.source_href}>Inspect exact finding and evidence</a>.</p>
            {item.evidence_capped && <p className="hint">Source evidence is capped; inspect its full retained scope.</p>}
          </article>)}
        </>}
        {strings && <p>{strings.stored.toLocaleString("en")} printable text sequences retained out of {strings.total_found.toLocaleString("en")} found. {strings.truncated && "Additional strings were not retained. "}Values may be shortened to 256 characters. <a href={`/versions/${version.id}?tab=strings&run_id=${run.id}`}>Browse text from this exact run</a>.</p>}
      </div>
    </>}
    <div className="inspection-guidance">
      <div><h3>What remains unknown</h3><p>Static inspection cannot establish what happens when this file runs, who published it, or whether it is safe. Missing checks and retained subsets leave unanswered questions. Strings, imports and function names alone do not prove behavior.</p></div>
      <div><h3>What to do next</h3>
        {!run ? <p><a href="#pattern-matching">Choose a static inspection</a> to collect text and rule evidence from this admitted file.</p>
          : ["queued", "running"].includes(run.status) ? <p><Link to={`/runs/${run.id}`}>Follow or cancel this run</Link>; final evidence is not ready yet.</p>
          : <p><Link to={`/runs/${run.id}`}>Review the run's evidence and limitations</Link>{complete.length !== run.steps.length ? " before choosing a new run for missing checks" : " before drawing conclusions"}.</p>}
        <p><Link to={`/projects/${version.project_id}/compare/${version.sample_id}`}>Compare a locally imported version</Link> to inspect changes against a baseline you know. For an uncertain source, ask the publisher for an independently verifiable checksum or signature and obtain expert review before using a daily-use machine.</p>
      </div>
    </div>
    <p className="hint">No file execution, remote lookup, AI verdict or safety score. This overview reads stored evidence; expanding details does not start a parser. Reports retain their own recorded scope and may select a different run; review the report preview before sharing.</p>
  </>;
}
