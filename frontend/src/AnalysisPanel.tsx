import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ApiError, api, type SampleVersion } from "./api";
import { ErrorPanel, Loading, StatusPill, formatDate } from "./components";
import { Link, navigate } from "./router";

/**
 * Sample-version section for v0.2 analysis: start a run (strings, then YARA-X)
 * after a confirmation that names the sample and the rule set, and list earlier runs.
 */
export function AnalysisPanel({ version }: { version: SampleVersion }) {
  const client = useQueryClient();
  const tools = useQuery({ queryKey: ["tools"], queryFn: api.tools });
  const ghidraProfile = tools.data?.profiles.find(item => item.id === "ghidra-static");
  const ghidraAvailable = Boolean(ghidraProfile && tools.data?.optional_providers?.some(item => item.provider === "ghidra" && item.available && item.analysis_enabled));
  const [profile, setProfile] = useState("default-static");
  const runs = useQuery({
    queryKey: ["runs", version.id],
    queryFn: () => api.runs(version.id),
    refetchInterval: (query) =>
      query.state.data?.runs.some((run) => run.status === "queued" || run.status === "running") ? 2000 : false,
  });
  const rules = useQuery({ queryKey: ["rule-set", "current"], queryFn: api.currentRuleSet });
  const [confirming, setConfirming] = useState(false);
  const startButton = useRef<HTMLButtonElement>(null);
  const create = useMutation({
    mutationFn: () => api.createRun(version.id, profile),
    onSuccess: (run) => {
      void client.invalidateQueries({ queryKey: ["runs", version.id] });
      navigate(`/runs/${run.id}`);
    },
  });

  const active = runs.data?.runs.find((run) => run.status === "queued" || run.status === "running");
  const conflictRun =
    create.error instanceof ApiError && create.error.problem.code === "run_active"
      ? create.error.problem.run_id
      : undefined;
  const sampleLabel = `${version.sample_name} ${version.version_label ?? "(unlabelled version)"}`;

  const cancelConfirm = () => {
    setConfirming(false);
    create.reset();
    startButton.current?.focus();
  };

  return (
    <section className="card" aria-labelledby="pattern-matching">
      <h2 id="pattern-matching">Static analysis runs</h2>
      <p>
        Choose a reviewed profile to inspect the stored file. Quick review extracts strings and matches Bytasm's bundled rules. The file is not executed. A match is an observation to interpret, not a verdict; no
        match does not mean the file is safe. <Link to="/rules">See the rules</Link>.
      </p>

      <label htmlFor="analysis-profile">Analysis profile</label>
      <select id="analysis-profile" value={profile} disabled={confirming || Boolean(active)} onChange={event => setProfile(event.target.value)}>
        <option value="default-static">Quick static review: strings and YARA-X</option>
        <option value="full-static">Full static review: strings, YARA-X and capa</option>
        {ghidraAvailable && <option value="ghidra-static">{ghidraProfile?.name}</option>}
      </select>
      <p className="hint">Metadata was read at import. Full review adds capa 10.0.0 with two upstream rules, a 120 s deadline and native PE x86/x64 support. Other formats retain Quick results with an unsupported capa step.</p>
      {!confirming && (
        <div className="actions">
          <button
            ref={startButton}
            type="button"
            className="button button-primary"
            onClick={() => setConfirming(true)}
            disabled={Boolean(active)}
          >
            {profile === "ghidra-static" ? "Run Ghidra static analysis…" : "Run pattern matching…"}
          </button>
          {active && (
            <span className="status-text">
              A run is already {active.status}. <Link to={`/runs/${active.id}`}>Open it</Link>
            </span>
          )}
        </div>
      )}

      {confirming && (
        <div className="confirm" role="group" aria-labelledby="confirm-heading">
          <h3 id="confirm-heading">Start a run?</h3>
          <p>Selected profile: {profile === "ghidra-static" ? ghidraProfile?.name : profile === "full-static" ? "Full static review — strings, YARA-X, then capa" : "Quick static review — strings and YARA-X"}.</p>
          {rules.isPending && <Loading label="Loading the rule set…" />}
          {rules.isError && <ErrorPanel error={rules.error} title="The rule set could not be loaded" />}
          {profile === "ghidra-static" && <p>Ghidra will inspect the stored file without executing it, recording a bounded function inventory and available pseudocode, assembly and static call references. {ghidraProfile?.limitations}</p>}
          {profile !== "ghidra-static" && rules.data && (
            <p>
              Step 1 extracts ASCII and UTF-16LE strings. Step 2: YARA-X{" "}
              {rules.data.installed_yara_x_version} will match{" "}
              <strong>{rules.data.label}</strong> ({rules.data.rule_count} rules, SHA-256{" "}
              <code className="hash">{rules.data.sha256.slice(0, 16)}…</code>) against{" "}
              <strong className="untrusted">{sampleLabel}</strong> (SHA-256{" "}
              <code className="hash">{version.sha256.slice(0, 16)}…</code>).
            </p>
          )}
          <div className="actions">
            <button
              type="button"
              className="button button-primary"
              onClick={() => create.mutate()}
              disabled={create.isPending || (profile === "ghidra-static" ? !ghidraAvailable : !rules.data)}
              autoFocus
            >
              {create.isPending ? "Starting…" : "Start run"}
            </button>
            <button type="button" className="button" onClick={cancelConfirm} disabled={create.isPending}>
              Back
            </button>
          </div>
          {create.isError && (
            <>
              <ErrorPanel error={create.error} title="The run was not started" />
              {conflictRun && (
                <p>
                  <Link to={`/runs/${conflictRun}`}>Open the run in progress</Link>
                </p>
              )}
            </>
          )}
        </div>
      )}

      {!ghidraAvailable && <p className="hint">Ghidra analysis requires a verified offline provider. <Link to="/tools">See provider setup and diagnostics</Link>.</p>}
      <h3>Runs</h3>
      {runs.isPending && <Loading label="Loading runs…" />}
      {runs.isError && <ErrorPanel error={runs.error} title="Runs could not be loaded" />}
      {runs.data && runs.data.runs.length === 0 && (
        <p className="muted">No analysis runs yet for this version.</p>
      )}
      {runs.data && runs.data.runs.length > 0 && (
        <div className="table-scroll" tabIndex={0} role="region" aria-label="Runs of this version">
          <table className="table">
            <caption className="sr-only">Analysis runs, newest first</caption>
            <thead>
              <tr>
                <th scope="col">Queued</th>
                <th scope="col">Status</th>
                <th scope="col">Rule set</th>
                <th scope="col" className="num">Rules matched</th>
                <th scope="col">Details</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.runs.map((run) => (
                <tr key={run.id} className={run.status === "cancelled" ? "row-muted" : undefined}>
                  <td>{run.queued_at ? formatDate(run.queued_at) : "—"}</td>
                  <td>
                    <StatusPill status={run.status} />
                  </td>
                  <td>
                    <code>{run.profile_id === "ghidra-static" ? run.profile_name : run.rule_set.label}</code>
                  </td>
                  <td className="num">
                    {run.steps.find((step) => step.tool === "yara-x")?.status === "succeeded"
                      ? run.counts.findings
                      : "—"}
                  </td>
                  <td>
                    <Link to={`/runs/${run.id}`} aria-label={`Open run queued ${run.queued_at ?? ""}`}>
                      Open run
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
