import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api, rawOutputUrl, type Finding, type Run, type RunStep } from "../api";
import {
  AdmittedPill,
  CopyButton,
  Empty,
  ErrorPanel,
  FindingsMeaning,
  KeyValues,
  Loading,
  StatusPill,
  asciiPreview,
  formatBytes,
  formatDate,
  hex,
  spacedHex,
} from "../components";
import { Link } from "../router";
import { RuleSource } from "./RulesPage";

const ACTIVE = new Set(["queued", "running"]);
const TOOL_NAMES: Record<string, string> = { strings: "Strings extractor", "yara-x": "YARA-X" };

function stepOf(run: Run, tool: string): RunStep | undefined {
  return run.steps.find((step) => step.tool === tool);
}
// The worker touches its heartbeat every loop; older than this means it is not running.
const WORKER_STALE_SECONDS = 15;

export function RunPage({ runId }: { runId: string }) {
  const run = useQuery({
    queryKey: ["run", runId],
    queryFn: () => api.run(runId),
    // Poll while the run can still change (blueprint 7.2: every 2 s).
    refetchInterval: (query) => (query.state.data && ACTIVE.has(query.state.data.status) ? 2000 : false),
  });

  if (run.isPending) return <Loading label="Loading the analysis run…" />;
  if (run.isError) return <ErrorPanel error={run.error} title="The run could not be loaded" />;
  const r = run.data;
  const label = r.sample.version_label ?? "(unlabelled version)";

  return (
    <>
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to={`/versions/${r.sample.version_id}`}>
          ← {r.sample.sample_name} {label}
        </Link>
      </nav>
      <header className="page-header page-header-actions">
        <div>
          <h1>
            Analysis run <span className="muted">strings + {r.rule_set.label}</span>
          </h1>
          <p className="status-line" aria-live="polite">
            <StatusPill status={r.status} />
            <span>{statusSentence(r)}</span>
          </p>
        </div>
        <CancelButton run={r} />
      </header>

      {ACTIVE.has(r.status) && <WorkerWarning />}
      <RunBanner run={r} />

      <div className="grid-2 run-grid">
        <SamplePanel run={r} />
        <ProvenancePanel run={r} />
      </div>
      <StepsTable run={r} />
      <TechnicalLog run={r} />
      <StringsSummaryPanel run={r} />
      {stepOf(r, "yara-x")?.status === "succeeded" ? (
        <FindingsSection run={r} />
      ) : (
        !ACTIVE.has(r.status) && (
          <section className="card" aria-labelledby="findings">
            <h2 id="findings">Findings</h2>
            <p>
              <strong>Not analysed.</strong> YARA-X did not complete in this run, so there are no
              findings. Absence of a match here does not mean a pattern is absent from the file.
            </p>
          </section>
        )
      )}
    </>
  );
}

function statusSentence(run: Run): string {
  const current = run.steps.find((step) => step.status === "running");
  const total = run.steps.length;
  const finished = run.finished_at ? ` ${formatDate(run.finished_at)}` : "";
  switch (run.status) {
    case "queued":
      return "Waiting for the worker to start the run.";
    case "running":
      if (run.cancel_requested) return "Cancellation requested; stopping the current step…";
      return current
        ? `${TOOL_NAMES[current.tool] ?? current.tool} is running (step ${current.index + 1} of ${total}).`
        : "The worker is between steps.";
    case "succeeded":
      return `Finished${finished}: all ${total} steps completed. ${run.counts.findings} rule${
        run.counts.findings === 1 ? "" : "s"
      } matched; ${run.counts.strings.toLocaleString("en")} strings recorded.`;
    case "partial":
      return `Finished${finished} with a partial result: ${
        run.steps.filter((step) => step.status === "succeeded").length
      } of ${total} steps completed.`;
    case "failed":
      return `Finished${finished} without results.`;
    case "cancelled":
      return "Cancelled. Only steps that finished before the cancel kept results.";
  }
}

/** The persistent partial / failed / cancelled explanation (blueprint 7.3). */
function RunBanner({ run }: { run: Run }) {
  if (!run.failure_message) return null;
  if (run.status === "partial") {
    return (
      <div className="notice notice-warn" role="status" data-testid="partial-banner">
        <p className="error-title">Partial result</p>
        <p>{run.failure_message}</p>
        <p className="hint">
          Reason code <code>{run.failure_reason}</code>. Start a new run to try the missing steps
          again.
        </p>
      </div>
    );
  }
  if (run.status === "cancelled") {
    return (
      <div className="notice" role="note">
        <p className="error-title">Run cancelled</p>
        <p>{run.failure_message}</p>
      </div>
    );
  }
  return (
    <div className="error" role="alert">
      <p className="error-title">The run did not complete</p>
      <p>{run.failure_message}</p>
      {run.failure_reason && (
        <p className="hint">
          Reason code <code>{run.failure_reason}</code>
        </p>
      )}
    </div>
  );
}

function CancelButton({ run }: { run: Run }) {
  const client = useQueryClient();
  const cancel = useMutation({
    mutationFn: () => api.cancelRun(run.id),
    onSuccess: (updated) => {
      client.setQueryData(["run", run.id], updated);
      void client.invalidateQueries({ queryKey: ["runs", run.sample.version_id] });
    },
    // A 409 means the run finished meanwhile: show its final state.
    onError: () => void client.invalidateQueries({ queryKey: ["run", run.id] }),
  });
  if (!ACTIVE.has(run.status)) return null;
  const requested = run.cancel_requested || cancel.isPending;
  return (
    <div className="export">
      <button
        type="button"
        className="button"
        onClick={() => cancel.mutate()}
        disabled={requested}
      >
        {requested ? "Cancelling…" : "Cancel run"}
      </button>
      <p className="hint">
        Stops the current step's process. Steps that already finished keep their results.
      </p>
      {cancel.isError && <ErrorPanel error={cancel.error} title="The run was not cancelled" />}
    </div>
  );
}

function WorkerWarning() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 5000 });
  const seen = health.data?.worker_last_seen_seconds;
  if (!health.data || (seen !== null && seen !== undefined && seen < WORKER_STALE_SECONDS)) return null;
  return (
    <div className="notice notice-warn" role="status">
      <p>
        <strong>No analysis worker seems to be running.</strong> Queued runs start only when{" "}
        <code>bytasm worker</code> runs next to the server (<code>make serve</code> and{" "}
        <code>make compose-up</code> start one). You can cancel this run and start it again later.
      </p>
    </div>
  );
}

function SamplePanel({ run }: { run: Run }) {
  const s = run.sample;
  return (
    <section className="card" aria-labelledby="run-sample">
      <h2 id="run-sample">Sample</h2>
      <KeyValues
        items={[
          ["Project", <Link to={`/projects/${s.project_id}`}>{s.project_name}</Link>],
          [
            "Sample",
            <span className="untrusted">
              {s.sample_name} {s.version_label ?? ""}
            </span>,
          ],
          [
            "SHA-256",
            <span className="hash-row">
              <code className="hash" data-testid="run-sample-sha256">
                {s.sha256}
              </code>
              <CopyButton value={s.sha256} label="Copy sample SHA-256" />
            </span>,
          ],
          ["Size and format", `${formatBytes(s.size_bytes)} · ${s.detected_format}`],
          ["Admitted under", <AdmittedPill value={s.admitted_under} />],
        ]}
      />
      <p className="hint">
        Before each step, the worker re-checked the input policy and re-verified the stored bytes
        against this SHA-256. The file was not executed.
      </p>
    </section>
  );
}

function ProvenancePanel({ run }: { run: Run }) {
  const step = stepOf(run, "yara-x");
  const strings = stepOf(run, "strings");
  return (
    <section className="card" aria-labelledby="run-provenance">
      <h2 id="run-provenance">Provenance</h2>
      <KeyValues
        items={[
          ["Rule set", <Link to={`/rules/${run.rule_set.id}`}>{run.rule_set.label}</Link>],
          ["Rule-set SHA-256", <code className="hash">{run.rule_set.sha256}</code>],
          ["YARA-X", step?.tool_version ? <code>{step.tool_version}</code> : "— (not started)"],
          [
            "Strings extractor",
            strings?.tool_version ? <code>{strings.tool_version}</code> : "— (not started)",
          ],
          ["Bytasm", run.bytasm_version],
          ["Queued", run.queued_at ? formatDate(run.queued_at) : "—"],
          ["Started", run.started_at ? formatDate(run.started_at) : "—"],
          ["Finished", run.finished_at ? formatDate(run.finished_at) : "—"],
          ["Run ID", <code className="hash">{run.id}</code>],
        ]}
      />
      <p className="hint">
        To repeat this analysis, start a new run on the same sample version. A run with the same
        sample SHA-256, rule-set SHA-256 and tool versions should report the same strings and
        matches. Header metadata comes from the import, not from this run.
      </p>
    </section>
  );
}

const STEP_DESCRIPTIONS: Record<string, string> = {
  strings: "Printable ASCII and UTF-16LE runs of at least 6 characters, with their file offsets.",
  "yara-x": "Static pattern matching with Bytasm's bundled rules.",
};

function StepsTable({ run }: { run: Run }) {
  return (
    <section className="card" aria-labelledby="steps">
      <h2 id="steps">Steps</h2>
      <p className="hint">
        Steps run one after another, each in a separate, resource-limited process (not a sandbox).
        A step that fails does not undo the steps before it.
      </p>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Run steps">
        <table className="table">
          <caption className="sr-only">Steps of this run, in order</caption>
          <thead>
            <tr>
              <th scope="col" className="num">#</th>
              <th scope="col">Tool</th>
              <th scope="col">Status</th>
              <th scope="col" className="num">Duration</th>
              <th scope="col" className="num">Time limit</th>
              <th scope="col">Raw output</th>
            </tr>
          </thead>
          <tbody>
            {run.steps.map((step) => (
              <tr key={step.index} className={step.status === "skipped" ? "row-muted" : undefined}>
                <td className="num">{step.index + 1}</td>
                <td>
                  {step.tool === "yara-x"
                    ? `YARA-X with ${run.rule_set.label}`
                    : TOOL_NAMES[step.tool] ?? step.tool}
                  <div className="hint">{STEP_DESCRIPTIONS[step.tool] ?? step.adapter}</div>
                  {step.message && <div className="step-message">{step.message}</div>}
                </td>
                <td>
                  <StatusPill status={step.status} />
                </td>
                <td className="num">{step.duration_ms === null ? "—" : `${step.duration_ms} ms`}</td>
                <td className="num">{step.timeout_seconds} s</td>
                <td>
                  {step.invocation_id && step.raw_output_sha256 ? (
                    <a
                      href={rawOutputUrl(step.invocation_id)}
                      download
                      aria-label={`Download the raw ${TOOL_NAMES[step.tool] ?? step.tool} output (JSON)`}
                    >
                      JSON
                    </a>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="hint">
        Raw output is the tool adapter's validated result document (JSON, re-hashed before
        download). It never contains the sample file itself.
      </p>
      {run.steps.some((step) => step.warnings.length > 0) && (
        <details>
          <summary>Compiler warnings</summary>
          <ul className="diagnostics">
            {run.steps.flatMap((step) =>
              step.warnings.map((warning, index) => (
                <li key={`${step.index}-${index}`} className="untrusted">
                  {warning}
                </li>
              )),
            )}
          </ul>
        </details>
      )}
    </section>
  );
}

function TechnicalLog({ run }: { run: Run }) {
  const [open, setOpen] = useState(false);
  const log = useQuery({
    queryKey: ["run-log", run.id, run.status, run.steps.map((step) => step.status).join()],
    queryFn: () => api.runLog(run.id),
    enabled: open,
  });
  return (
    <details className="card" onToggle={(event) => setOpen((event.target as HTMLDetailsElement).open)}>
      <summary>Technical log</summary>
      {log.isPending && open && <Loading label="Loading the log…" />}
      {log.isError && <ErrorPanel error={log.error} title="The log could not be loaded" />}
      {log.data && (
        <ol className="run-log">
          {log.data.entries.map((entry) => (
            <li key={entry.seq}>
              <span className="muted">{entry.at ? formatDate(entry.at) : "—"}</span> {entry.message}
            </li>
          ))}
        </ol>
      )}
      <p className="hint">Fixed messages from Bytasm. Tool output is never shown here.</p>
    </details>
  );
}

function StringsSummaryPanel({ run }: { run: Run }) {
  const step = stepOf(run, "strings");
  if (!step || ACTIVE.has(run.status)) return null;
  const summary = step.strings;
  return (
    <section className="card" aria-labelledby="strings-summary">
      <h2 id="strings-summary">
        Strings <span className="count">{run.counts.strings.toLocaleString("en")}</span>
      </h2>
      {summary ? (
        <>
          <p>
            {summary.total_found.toLocaleString("en")} strings found (
            {Object.entries(summary.found_by_encoding)
              .map(([encoding, count]) => `${count.toLocaleString("en")} ${encoding}`)
              .join(", ")}
            ){summary.truncated ? `; the first ${summary.stored.toLocaleString("en")} by offset are kept` : ""}.
            Strings are observations, not findings.
          </p>
          <p>
            <Link to={`/versions/${run.sample.version_id}?tab=strings`}>
              Search the strings on the sample version page
            </Link>
          </p>
        </>
      ) : (
        <p>
          <strong>Not analysed.</strong> The strings step did not complete in this run, so no
          strings were recorded.
        </p>
      )}
    </section>
  );
}

function FindingsSection({ run }: { run: Run }) {
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const findings = useQuery({
    queryKey: ["findings", run.id, query],
    queryFn: () => api.findings(run.id, { q: query }),
    placeholderData: (previous) => previous,
  });
  const [selected, setSelected] = useState<string | null>(null);
  const openers = useRef<Record<string, HTMLButtonElement | null>>({});

  if (findings.isPending) return <Loading label="Loading findings…" />;
  if (findings.isError) return <ErrorPanel error={findings.error} title="The findings could not be loaded" />;
  const items = findings.data.findings;
  const current = items.find((finding) => finding.id === selected) ?? null;

  const close = () => {
    const opener = selected ? openers.current[selected] : null;
    setSelected(null);
    opener?.focus();
  };

  const total = findings.data.total;
  return (
    <section className="card" aria-labelledby="findings">
      <h2 id="findings">
        Findings <span className="count">{total}</span>
      </h2>
      <FindingsMeaning notices={findings.data.notices} />
      {total > 0 && (
        <form
          className="filter-row"
          role="search"
          aria-label="Filter findings"
          onSubmit={(event) => {
            event.preventDefault();
            setQuery(search.trim());
          }}
        >
          <label htmlFor="finding-search">Search findings</label>
          <input
            id="finding-search"
            type="search"
            maxLength={128}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Rule, description or tag"
          />
          <button type="submit" className="button button-small">
            Search
          </button>
          <span className="hint" aria-live="polite">
            {query ? `${items.length} of ${total} shown` : `${total} shown`} · tool: YARA-X
          </span>
        </form>
      )}
      {total > 0 && items.length === 0 ? (
        <Empty>
          <p>No finding matches “{query}”.</p>
        </Empty>
      ) : items.length === 0 ? (
        <Empty>
          <p>
            <strong>No rule matched.</strong> None of the {run.rule_set.label} rules found their
            patterns in this file's bytes.
          </p>
          <p className="hint">
            This is not evidence that the file is safe. It only says these specific rules did not
            match.
          </p>
        </Empty>
      ) : (
        <div className="table-scroll" tabIndex={0} role="region" aria-label="Findings table">
          <table className="table">
            <caption className="sr-only">Rules that matched, with their match counts</caption>
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">Description (from the rule)</th>
                <th scope="col" className="num">Matches</th>
                <th scope="col">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {items.map((finding) => (
                <tr key={finding.id} className={finding.id === selected ? "row-selected" : undefined}>
                  <td>
                    <span className="tool-badge">YARA-X</span> <code className="untrusted">{finding.rule_id}</code>
                  </td>
                  <td className="untrusted">{finding.title}</td>
                  <td className="num">
                    {finding.match_count}
                    {finding.evidence_truncated ? "+" : ""}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="button button-small"
                      ref={(element) => {
                        openers.current[finding.id] = element;
                      }}
                      aria-expanded={finding.id === selected}
                      aria-controls="evidence-panel"
                      onClick={() => setSelected(finding.id === selected ? null : finding.id)}
                    >
                      {finding.id === selected ? "Hide evidence" : `Inspect ${finding.rule_id}`}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {current && <EvidencePanel finding={current} run={run} onClose={close} />}
    </section>
  );
}

function EvidencePanel({ finding, run, onClose }: { finding: Finding; run: Run; onClose: () => void }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const ruleSet = useQuery({
    queryKey: ["rule-set", finding.rule_set_id],
    queryFn: () => api.ruleSet(finding.rule_set_id),
  });
  useEffect(() => heading.current?.focus(), [finding.id]);
  const file = ruleSet.data?.files.find((item) => item.identifier === finding.rule_id);

  return (
    <section
      id="evidence-panel"
      className="evidence-panel"
      aria-labelledby="evidence-heading"
      onKeyDown={(event) => {
        if (event.key === "Escape") onClose();
      }}
    >
      <div className="evidence-header">
        <h3 id="evidence-heading" tabIndex={-1} ref={heading}>
          Evidence: <code className="untrusted">{finding.rule_id}</code>
        </h3>
        <button type="button" className="button button-small" onClick={onClose}>
          Close evidence
        </button>
      </div>
      <p>
        YARA-X {stepOf(run, "yara-x")?.tool_version} reported that rule <code>{finding.rule_id}</code>{" "}
        matched {finding.match_count} time{finding.match_count === 1 ? "" : "s"} in the stored
        bytes. Offsets are byte positions from the start of the file.
        {finding.evidence_truncated &&
          " The match list was capped, so more matches may exist than are listed."}
      </p>
      <KeyValues
        items={[
          ["Namespace", <code>{finding.rule_namespace}</code>],
          ["Tags", finding.tags.length ? finding.tags.map((tag) => <code key={tag}>{tag} </code>) : "—"],
          [
            "Rule metadata",
            finding.metadata.length ? (
              <ul className="name-list">
                {finding.metadata.map(([key, value], index) => (
                  <li key={index}>
                    <code>{key}</code> = <span className="untrusted">{String(value)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              "—"
            ),
          ],
        ]}
      />
      {finding.evidence.length === 0 ? (
        <p className="muted">
          This rule matched on its condition without reporting byte ranges, so there is no byte
          evidence to show.
        </p>
      ) : (
        <div className="table-scroll" tabIndex={0} role="region" aria-label="Matched byte ranges">
          <table className="table table-dense">
            <caption className="sr-only">Byte ranges matched by {finding.rule_id}</caption>
            <thead>
              <tr>
                <th scope="col">Pattern</th>
                <th scope="col" className="num">File offset</th>
                <th scope="col" className="num">Length</th>
                <th scope="col">Bytes (hex)</th>
                <th scope="col">As text</th>
              </tr>
            </thead>
            <tbody>
              {finding.evidence.map((item) => (
                <tr key={item.id}>
                  <td>
                    <code className="untrusted">{item.pattern_id}</code>
                    {item.xor_key !== null && <div className="hint">XOR key {hex(item.xor_key)}</div>}
                  </td>
                  <td className="num">
                    <code>{hex(item.file_offset)}</code>
                    <div className="hint">{item.file_offset.toLocaleString("en")}</div>
                  </td>
                  <td className="num">{item.length.toLocaleString("en")} B</td>
                  <td>
                    <code className="hash">{spacedHex(item.excerpt_hex)}</code>
                    {item.excerpt_truncated && <div className="hint">first 32 bytes shown</div>}
                  </td>
                  <td>
                    <code className="untrusted">{asciiPreview(item.excerpt_hex)}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {stepOf(run, "yara-x")?.invocation_id && (
        <p className="hint">
          <a href={rawOutputUrl(stepOf(run, "yara-x")!.invocation_id!)} download>
            Download YARA-X's raw output (JSON)
          </a>{" "}
          — evidence pointer for the first item:{" "}
          <code className="untrusted">{finding.evidence[0]?.raw_json_pointer ?? "—"}</code>
        </p>
      )}
      <p className="hint">
        “As text” shows printable ASCII only; other bytes appear as “·”. Excerpts are read from the
        verified stored file and capped at 32 bytes.
      </p>
      {ruleSet.isPending && <Loading label="Loading the rule text…" />}
      {ruleSet.isError && <ErrorPanel error={ruleSet.error} title="The rule text could not be loaded" />}
      {file && <RuleSource file={file} headingLevel={4} />}
    </section>
  );
}
