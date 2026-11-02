import { useMutation, useQuery } from "@tanstack/react-query";
import { Arcade, MastScene, Niche } from "../art/MastArt";
import { Breadcrumbs } from "../shell";
import { api, type Diagnostic, type RuleSet, type RuleValidation } from "../api";
import { CopyButton, Empty, ErrorPanel, KeyValues, Loading, PageMast } from "../components";

/**
 * Bytasm's bundled YARA-X rule set: read-only (the rules ship with the code,
 * ADR-0003). `ruleSetId` shows an exact earlier rule set that a run used,
 * from its stored snapshot; null shows the rule set on disk now.
 */
export function RulesPage({ ruleSetId }: { ruleSetId: string | null }) {
  const ruleSet = useQuery({
    queryKey: ["rule-set", ruleSetId ?? "current"],
    queryFn: () => (ruleSetId ? api.ruleSet(ruleSetId) : api.currentRuleSet()),
  });

  if (ruleSet.isPending) return <Loading label="Loading the rule set…" />;
  if (ruleSet.isError) return <ErrorPanel error={ruleSet.error} title="The rule set could not be loaded" />;
  const rules = ruleSet.data;

  return (
    <>
      {ruleSetId && <Breadcrumbs items={[{ to: "/rules", label: "← Current rule set" }]} current={rules.label} />}
      <PageMast
        eyebrow={
          <>
            <b>∷</b> {ruleSetId ? "Stored rule set" : "Bundled rule set"}
          </>
        }
        title={
          <>
            YARA-X rules <span className="muted">{rules.label}</span>
          </>
        }
        // The bundled set has the wizard; a stored set (the exact text an earlier run used) has the
        // executioner as keeper of the archive: a locked record, never a judgement on a sample.
        art={ruleSetId
          ? <MastScene kind="figure" character="executioner" ornament={<Arcade />} />
          : <MastScene kind="figure" character="wizard" ornament={<Niche />} />}
        lede={
          ruleSetId
            ? "The exact rule text an earlier run used, from the copy Bytasm stored with it."
            : "Bytasm matches samples against this small, self-written rule set. The rules ship " +
              "with Bytasm and cannot be edited from the UI; each change produces a new rule-set " +
              "hash, and earlier runs keep the exact text they used."
        }
      />

      <div className="grid-2">
        <section className="card plate frame-bracket" aria-labelledby="ruleset-identity">
          <h2 id="ruleset-identity">Rule set</h2>
          <KeyValues
            items={[
              ["Name and version", <code>{rules.label}</code>],
              [
                "SHA-256",
                <span className="hash-row">
                  <code className="hash" data-testid="ruleset-sha256">
                    {rules.sha256}
                  </code>
                  <CopyButton value={rules.sha256} label="Copy rule-set SHA-256" />
                </span>,
              ],
              ["Rules", rules.rule_count],
              ["Source", <code>{rules.source}</code>],
              ["Installed YARA-X", <code>{rules.installed_yara_x_version}</code>],
              [
                "Status",
                rules.current ? "Current (matches the rules on disk)" : "Earlier version (rules have changed since)",
              ],
            ]}
          />
        </section>
        {ruleSetId ? (
          <section className="card" aria-labelledby="ruleset-history">
            <h2 id="ruleset-history">Reproducing a run</h2>
            <p>
              A run is identified by the sample's SHA-256, this rule-set SHA-256, and the YARA-X
              version recorded on the run. Running the same rules with the same YARA-X version on
              the same bytes should report the same matches.
            </p>
            {!rules.current && (
              <p className="hint">
                These rules differ from the current ones, so a new run would use different rules.
              </p>
            )}
          </section>
        ) : (
          <ValidatePanel />
        )}
      </div>

      <section className="card rules-codex" aria-labelledby="rule-files">
        <h2 id="rule-files">Rules ({rules.files.length})</h2>
        {rules.files.length === 0 ? (
          <Empty>This rule set has no rule files.</Empty>
        ) : (
          rules.files.map((file) => <RuleSource key={file.name} file={file} />)
        )}
      </section>
    </>
  );
}

export function RuleSource({ file, headingLevel = 3 }: { file: RuleSet["files"][number]; headingLevel?: 3 | 4 }) {
  const Heading = headingLevel === 3 ? "h3" : "h4";
  return (
    <div className="rule-source">
      <Heading>
        <code>{file.identifier}</code> <span className="hint">{file.name}</span>
      </Heading>
      {/* Focusable so long lines can be scrolled from the keyboard. */}
      <pre className="code-block" tabIndex={0} aria-label={`Source of rule ${file.identifier}`}>
        <code>{file.text}</code>
      </pre>
    </div>
  );
}

function ValidatePanel() {
  const validation = useMutation({ mutationFn: api.validateRules });
  return (
    <section className="card" aria-labelledby="validate">
      <h2 id="validate">Validate</h2>
      <p>
        Compile the rules on disk with the installed YARA-X, in a separate process, and show any
        compiler errors or warnings. No sample is read.
      </p>
      <div className="actions">
        <button
          type="button"
          className="button button-primary"
          onClick={() => validation.mutate()}
          disabled={validation.isPending}
        >
          {validation.isPending ? "Compiling…" : "Validate rules"}
        </button>
      </div>
      <div aria-live="polite">
        {validation.isSuccess && <ValidationResult result={validation.data} />}
      </div>
      {validation.isError && <ErrorPanel error={validation.error} title="The rules were not checked" />}
    </section>
  );
}

function where(item: Diagnostic): string {
  const parts = [item.file, item.line, item.column].filter((part) => part !== null && part !== undefined);
  return parts.join(":");
}

function DiagnosticList({ title, items }: { title: string; items: Diagnostic[] }) {
  if (items.length === 0) return null;
  return (
    <>
      <h3>{title}</h3>
      <ul className="diagnostics">
        {items.map((item, index) => (
          <li key={index}>
            <code>{item.code}</code> <span className="untrusted">{item.title}</span>{" "}
            {where(item) && <span className="hint">at {where(item)}</span>}
          </li>
        ))}
      </ul>
    </>
  );
}

function ValidationResult({ result }: { result: RuleValidation }) {
  return (
    <div className="validation" data-testid="validation-result">
      {result.compiled ? (
        <p className="status-text">
          <span className="pill pill-ok">
            <span className="pill-dot" aria-hidden="true" />
            Compiled
          </span>{" "}
          {result.rule_identifiers.length} rules compiled with YARA-X {result.yara_x_version} in{" "}
          {result.duration_ms} ms.
        </p>
      ) : (
        <div className="error" role="alert">
          <p className="error-title">The rules did not compile</p>
          <p>
            Runs started now will fail with “rules did not compile” and produce no findings. Fix
            the files listed below in <code>rules/yara/</code>, then validate again.
          </p>
        </div>
      )}
      {result.problems.length > 0 && (
        <ul className="diagnostics">
          {result.problems.map((problem) => (
            <li key={problem}>{problem}</li>
          ))}
        </ul>
      )}
      <DiagnosticList title="Errors" items={result.errors} />
      <DiagnosticList title="Warnings" items={result.warnings} />
    </div>
  );
}
