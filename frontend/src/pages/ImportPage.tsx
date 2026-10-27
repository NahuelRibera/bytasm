import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { ApiError, api, type Health, type ImportMetadata } from "../api";
import { ErrorPanel, Loading } from "../components";
import { Link, navigate } from "../router";

export const INPUT_POLICY_DISCLOSURE =
  "This version is for Bytasm's test fixtures and programs you compiled yourself from your " +
  "own source. Do not import downloaded, received, third-party, or suspicious files. v0.1 has " +
  "no isolation boundary for them, and a crafted file could exploit a parser bug. Bytasm never " +
  "runs the files it imports.";

export const ATTESTATION_NOTICE =
  "This statement is a self-attestation recorded for accountability. Bytasm does not verify " +
  "it. It is not proof of permission and not a legal determination.";

const DEFAULT_MAX = 64 * 1024 * 1024;

function stem(fileName: string): string {
  const base = fileName.split(/[\\/]/).pop() ?? fileName;
  const dot = base.lastIndexOf(".");
  return (dot > 0 ? base.slice(0, dot) : base).slice(0, 200);
}

export function ImportPage({ projectId, health }: { projectId: string; health?: Health }) {
  const client = useQueryClient();
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.project(projectId) });
  const samples = useQuery({ queryKey: ["samples", projectId], queryFn: () => api.samples(projectId) });

  const [file, setFile] = useState<File | null>(null);
  const [target, setTarget] = useState<"new" | "existing">("new");
  const [sampleName, setSampleName] = useState("");
  const [sampleId, setSampleId] = useState("");
  const [versionLabel, setVersionLabel] = useState("");
  const [statement, setStatement] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  const maxBytes = health?.max_upload_bytes ?? DEFAULT_MAX;
  const fixturesOnly = (health?.input_policy.mode ?? "fixtures") === "fixtures";

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("no file");
      const metadata: ImportMetadata = {
        authorization: { basis: "owned_or_built", statement: statement.trim() },
        declared_filename: file.name.slice(0, 255),
      };
      if (versionLabel.trim()) metadata.version_label = versionLabel.trim();
      if (target === "existing") metadata.sample_id = sampleId;
      else metadata.sample_name = sampleName.trim();
      return api.importFile(projectId, file, metadata);
    },
    onSuccess: (result) => {
      void client.invalidateQueries({ queryKey: ["samples", projectId] });
      void client.invalidateQueries({ queryKey: ["projects"] });
      navigate(`/versions/${result.sample_version.id}`);
    },
  });

  const choose = (chosen: File | null) => {
    setFile(chosen);
    setLocalError(null);
    upload.reset();
    if (chosen && !sampleName) setSampleName(stem(chosen.name));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setLocalError(null);
    if (!file) return setLocalError("Choose a file to import.");
    if (file.size === 0) return setLocalError("The file is empty. Nothing was imported.");
    if (file.size > maxBytes)
      return setLocalError("The file is larger than the 64 MiB limit. Nothing was uploaded.");
    if (target === "new" && !sampleName.trim()) return setLocalError("Give the new sample a name.");
    if (target === "existing" && !sampleId) return setLocalError("Choose an existing sample.");
    if (!statement.trim()) return setLocalError("The authorisation statement is required.");
    upload.mutate();
  };

  if (project.isPending) return <Loading label="Loading project…" />;
  if (project.isError) return <ErrorPanel error={project.error} />;

  const existing = samples.data ?? [];
  const problem = upload.error instanceof ApiError ? upload.error.problem : null;

  return (
    <>
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to={`/projects/${projectId}`}>← {project.data.name}</Link>
      </nav>
      <header className="page-header">
        <h1>Import a binary</h1>
        <p className="lede">Up to 64 MiB. PE and ELF files only. The file is read, never run.</p>
      </header>

      <section className="notice" aria-labelledby="policy-heading">
        <h2 id="policy-heading">Supported inputs</h2>
        <p>{INPUT_POLICY_DISCLOSURE}</p>
        {fixturesOnly ? (
          <p>
            <strong>Fixtures-only mode:</strong> only files listed in Bytasm's fixture manifest
            (<code>fixtures/MANIFEST.sha256</code>) are accepted. Any other file is refused before
            it is parsed. This cannot be changed from the browser.
          </p>
        ) : (
          <p>
            <strong>self_built mode is on</strong> (local server configuration): files you compiled
            from source you wrote are also accepted, on your word. Bytasm cannot verify that.
          </p>
        )}
      </section>

      <form className="card form" onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="import-file">
            <span>File</span>
          </label>
          <input
            id="import-file"
            type="file"
            onChange={(event) => choose(event.target.files?.[0] ?? null)}
            aria-describedby="file-hint"
          />
          <small id="file-hint" className="hint">
            The file name is recorded as uploaded and treated as untrusted text.
          </small>
        </div>

        <fieldset className="field">
          <legend>Add it to</legend>
          <label className="choice">
            <input
              type="radio"
              name="target"
              checked={target === "new"}
              onChange={() => setTarget("new")}
            />
            A new sample
          </label>
          <label className="choice">
            <input
              type="radio"
              name="target"
              checked={target === "existing"}
              onChange={() => setTarget("existing")}
              disabled={existing.length === 0}
            />
            A new version of an existing sample
          </label>
        </fieldset>

        {target === "new" ? (
          <label className="field">
            <span>Sample name</span>
            <input
              value={sampleName}
              onChange={(event) => setSampleName(event.target.value)}
              maxLength={200}
              placeholder="my-cli-tool"
            />
          </label>
        ) : (
          <label className="field">
            <span>Sample</span>
            <select value={sampleId} onChange={(event) => setSampleId(event.target.value)}>
              <option value="">Choose a sample…</option>
              {existing.map((sample) => (
                <option key={sample.id} value={sample.id}>
                  {sample.name}
                </option>
              ))}
            </select>
          </label>
        )}

        <label className="field">
          <span>Version label (optional)</span>
          <input
            value={versionLabel}
            onChange={(event) => setVersionLabel(event.target.value)}
            maxLength={100}
            placeholder="v1.0.0"
          />
        </label>

        <fieldset className="field">
          <legend>Authorisation (self-attestation)</legend>
          <label className="choice">
            <input type="radio" name="basis" checked readOnly />I built this binary from source I
            wrote or control
          </label>
          <p className="hint">
            This is the only basis in v0.1. Other bases need an isolation boundary first.
          </p>
          <label className="field">
            <span>Statement</span>
            <textarea
              value={statement}
              onChange={(event) => setStatement(event.target.value)}
              maxLength={2000}
              rows={3}
              placeholder="I compiled this from fixtures/src/hello_v1.c in the Bytasm repository."
              aria-describedby="attestation-notice"
            />
          </label>
          <p id="attestation-notice" className="hint">
            {ATTESTATION_NOTICE}
          </p>
        </fieldset>

        <div className="actions">
          <button className="button button-primary" type="submit" disabled={upload.isPending}>
            {upload.isPending ? "Importing…" : "Import"}
          </button>
          <div aria-live="polite" className="status-text">
            {upload.isPending && "Uploading, validating and reading metadata…"}
          </div>
        </div>

        {localError && (
          <div className="error" role="alert">
            <p>{localError}</p>
          </div>
        )}
        {upload.isError && (
          <>
            <ErrorPanel error={upload.error} title={problem?.title ?? "The file was not imported"} />
            {problem?.code === "input_policy" && (
              <p className="hint">
                Only the committed fixtures are accepted in this mode. See “Supported inputs and
                security limits” in the README.
              </p>
            )}
            {problem?.existing_version_id && (
              <p>
                <Link to={`/versions/${problem.existing_version_id}`}>Open the existing version</Link>
              </p>
            )}
          </>
        )}
      </form>
    </>
  );
}
