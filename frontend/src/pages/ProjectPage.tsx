import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { BinaryArt } from "../art/BinaryArt";
import {
  AdmittedPill,
  EmptyArt,
  ErrorPanel,
  Loading,
  MetricStrip,
  SectionLabel,
  formatDate,
  shortHash,
} from "../components";
import { Link } from "../router";
import { ProjectActivity } from "./ProjectActivity";

export function ProjectPage({ projectId }: { projectId: string }) {
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.project(projectId) });
  const samples = useQuery({
    queryKey: ["samples", projectId],
    queryFn: () => api.samples(projectId),
  });

  if (project.isPending) return <Loading label="Loading project…" />;
  if (project.isError) return <ErrorPanel error={project.error} />;
  const versions = samples.data?.reduce((total, sample) => total + sample.versions.length, 0) ?? 0;

  return (
    <>
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to="/">← Projects</Link>
      </nav>
      <header className="page-header page-header-actions">
        <div>
          <p className="eyebrow">
            <b>∷</b> Project
          </p>
          <h1>{project.data.name}</h1>
          {project.data.description && <p className="lede">{project.data.description}</p>}
        </div>
        <Link className="button button-primary button-arrow" to={`/projects/${projectId}/import`}>
          Import a binary
        </Link>
      </header>

      {samples.data && samples.data.length > 0 && (
        <MetricStrip
          label="Project counts"
          items={[
            ["Samples", samples.data.length.toLocaleString("en")],
            ["Versions", versions.toLocaleString("en")],
          ]}
        />
      )}

      <section aria-labelledby="samples">
        <SectionLabel index="01">Samples</SectionLabel>
        <h2 id="samples">Samples</h2>
        {samples.isPending && <Loading label="Loading samples…" />}
        {samples.isError && <ErrorPanel error={samples.error} />}
        {samples.data?.length === 0 && (
          <EmptyArt art={<BinaryArt character="scavenger" tint="ash" />}>
            <p>
              <strong>No samples yet.</strong> Import one of Bytasm's fixtures to add the first one.
            </p>
            <p className="hint">
              Only files listed in the fixture manifest (or, when the operator enables it, binaries you
              built yourself) are accepted. Nothing is executed.
            </p>
            <div>
              <Link className="button button-primary button-arrow" to={`/projects/${projectId}/import`}>
                Import a binary
              </Link>
            </div>
          </EmptyArt>
        )}
        {samples.data?.map((sample) => (
          <article className="card sample-card" key={sample.id} aria-label={`Sample ${sample.name}`}>
            <div className="sample-card-head">
              <h3 className="untrusted">{sample.name}</h3>
              <span className="hint mono">
                {sample.versions.length} version{sample.versions.length === 1 ? "" : "s"}
              </span>
              {sample.versions.length >= 2 && (
                <Link to={`/projects/${projectId}/compare/${sample.id}`}>Compare versions of {sample.name}</Link>
              )}
            </div>
            {/* Focusable so the table can be scrolled sideways from the keyboard. */}
            <div className="table-scroll" tabIndex={0} role="region" aria-label={`Versions of ${sample.name}`}>
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Version</th>
                    <th scope="col">Format</th>
                    <th scope="col">Architecture</th>
                    <th scope="col">SHA-256</th>
                    <th scope="col">Admitted under</th>
                    <th scope="col">Imported</th>
                  </tr>
                </thead>
                <tbody>
                  {sample.versions.map((version) => (
                    <tr key={version.id}>
                      <td>
                        <Link className="row-link" to={`/versions/${version.id}`}>
                          {version.version_label ?? "(unlabelled)"}
                        </Link>
                      </td>
                      <td className="mono">{version.detected_format}</td>
                      <td className="mono">{version.architecture}</td>
                      <td>
                        <code title={version.sha256}>{shortHash(version.sha256)}</code>
                      </td>
                      <td>
                        <AdmittedPill value={version.admitted_under} />
                      </td>
                      <td className="muted mono">{formatDate(version.imported_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        ))}
      </section>
      <SectionLabel index="02">Activity</SectionLabel>
      <ProjectActivity key={projectId} projectId={projectId} />
    </>
  );
}
