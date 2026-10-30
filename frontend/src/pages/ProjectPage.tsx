import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { AdmittedPill, Empty, ErrorPanel, Loading, formatDate, shortHash } from "../components";
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

  return (
    <>
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to="/">← Projects</Link>
      </nav>
      <header className="page-header page-header-actions">
        <div>
          <h1>{project.data.name}</h1>
          {project.data.description && <p className="lede">{project.data.description}</p>}
        </div>
        <Link className="button button-primary" to={`/projects/${projectId}/import`}>
          Import a binary
        </Link>
      </header>

      <section aria-labelledby="samples">
        <h2 id="samples">Samples</h2>
        {samples.isPending && <Loading label="Loading samples…" />}
        {samples.isError && <ErrorPanel error={samples.error} />}
        {samples.data?.length === 0 && (
          <Empty>
            No samples yet. <Link to={`/projects/${projectId}/import`}>Import a binary</Link> to
            add the first one.
          </Empty>
        )}
        {samples.data?.map((sample) => (
          <article className="card" key={sample.id} aria-label={`Sample ${sample.name}`}>
            <h3>{sample.name}</h3>
            {sample.versions.length >= 2 && <p><Link to={`/projects/${projectId}/compare/${sample.id}`}>Compare versions of {sample.name}</Link></p>}
            {/* Focusable so the table can be scrolled sideways from the keyboard. */}
            <div
              className="table-scroll"
              tabIndex={0}
              role="region"
              aria-label={`Versions of ${sample.name}`}
            >
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
                        <Link to={`/versions/${version.id}`}>
                          {version.version_label ?? "(unlabelled)"}
                        </Link>
                      </td>
                      <td>{version.detected_format}</td>
                      <td>{version.architecture}</td>
                      <td>
                        <code title={version.sha256}>{shortHash(version.sha256)}</code>
                      </td>
                      <td>
                        <AdmittedPill value={version.admitted_under} />
                      </td>
                      <td className="muted">{formatDate(version.imported_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        ))}
      </section>
      <ProjectActivity key={projectId} projectId={projectId} />
    </>
  );
}
