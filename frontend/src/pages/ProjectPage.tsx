import { useQuery } from "@tanstack/react-query";
import { api, type Sample } from "../api";
import { BinaryArt } from "../art/BinaryArt";
import { MastScene, Ruins } from "../art/MastArt";
import {
  AdmittedPill,
  EmptyArt,
  ErrorPanel,
  Loading,
  MetricStrip,
  PageMast,
  formatBytes,
  formatDate,
  shortHash,
} from "../components";
import { Link } from "../router";
import { Breadcrumbs } from "../shell";
import { ProjectActivity } from "./ProjectActivity";

export function ProjectPage({ projectId }: { projectId: string }) {
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.project(projectId) });
  const samples = useQuery({
    queryKey: ["samples", projectId],
    queryFn: () => api.samples(projectId),
  });

  if (project.isPending) return <Loading label="Loading project…" />;
  if (project.isError) return <ErrorPanel error={project.error} />;
  const all = samples.data ?? [];
  const versions = all.flatMap((sample) => sample.versions);
  const formats = [...new Set(versions.map((version) => version.detected_format))].sort();
  const lastImport = versions.reduce<string | null>((max, version) => (!max || version.imported_at > max ? version.imported_at : max), null);
  const importLink = (
    <Link className="button button-primary button-arrow" to={`/projects/${projectId}/import`}>
      Import a binary
    </Link>
  );

  return (
    <>
      <Breadcrumbs items={[{ to: "/", label: "Projects" }]} current={project.data.name} />
      <PageMast
        level="workspace"
        eyebrow={
          <>
            <b>∷</b> Project workspace
          </>
        }
        title={project.data.name}
        lede={project.data.description || undefined}
        actions={importLink}
        // Architecture, not a figure: no character stands beside a project's samples
        // (ASCII_INTEGRATION §1), and "An empty satchel" owns the figure when there are none.
        art={<MastScene kind="architecture" ornament={<Ruins />} />}
      />

      {all.length > 0 && (
        <MetricStrip
          label="Project counts"
          items={[
            ["Samples", all.length.toLocaleString("en")],
            ["Versions", versions.length.toLocaleString("en")],
            ["Formats", <span className="metric-words">{formats.join(" · ") || "—"}</span>],
            ["Last import", <span className="metric-date">{lastImport ? lastImport.slice(0, 10) : "—"}</span>],
          ]}
        />
      )}

      <div className="workspace-layout">
        <section aria-labelledby="samples" className="specimens">
          <h2 id="samples" className="section-label section-label-first">
            Samples
          </h2>
          {samples.isPending && <Loading label="Loading samples…" />}
          {samples.isError && <ErrorPanel error={samples.error} />}
          {samples.data?.length === 0 && (
            <EmptyArt art={<BinaryArt character="scavenger" tint="bone" />} className="empty-satchel">
              <p className="empty-kicker" aria-hidden="true">
                An empty satchel
              </p>
              <p>
                <strong>No samples yet.</strong> Import one of Bytasm's fixtures to add the first one.
                Each import is identified by its SHA-256 and kept as a version of a sample.
              </p>
              <p className="hint">
                Only files listed in the fixture manifest (or, when the operator enables it, binaries you
                built yourself) are accepted. Nothing is executed.
              </p>
              <div>{importLink}</div>
            </EmptyArt>
          )}
          {samples.data?.map((sample, index) => (
            <Specimen key={sample.id} sample={sample} projectId={projectId} index={index} />
          ))}
        </section>
        <aside className="field-log" aria-label="Project activity log">
          <ProjectActivity key={projectId} projectId={projectId} />
        </aside>
      </div>
    </>
  );
}

/** One sample as a specimen: its versions on a spine, oldest first, with real comparisons between them. */
function Specimen({ sample, projectId, index }: { sample: Sample; projectId: string; index: number }) {
  const ordered = [...sample.versions].sort((a, b) => a.imported_at.localeCompare(b.imported_at));
  return (
    <article className="specimen" aria-label={`Sample ${sample.name}`}>
      <header className="specimen-head">
        <span className="specimen-no" aria-hidden="true">
          S{String(index + 1).padStart(2, "0")}
        </span>
        <h3 className="untrusted">{sample.name}</h3>
        <span className="hint mono">
          {sample.versions.length} version{sample.versions.length === 1 ? "" : "s"}
        </span>
        {sample.versions.length >= 2 && (
          <Link className="specimen-compare" to={`/projects/${projectId}/compare/${sample.id}`}>
            Compare versions of {sample.name}
          </Link>
        )}
      </header>
      {ordered.length === 0 ? (
        <p className="hint specimen-empty">No versions recorded for this sample.</p>
      ) : (
        // Focusable so the list can be scrolled sideways from the keyboard on narrow screens.
        <div className="spine-scroll" tabIndex={0} role="region" aria-label={`Versions of ${sample.name}`}>
          <ol className="spine">
            {ordered.map((version) => (
              <li key={version.id} className="spine-node">
                <span className="spine-mark" aria-hidden="true" />
                <div className="spine-main">
                  <Link className="row-link spine-label" to={`/versions/${version.id}`}>
                    {version.version_label ?? "(unlabelled)"}
                  </Link>
                  <span className="chip mono">{version.detected_format}</span>
                  <span className="chip mono">{version.architecture}</span>
                  <AdmittedPill value={version.admitted_under} />
                </div>
                <dl className="spine-facts">
                  <div>
                    <dt>SHA-256</dt>
                    <dd>
                      <code title={version.sha256}>{shortHash(version.sha256)}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Size</dt>
                    <dd className="mono">{formatBytes(version.size_bytes).split(" (")[0]}</dd>
                  </div>
                  <div>
                    <dt>Imported</dt>
                    <dd className="mono">{formatDate(version.imported_at)}</dd>
                  </div>
                </dl>
              </li>
            ))}
          </ol>
        </div>
      )}
    </article>
  );
}
