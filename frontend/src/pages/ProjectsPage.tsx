import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, type Project } from "../api";
import { BinaryArt } from "../art/BinaryArt";
import { JourneyScene } from "../art/JourneyScene";
import { EmptyArt, ErrorPanel, Loading, MetricStrip, formatDate } from "../components";
import { Link, navigate } from "../router";
import { Isotipo } from "../shell";

// The real order of work in Bytasm, shown once on the entrance page.
const ROUTE = ["Import a binary", "Inspect its structure", "Run static analysis", "Pin a review"];

export function ProjectsPage() {
  const projects = useQuery({ queryKey: ["projects"], queryFn: api.projects });
  const list = projects.data ?? [];
  const samples = list.reduce((total, project) => total + project.sample_count, 0);
  const latest = list.reduce<string | null>((max, project) => (!max || project.created_at > max ? project.created_at : max), null);

  return (
    <>
      <div className="masthead">
        <JourneyScene />
        <div className="masthead-copy">
          <p className="mast-kicker">
            <Isotipo size={20} />
            <span>Bytasm · local workbench</span>
          </p>
          <h1 className="mast-title">Static analysis for unknown lands</h1>
          <p className="mast-lede">
            Bring in binaries you built yourself, read their structure, and keep every observation tied
            to the bytes that support it. Nothing you import is ever executed.
          </p>
          <div className="mast-actions">
            <a className="button button-primary button-arrow button-large" href="#new-project">
              New project
            </a>
            {list.length > 0 && (
              <a className="button button-ghost button-large" href="#project-list">
                Open a project
              </a>
            )}
          </div>
          <ol className="mast-route" aria-label="How work proceeds in Bytasm">
            {ROUTE.map((step, index) => (
              <li key={step}>
                <span aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
                {step}
              </li>
            ))}
          </ol>
        </div>
      </div>

      {projects.isPending && <Loading label="Loading projects…" />}
      {projects.isError && <ErrorPanel error={projects.error} />}

      {projects.data?.length === 0 && (
        <EmptyArt
          art={<BinaryArt character="crow" tint="bone" className="art-dense" />}
          className="empty-crow"
        >
          <h2 id="new-project" tabIndex={-1}>
            No projects yet
          </h2>
          <p>
            A project holds the samples you study: each import becomes a sample version with its own
            hash, metadata and analysis runs. Name one, then import one of Bytasm's fixtures.
          </p>
          <p className="hint">Bytasm never runs the files it imports. Use it only for binaries you built yourself.</p>
          <NewProjectForm />
        </EmptyArt>
      )}

      {projects.data && projects.data.length > 0 && (
        <>
          <MetricStrip
            label="Workspace counts"
            items={[
              ["Projects", list.length.toLocaleString("en")],
              ["Samples", samples.toLocaleString("en")],
              ["Newest project", <span className="metric-date">{latest ? latest.slice(0, 10) : "—"}</span>],
            ]}
          />
          <div className="projects-layout">
            <section aria-labelledby="project-list">
              <h2 id="project-list" className="section-label section-label-first" tabIndex={-1}>
                Your projects
              </h2>
              <ProjectLedger projects={list} />
            </section>
            <section className="panel frame-bracket create-panel" aria-labelledby="new-project">
              <div className="panel-head">
                <h2 id="new-project" tabIndex={-1}>
                  New project
                </h2>
              </div>
              <div className="panel-body">
                <p className="hint create-note">
                  Group the versions of one program you are studying. You can import into it right after.
                </p>
                <NewProjectForm />
              </div>
            </section>
          </div>
        </>
      )}
    </>
  );
}

/** Projects as a ledger: newest first, each row one project, the counts straight from the API. */
function ProjectLedger({ projects }: { projects: Project[] }) {
  const ordered = [...projects].sort((a, b) => b.created_at.localeCompare(a.created_at));
  const most = Math.max(1, ...ordered.map((project) => project.sample_count));
  return (
    // Focusable so the table can be scrolled sideways from the keyboard.
    <div className="table-scroll ledger-scroll" tabIndex={0} role="region" aria-label="Projects table">
      <table className="table ledger">
        <thead>
          <tr>
            <th scope="col" className="num ledger-no">
              <span aria-hidden="true">№</span>
              <span className="sr-only">Number</span>
            </th>
            <th scope="col">Project</th>
            <th scope="col" className="num">
              Samples
            </th>
            <th scope="col">Created</th>
          </tr>
        </thead>
        <tbody>
          {ordered.map((project, index) => (
            <tr key={project.id}>
              <td className="num ledger-no mono">{String(ordered.length - index).padStart(2, "0")}</td>
              <td className="ledger-name">
                <Link className="row-link" to={`/projects/${project.id}`}>
                  {project.name}
                </Link>
                <span className="ledger-desc untrusted">{project.description || "No description"}</span>
              </td>
              <td className="num">
                <span className="ledger-count">
                  <span className="ledger-bar" aria-hidden="true">
                    <span style={{ width: `${(project.sample_count / most) * 100}%` }} />
                  </span>
                  <span className="mono">{project.sample_count}</span>
                </span>
              </td>
              <td className="muted mono">{formatDate(project.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function NewProjectForm() {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const create = useMutation({
    mutationFn: () => api.createProject(name, description),
    onSuccess: (project) => {
      void client.invalidateQueries({ queryKey: ["projects"] });
      navigate(`/projects/${project.id}`);
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (name.trim()) create.mutate();
  };

  return (
    <>
      <form className="form new-project-form" onSubmit={submit}>
        <label className="field">
          <span>Name</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            maxLength={200}
            placeholder="Demo: Bytasm fixtures"
          />
        </label>
        <label className="field">
          <span>Description (optional)</span>
          <input value={description} onChange={(event) => setDescription(event.target.value)} maxLength={2000} />
        </label>
        <div>
          <button className="button button-primary button-arrow" type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create project"}
          </button>
        </div>
      </form>
      {create.isError && <ErrorPanel error={create.error} title="The project was not created" />}
    </>
  );
}
