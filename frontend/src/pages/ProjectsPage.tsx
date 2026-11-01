import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { BinaryArt } from "../art/BinaryArt";
import { EmptyArt, ErrorPanel, Loading, MetricStrip, SectionLabel, formatDate } from "../components";
import { Link, navigate } from "../router";

export function ProjectsPage() {
  const projects = useQuery({ queryKey: ["projects"], queryFn: api.projects });
  const list = projects.data ?? [];
  const samples = list.reduce((total, project) => total + project.sample_count, 0);

  return (
    <>
      <header className="hero page-header">
        <p className="eyebrow">
          <b>∷</b> Local workbench · static analysis only
        </p>
        <h1>
          Projects <span className="dim">· evidence first, nothing executed</span>
        </h1>
        <p className="lede">A project groups the samples you import and their versions.</p>
      </header>

      {projects.isPending && <Loading label="Loading projects…" />}
      {projects.isError && <ErrorPanel error={projects.error} />}

      {projects.data?.length === 0 && (
        <EmptyArt art={<BinaryArt character="crow" tint="signal" />}>
          <h2>No projects yet</h2>
          <p>A project groups the samples you analyse. Create one, then import one of Bytasm's fixtures.</p>
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
            ]}
          />
          <div className="projects-layout">
            <section aria-labelledby="project-list">
              <SectionLabel index="01">Index</SectionLabel>
              <h2 id="project-list">Your projects</h2>
              {/* Focusable so the table can be scrolled sideways from the keyboard. */}
              <div className="table-scroll" tabIndex={0} role="region" aria-label="Projects table">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Project</th>
                      <th scope="col">Description</th>
                      <th scope="col" className="num">
                        Samples
                      </th>
                      <th scope="col">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((project) => (
                      <tr key={project.id}>
                        <td>
                          <Link className="row-link" to={`/projects/${project.id}`}>
                            {project.name}
                          </Link>
                        </td>
                        <td className="muted">{project.description || "—"}</td>
                        <td className="num mono">{project.sample_count}</td>
                        <td className="muted mono">{formatDate(project.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
            <section className="card" aria-labelledby="new-project">
              <SectionLabel index="02">Create</SectionLabel>
              <h2 id="new-project">New project</h2>
              <NewProjectForm />
            </section>
          </div>
        </>
      )}
    </>
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
