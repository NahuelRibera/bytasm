import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Empty, ErrorPanel, Loading, formatDate } from "../components";
import { Link, navigate } from "../router";

export function ProjectsPage() {
  const projects = useQuery({ queryKey: ["projects"], queryFn: api.projects });
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
      <header className="page-header">
        <h1>Projects</h1>
        <p className="lede">A project groups the samples you import and their versions.</p>
      </header>

      <section className="card" aria-labelledby="new-project">
        <h2 id="new-project">New project</h2>
        <form className="form-row" onSubmit={submit}>
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
          <label className="field field-grow">
            <span>Description (optional)</span>
            <input
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              maxLength={2000}
            />
          </label>
          <button className="button button-primary" type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create project"}
          </button>
        </form>
        {create.isError && <ErrorPanel error={create.error} title="The project was not created" />}
      </section>

      <section aria-labelledby="project-list">
        <h2 id="project-list">Your projects</h2>
        {projects.isPending && <Loading label="Loading projects…" />}
        {projects.isError && <ErrorPanel error={projects.error} />}
        {projects.data?.length === 0 && (
          <Empty>No projects yet. Create one above, then import one of Bytasm's fixtures.</Empty>
        )}
        {projects.data && projects.data.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Description</th>
                <th scope="col" className="num">
                  Samples
                </th>
                <th scope="col">Created</th>
              </tr>
            </thead>
            <tbody>
              {projects.data.map((project) => (
                <tr key={project.id}>
                  <td>
                    <Link to={`/projects/${project.id}`}>{project.name}</Link>
                  </td>
                  <td className="muted">{project.description || "—"}</td>
                  <td className="num">{project.sample_count}</td>
                  <td className="muted">{formatDate(project.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
