import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { SelfBuiltBanner } from "./components";
import { ImportPage } from "./pages/ImportPage";
import { ProjectPage } from "./pages/ProjectPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { VersionPage } from "./pages/VersionPage";
import { ExportReportButton } from "./ExportReportButton";
import { Link, useRoute } from "./router";

export function App() {
  const route = useRoute();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, staleTime: 60_000 });
  const mode = health.data?.input_policy.mode;

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <Link to="/" className="brand" aria-label="Bytasm home">
          <span className="brand-mark" aria-hidden="true">
            ▚
          </span>
          Bytasm
        </Link>
        <span className="topbar-meta">
          local · static analysis only
          {health.data && <> · v{health.data.bytasm_version}</>}
        </span>
        <span className={`pill ${mode === "self_built" ? "pill-warn" : "pill-ok"}`}>
          <span className="pill-dot" aria-hidden="true" />
          Input policy: {mode === "self_built" ? "fixtures + self-built" : "fixtures only"}
        </span>
      </header>
      <SelfBuiltBanner health={health.data} />
      <main id="main" className="main" tabIndex={-1}>
        {route.name === "projects" && <ProjectsPage />}
        {route.name === "project" && <ProjectPage projectId={route.projectId} />}
        {route.name === "import" && <ImportPage projectId={route.projectId} health={health.data} />}
        {route.name === "version" && (
          <VersionPage
            versionId={route.versionId}
            actions={<ExportReportButton versionId={route.versionId} />}
          />
        )}
        {route.name === "not_found" && (
          <div className="empty">
            <h1>Not found</h1>
            <p>
              Nothing lives at this address. <Link to="/">Back to projects</Link>
            </p>
          </div>
        )}
      </main>
      <footer className="footer">
        Bytasm never runs the files it imports. v0.1 is for self-authored binaries only and is not
        safe for downloaded, received, third-party, or suspicious files. Resource limits are not a
        sandbox.
      </footer>
    </div>
  );
}
