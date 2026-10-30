import { ToolsPage } from "./pages/ToolsPage";
import { ReportPage } from "./pages/ReportPage";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { SelfBuiltBanner } from "./components";
import { ImportPage } from "./pages/ImportPage";
import { ComparePage } from "./pages/ComparePage";
import { ProjectPage } from "./pages/ProjectPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { RulesPage } from "./pages/RulesPage";
import { RunPage } from "./pages/RunPage";
import { VersionPage } from "./pages/VersionPage";
import { AnalysisPanel } from "./AnalysisPanel";
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
        <nav className="topbar-nav" aria-label="Main">
          <Link to="/" aria-current={route.name === "projects" ? "page" : undefined}>
            Projects
          </Link>
          <Link to="/rules" aria-current={route.name === "rules" ? "page" : undefined}>
            Rules
          </Link>
          <Link to="/tools" aria-current={route.name === "tools" ? "page" : undefined}>Tools</Link>
        </nav>
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
        {route.name === "tools" && <ToolsPage />}
        {route.name === "report" && <ReportPage key={route.reportId} reportId={route.reportId} />}
        {route.name === "compare" && <ComparePage key={route.sampleId} projectId={route.projectId} sampleId={route.sampleId} />}
        {route.name === "project" && <ProjectPage projectId={route.projectId} />}
        {route.name === "import" && <ImportPage projectId={route.projectId} health={health.data} />}
        {route.name === "version" && (
          <VersionPage
            versionId={route.versionId}
            actions={<ExportReportButton versionId={route.versionId} />}
            analysis={(version) => <AnalysisPanel version={version} />}
          />
        )}
        {route.name === "rules" && <RulesPage key={route.ruleSetId ?? "current"} ruleSetId={route.ruleSetId} />}
        {route.name === "run" && <RunPage key={route.runId} runId={route.runId} />}
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
        Bytasm never runs the files it imports. It is for self-authored binaries only and is not
        safe for downloaded, received, third-party, or suspicious files. Resource limits are not a
        sandbox. Rule matches are observations, not verdicts.
      </footer>
    </div>
  );
}
