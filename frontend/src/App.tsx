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
import { useRoute } from "./router";
import { NotFound } from "./pages/NotFound";
import { NavRail, StatusBar } from "./shell";

export function App() {
  const route = useRoute();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, staleTime: 60_000 });

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <NavRail route={route} />
      <div className="workspace">
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
        {route.name === "not_found" && <NotFound />}
        </main>
        <StatusBar health={health.data} healthError={health.isError} />
      </div>
    </div>
  );
}
