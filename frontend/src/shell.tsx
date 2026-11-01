// App shell pieces: navigation rail and status bar (docs/design/DESIGN_SYSTEM.md §4.1).
// The input policy and Bytasm's global limitations stay reachable on every screen (D4).
import { useEffect, useState } from "react";
import type { Health } from "./api";
import { BrandMark, ProjectsIcon, RulesIcon, ToolsIcon } from "./icons";
import { Link, type Route } from "./router";

const SECTIONS = [
  { to: "/", label: "Projects", icon: <ProjectsIcon />, active: ["projects", "project", "import", "compare", "version", "run", "report"] },
  { to: "/rules", label: "Rules", icon: <RulesIcon />, active: ["rules"] },
  { to: "/tools", label: "Tools", icon: <ToolsIcon />, active: ["tools"] },
] as const;

export function NavRail({ route }: { route: Route }) {
  return (
    <header className="rail">
      <Link to="/" className="brand" aria-label="Bytasm home">
        <BrandMark />
        <span aria-hidden="true">Bytasm</span>
      </Link>
      <nav className="rail-nav" aria-label="Main">
        {SECTIONS.map((section) => (
          <Link
            key={section.to}
            to={section.to}
            aria-current={(section.active as readonly string[]).includes(route.name) ? "page" : undefined}
          >
            {section.icon}
            <span>{section.label}</span>
          </Link>
        ))}
      </nav>
      <div className="rail-foot" aria-hidden="true" />
    </header>
  );
}

const ATMOSPHERE_KEY = "bytasm.atmosphere";

function readAtmosphere(): boolean {
  try {
    return window.localStorage.getItem(ATMOSPHERE_KEY) !== "off";
  } catch {
    return true;
  }
}

/** Decorative art and motion can be switched off; the choice is a per-browser convenience. */
export function useAtmosphere(): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(readAtmosphere);
  useEffect(() => {
    document.documentElement.dataset.atmosphere = on ? "on" : "off";
    try {
      window.localStorage.setItem(ATMOSPHERE_KEY, on ? "on" : "off");
    } catch {
      // Storage can be unavailable (private windows); the toggle still works for this page.
    }
  }, [on]);
  return [on, setOn];
}

export function StatusBar({ health, healthError }: { health: Health | undefined; healthError: boolean }) {
  const [atmosphere, setAtmosphere] = useAtmosphere();
  const mode = health?.input_policy.mode;
  return (
    <footer className="statusbar">
      <span className={`pill ${mode === "self_built" ? "pill-warn" : "pill-ok"}`}>
        <span className="pill-dot" aria-hidden="true" />
        Input policy: {mode === "self_built" ? "fixtures + self-built" : "fixtures only"}
      </span>
      <span className="statusbar-item statusbar-optional">
        {healthError ? "API unreachable" : health ? "API ok" : "API …"}
      </span>
      <span className="statusbar-item statusbar-optional">local · static analysis only</span>
      {health && <span className="statusbar-item statusbar-optional">v{health.bytasm_version}</span>}
      <span className="statusbar-spacer" />
      <button type="button" aria-pressed={!atmosphere} onClick={() => setAtmosphere(!atmosphere)}>
        Reduce atmosphere
      </button>
      <details className="limits">
        <summary>Limits</summary>
        <div className="limits-panel">
          <p>
            Bytasm never runs the files it imports. It is for self-authored binaries only and is not
            safe for downloaded, received, third-party, or suspicious files.
          </p>
          <p>Resource limits are not a sandbox. Rule matches are observations, not verdicts.</p>
        </div>
      </details>
    </footer>
  );
}
