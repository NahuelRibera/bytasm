// App shell pieces (M2 Journey, docs/milestones/m2-journey-frontend.md): a horizontal top bar
// with the approved isotipo, a breadcrumb trail per page, an optional section index for long
// technical pages, and the status bar. The input policy and Bytasm's global limitations stay
// reachable on every screen (D4): the policy sits in the top bar, the limits in the status bar.
import { useEffect, useState, type ReactNode } from "react";
import type { Health } from "./api";
import { ProjectsIcon, RulesIcon, ToolsIcon } from "./icons";
import { Link, type Route } from "./router";

const SECTIONS = [
  { to: "/", label: "Projects", icon: <ProjectsIcon />, active: ["projects", "project", "import", "compare", "version", "run", "report"] },
  { to: "/rules", label: "Rules", icon: <RulesIcon />, active: ["rules"] },
  { to: "/tools", label: "Tools", icon: <ToolsIcon />, active: ["tools"] },
] as const;

/** The approved isotipo, untouched: the SVG file as delivered (its own black field included),
 *  drawn as a CSS background so pages keep their "no <img> from content" invariant. */
export function Isotipo({ size = 28, className }: { size?: number; className?: string }) {
  return (
    <span
      className={["isotipo", className].filter(Boolean).join(" ")}
      style={{ width: size, height: size }}
      aria-hidden="true"
    />
  );
}

export function TopBar({ route, health, healthError }: { route: Route; health: Health | undefined; healthError: boolean }) {
  const mode = health?.input_policy.mode;
  return (
    <header className="topbar">
      <Link to="/" className="brand" aria-label="Bytasm home">
        <Isotipo />
        <span className="brand-word" aria-hidden="true">
          Bytasm
        </span>
      </Link>
      <nav className="topnav" aria-label="Main">
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
      <div className="topbar-status">
        <span className={`pill ${mode === "self_built" ? "pill-warn" : "pill-ok"}`}>
          <span className="pill-dot" aria-hidden="true" />
          Input policy: {mode === "self_built" ? "fixtures + self-built" : "fixtures only"}
        </span>
        <span className={`api-state ${healthError ? "api-down" : health ? "api-up" : ""}`}>
          <span className="api-led" aria-hidden="true" />
          {healthError ? "API unreachable" : health ? "API ok" : "API …"}
        </span>
      </div>
    </header>
  );
}

export interface Crumb {
  to: string;
  label: ReactNode;
  /** Names that come from a file or the user are untrusted and may be long. */
  untrusted?: boolean;
}

/** Where the page sits: Projects / project / sample version / run. The last item is the page. */
export function Breadcrumbs({ items, current }: { items: Crumb[]; current: ReactNode }) {
  return (
    <nav className="trail" aria-label="Breadcrumb">
      <ol>
        {items.map((item) => (
          <li key={item.to}>
            <Link to={item.to} className={item.untrusted ? "untrusted" : undefined}>
              {item.label}
            </Link>
          </li>
        ))}
        <li aria-current="page">
          <span>{current}</span>
        </li>
      </ol>
    </nav>
  );
}

export interface IndexEntry {
  id: string;
  label: string;
  group?: string;
}

/** A narrow index of a long technical page. Links are plain anchors to section ids; the last
 *  section whose top has passed under the top bar is marked as the current location. */
export function SectionIndex({ entries, label }: { entries: IndexEntry[]; label: string }) {
  const [active, setActive] = useState<string | null>(entries[0]?.id ?? null);
  const ids = entries.map((entry) => entry.id).join("|");
  useEffect(() => {
    // Sections render asynchronously (findings, Ghidra), so look them up on every check.
    let frame = 0;
    const check = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        let current: string | null = null;
        for (const id of ids.split("|")) {
          const element = document.getElementById(id);
          if (element && element.getBoundingClientRect().top <= 140) current = id;
        }
        setActive(current ?? ids.split("|")[0] ?? null);
      });
    };
    check();
    window.addEventListener("scroll", check, { passive: true });
    window.addEventListener("hashchange", check);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", check);
      window.removeEventListener("hashchange", check);
    };
  }, [ids]);

  let group: string | undefined;
  return (
    <nav className="section-index" aria-label={label}>
      <details open>
        <summary>On this page</summary>
        <ol>
          {entries.map((entry, position) => {
            const heading = entry.group && entry.group !== group ? entry.group : null;
            group = entry.group;
            return (
              <li key={entry.id} className={heading ? "index-group-start" : undefined}>
                {heading && <span className="index-group" aria-hidden="true">{heading}</span>}
                <a
                  href={`#${entry.id}`}
                  aria-current={active === entry.id ? "location" : undefined}
                  onClick={(event) => {
                    const target = document.getElementById(entry.id);
                    if (!target) return;
                    event.preventDefault();
                    target.scrollIntoView({ block: "start" });
                    if (!target.hasAttribute("tabindex")) target.setAttribute("tabindex", "-1");
                    target.focus({ preventScroll: true });
                    setActive(entry.id);
                  }}
                >
                  <span className="index-num" aria-hidden="true">{String(position + 1).padStart(2, "0")}</span>
                  {entry.label}
                </a>
              </li>
            );
          })}
        </ol>
      </details>
    </nav>
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

export function StatusBar({ health }: { health: Health | undefined }) {
  const [atmosphere, setAtmosphere] = useAtmosphere();
  return (
    <footer className="statusbar">
      <span className="statusbar-item">
        <span className="statusbar-glyph" aria-hidden="true">∷</span> local · static analysis only
      </span>
      {health && <span className="statusbar-item statusbar-optional">v{health.bytasm_version}</span>}
      {health && <span className="statusbar-item statusbar-optional">YARA-X {health.yara_x_version}</span>}
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
