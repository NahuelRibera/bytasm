// A tiny history-API router: v0.1 has four screens, so no router library.
import { useEffect, useState, type AnchorHTMLAttributes, type MouseEvent } from "react";

export type Route =
  | { name: "projects" }
  | { name: "project"; projectId: string }
  | { name: "import"; projectId: string }
  | { name: "version"; versionId: string }
  | { name: "not_found" };

const ID = "([0-9a-f]{32})";

export function parseRoute(path: string): Route {
  let match: RegExpMatchArray | null;
  if (path === "/" || path === "") return { name: "projects" };
  if ((match = path.match(new RegExp(`^/projects/${ID}/?$`))))
    return { name: "project", projectId: match[1]! };
  if ((match = path.match(new RegExp(`^/projects/${ID}/import/?$`))))
    return { name: "import", projectId: match[1]! };
  if ((match = path.match(new RegExp(`^/versions/${ID}/?$`))))
    return { name: "version", versionId: match[1]! };
  return { name: "not_found" };
}

const EVENT = "bytasm:navigate";

export function navigate(to: string): void {
  window.history.pushState({}, "", to);
  window.dispatchEvent(new Event(EVENT));
  window.scrollTo?.(0, 0);
}

export function useRoute(): Route {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const update = () => setPath(window.location.pathname);
    window.addEventListener("popstate", update);
    window.addEventListener(EVENT, update);
    return () => {
      window.removeEventListener("popstate", update);
      window.removeEventListener(EVENT, update);
    };
  }, []);
  return parseRoute(path);
}

export function Link({ to, onClick, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }) {
  const handle = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey)
      return;
    event.preventDefault();
    navigate(to);
  };
  return <a href={to} onClick={handle} {...rest} />;
}
