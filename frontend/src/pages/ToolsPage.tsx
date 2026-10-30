import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { ErrorPanel, Loading } from "../components";

export function ToolsPage() {
  const tools = useQuery({ queryKey: ["tools"], queryFn: api.tools });
  if (tools.isPending) return <Loading label="Loading tool versions…" />;
  if (tools.isError) return <ErrorPanel error={tools.error} />;
  return <><h1>Tools and profiles</h1><p>Installed static analysis tools. No sample is opened to populate this page.</p>
    <div className="grid-2">{tools.data.tools.map((tool) => <section className="card" key={tool.tool}>
      <h2>{tool.tool} <span className="count">{tool.version ?? "Unavailable"}</span></h2>
      <p>{tool.available ? "Available" : "Unavailable for the configured version"}</p><p>{tool.adapter} {tool.adapter_version} · {tool.formats.join(", ")}</p>
      <p>{tool.limitations}</p>{tool.rules_sha256 && <p className="untrusted">Rules SHA-256: <code>{tool.rules_sha256}</code></p>}
    </section>)}</div><h2>Built-in profiles</h2>{tools.data.profiles.map((profile) => <section className="card" key={profile.id}>
      <h3>{profile.name}</h3><p>{profile.steps.join(" → ")}</p><p>{profile.limitations}</p>
    </section>)}<p>Header metadata is always read at import. Custom commands, plugins and editable rules are unavailable.</p></>;
}
