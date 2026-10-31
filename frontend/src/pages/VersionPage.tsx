import { ByteViewer } from "../ByteViewer";
import { PinnedReview } from "../PinnedReview";
import { InspectionOverview } from "../InspectionOverview";
import { SectionMap } from "../SectionMap";
import { ReportLibrary } from "../ReportLibrary";
import { useQuery } from "@tanstack/react-query";
import { useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { api, type SampleVersion, type StringCategory, type StringSort } from "../api";
import {
  AdmittedPill,
  CopyButton,
  Declared,
  Empty,
  ErrorPanel,
  KeyValues,
  Loading,
  formatBytes,
  formatDate,
  hex,
} from "../components";
import { Link } from "../router";
import { AnnotationsSection } from "./AnnotationsSection";

const TABS = ["Sections", "Imports", "Exports", "Strings"] as const;
type Tab = (typeof TABS)[number];
const STRINGS_PAGE = 100;

function initialTab(): Tab {
  return new URLSearchParams(window.location.search).get("tab") === "strings" ? "Strings" : "Sections";
}

export function VersionPage({
  versionId,
  actions,
  analysis,
}: {
  versionId: string;
  actions?: ReactNode;
  analysis?: (version: SampleVersion) => ReactNode;
}) {
  const version = useQuery({ queryKey: ["version", versionId], queryFn: () => api.version(versionId) });
  const [tab, setTab] = useState<Tab>(initialTab);
  const sourceRun = new URLSearchParams(window.location.search).get("run_id") ?? undefined;
  const strings = useQuery({
    queryKey: ["strings-summary", versionId, sourceRun],
    queryFn: () => api.strings(versionId, { limit: 1, run_id: sourceRun }),
  });

  if (version.isPending) return <Loading label="Loading sample version…" />;
  if (version.isError) return <ErrorPanel error={version.error} />;
  const v = version.data;
  const label = v.version_label ?? "(unlabelled version)";

  return (
    <>
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to={`/projects/${v.project_id}`}>← {v.project_name}</Link>
      </nav>
      <header className="page-header page-header-actions">
        <div>
          <h1>
            {v.sample_name} <span className="muted">{label}</span>
          </h1>
          <p className="status-line">
            <AdmittedPill value={v.admitted_under} />
            <span>
              {v.detected_format} · {v.header.architecture} · imported {formatDate(v.imported_at)}
            </span>
          </p>
        </div>
        {actions}
      </header>

      <InspectionOverview key={`${versionId}:${sourceRun ?? "latest"}`} version={v} runId={sourceRun} />
      <PinnedReview key={versionId} version={v} runId={sourceRun} />
      <ByteViewer key={`bytes:${versionId}`} versionId={versionId} />
      <div className="grid-2">
        <IdentityPanel v={v} />
        <MetadataPanel v={v} />
      </div>
      <ProvenancePanel v={v} />
      {analysis?.(v)}
      <ReportLibrary key={versionId} versionId={versionId} />
      <p><Link to={`/projects/${v.project_id}/compare/${v.sample_id}`}>Compare versions</Link></p>
      <AnnotationsSection key={versionId} versionId={versionId} />

      {v.warnings.length > 0 && (
        <section className="notice notice-warn" aria-labelledby="warnings">
          <h2 id="warnings">Measurement warnings</h2>
          <ul>
            {v.warnings.map((warning, index) => (
              <li key={index}>{warning}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="card" aria-label="File structure">
        <Tabs
          current={tab}
          onChange={setTab}
          counts={{ ...v.counts, strings: strings.data?.summary?.stored }}
        />
        <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} tabIndex={0}>
          {tab === "Sections" && <SectionsTable versionId={versionId} />}
          {tab === "Imports" && <ImportsList versionId={versionId} />}
          {tab === "Exports" && <ExportsList versionId={versionId} />}
          {tab === "Strings" && <StringsTab versionId={versionId} runId={sourceRun} onSection={() => setTab("Sections")} />}
        </div>
      </section>
    </>
  );
}

function IdentityPanel({ v }: { v: SampleVersion }) {
  return (
    <section className="card" aria-labelledby="identity">
      <h2 id="identity">Identity</h2>
      <KeyValues
        items={[
          [
            "SHA-256",
            <span className="hash-row">
              <code className="hash" data-testid="sha256">
                {v.sha256}
              </code>
              <CopyButton value={v.sha256} label="Copy SHA-256" />
            </span>,
          ],
          ["Size", formatBytes(v.size_bytes)],
          ["Format", <>{v.detected_format} <span className="hint">identified from the bytes</span></>],
          [
            "File name",
            <>
              <span className="untrusted">{v.declared_filename?.split(/[\\/]/).pop() || "—"}</span>{" "}
              {v.declared_filename && /[\\/]/.test(v.declared_filename) && <details><summary>Reveal original display name (may contain personal paths)</summary><span className="untrusted">{v.declared_filename}</span></details>}
              <span className="hint">as uploaded, untrusted</span>
            </>,
          ],
        ]}
      />
    </section>
  );
}

function MetadataPanel({ v }: { v: SampleVersion }) {
  const header = v.header;
  const declared = Object.entries(header.declared_header).sort(([a], [b]) => a.localeCompare(b));
  return (
    <section className="card" aria-labelledby="metadata">
      <h2 id="metadata">Header metadata</h2>
      <p className="hint">
        Values the file declares about itself. Bytasm does not verify them; a timestamp, for
        example, can be forged or zeroed.
      </p>
      <KeyValues
        items={[
          ["Architecture", <>{header.architecture} <Declared /></>],
          ["Bitness", <>{header.bitness}-bit <Declared /></>],
          ["Endianness", <>{header.endianness} <Declared /></>],
          ["Entry point", <><code>{header.entry_point_hex ?? hex(header.entry_point)}</code> <Declared /></>],
          ...declared.map(([key, value]): [ReactNode, ReactNode] => [
            <code>{key}</code>,
            <>
              <code>{typeof value === "number" && key !== "pe_timestamp" ? header.declared_header_exact?.[key] ?? hex(value) : String(value)}</code>{" "}
              <Declared />
            </>,
          ]),
          ["Linked libraries", header.imported_libraries.length],
        ]}
      />
    </section>
  );
}

function ProvenancePanel({ v }: { v: SampleVersion }) {
  return (
    <section className="card" aria-labelledby="provenance">
      <h2 id="provenance">Provenance</h2>
      <div className="grid-2">
        <KeyValues
          items={[
            ["Admitted under", <AdmittedPill value={v.admitted_under} />],
            ["Manifest entry", v.manifest_entry ? <code>{v.manifest_entry}</code> : "— (not a fixture)"],
            ["Parser", `${v.invocation.tool} ${v.invocation.tool_version}`],
            ["Adapter", `${v.invocation.adapter} ${v.invocation.adapter_version}`],
            ["Parse time", `${v.invocation.duration_ms} ms (separate process)`],
            ["Result SHA-256", <code className="hash">{v.invocation.result_sha256}</code>],
          ]}
        />
        <div>
          <h3>Authorisation (self-attestation)</h3>
          <KeyValues
            items={[
              ["Basis", <code>{v.authorization.basis}</code>],
              ["Statement", <span className="untrusted">{v.authorization.statement}</span>],
              ["Recorded", formatDate(v.authorization.recorded_at)],
            ]}
          />
          <p className="hint">{v.authorization.notice}</p>
        </div>
      </div>
    </section>
  );
}

function Tabs({
  current,
  onChange,
  counts,
}: {
  current: Tab;
  onChange: (tab: Tab) => void;
  counts: Record<string, number | undefined>;
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const count: Record<Tab, number | undefined> = {
    Sections: counts.sections,
    Imports: (counts.imported_functions ?? 0) + (counts.imported_libraries ?? 0),
    Exports: counts.exports,
    Strings: counts.strings,
  };
  const onKey = (event: KeyboardEvent, index: number) => {
    const delta = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (index + delta + TABS.length) % TABS.length;
    onChange(TABS[next]!);
    refs.current[next]?.focus();
  };
  return (
    <div role="tablist" aria-label="File structure" className="tabs">
      {TABS.map((tab, index) => (
        <button
          key={tab}
          ref={(element) => {
            refs.current[index] = element;
          }}
          role="tab"
          type="button"
          id={`tab-${tab}`}
          aria-selected={current === tab}
          aria-controls={`panel-${tab}`}
          tabIndex={current === tab ? 0 : -1}
          className="tab"
          onClick={() => onChange(tab)}
          onKeyDown={(event) => onKey(event, index)}
        >
          {tab} <span className="count">{count[tab] ?? "not available"}</span>
        </button>
      ))}
    </div>
  );
}

function StringsTab({ versionId, runId, onSection }: { versionId: string; runId?: string; onSection: () => void }) {
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [encoding, setEncoding] = useState<"" | "ascii" | "utf-16le">("");
  const [offset, setOffset] = useState(0);
  const [category, setCategory] = useState<"" | StringCategory>("");
  const [sort, setSort] = useState<StringSort>("offset");
  const [showPaths, setShowPaths] = useState(false);
  const page = useQuery({
    queryKey: ["strings", versionId, runId, query, encoding, offset, category, sort],
    queryFn: () =>
      api.strings(versionId, {
        query,
        run_id: runId,
        category: category || undefined,
        sort: sort === "offset" ? undefined : sort,
        encoding: encoding || undefined,
        offset,
        limit: STRINGS_PAGE,
      }),
    placeholderData: (previous) => previous,
  });

  if (page.isPending) return <Loading label="Loading strings…" />;
  if (page.isError) return <ErrorPanel error={page.error} />;
  const data = page.data;
  if (data.run_id === null) {
    return (
      <Empty>
        <p>
          No strings yet. Strings are extracted by an analysis run: use{" "}
          <strong>Run pattern matching…</strong> above.
        </p>
      </Empty>
    );
  }
  const last = Math.min(data.offset + data.items.length, data.matched);
  const groups = sort === "category"
    ? [...new Set(data.items.map(item => item.category ?? "other"))].map(category => ({ category, items: data.items.filter(item => (item.category ?? "other") === category) }))
    : [{ category: "all", items: data.items }];
  return (
    <>
      <ul className="hint">
        {data.notices.map((notice) => (
          <li key={notice}>{notice}</li>
        ))}
      </ul>
      <p className="hint">
        From <Link to={`/runs/${data.run_id}`}>this run</Link> ({data.tool_version}
        {data.run_status === "partial" ? ", a partial run" : ""}).
        {data.summary?.truncated &&
          ` The file holds ${data.summary.total_found.toLocaleString("en")} strings; the first ${data.summary.stored.toLocaleString("en")} by offset were kept.`}
      </p>
      <p className="hint">Heuristic categories describe text shape only, not its use or meaning. Counts cover all stored strings in this selected run before filtering: {Object.entries(data.category_counts ?? {}).map(([name, count]) => `${name}: ${count}`).join(" · ") || "not recorded"}.</p>
      <label className="privacy-choice"><input type="checkbox" checked={showPaths} onChange={event => setShowPaths(event.target.checked)} />Show path-like values (may contain personal paths)</label>
      <form
        className="filter-row"
        role="search"
        aria-label="Filter strings"
        onSubmit={(event) => {
          event.preventDefault();
          setQuery(search.trim());
          setOffset(0);
        }}
      >
        <label htmlFor="strings-search">Search strings</label>
        <input
          id="strings-search"
          type="search"
          maxLength={128}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <label htmlFor="strings-category">Heuristic category</label><select id="strings-category" value={category} onChange={event => { setCategory(event.target.value as "" | StringCategory); setOffset(0); }}>
          <option value="">All categories</option><option value="url_like">URL-like</option><option value="path_like">Path-like</option><option value="other">Other text</option></select>
        <label htmlFor="strings-sort">Sort / group</label><select id="strings-sort" value={sort} onChange={event => { setSort(event.target.value as StringSort); setOffset(0); }}>
          <option value="offset">File offset</option><option value="length">Length, longest first</option><option value="value">Displayed prefix, A–Z</option><option value="category">Group by heuristic category</option></select>
        <label htmlFor="strings-encoding">Encoding</label>
        <select
          id="strings-encoding"
          value={encoding}
          onChange={(event) => {
            setEncoding(event.target.value as "" | "ascii" | "utf-16le");
            setOffset(0);
          }}
        >
          <option value="">All</option>
          <option value="ascii">ASCII</option>
          <option value="utf-16le">UTF-16LE</option>
        </select>
        <button type="submit" className="button button-small">
          Search
        </button>
      </form>
      <p className="hint" aria-live="polite">
        {data.matched === 0
          ? "No string matches."
          : `Showing ${data.offset + 1}–${last} of ${data.matched.toLocaleString("en")}.`}
      </p>
      {data.items.length > 0 && (
        <div className="table-scroll" tabIndex={0} role="region" aria-label="Strings table">
          <table className="table table-dense strings-table">
            <caption>Strings found in the selected run; category groups and rows are paginated. Prefix sorting compares stored, possibly shortened values.</caption>
            <thead>
              <tr>
                <th scope="col" className="num">File offset</th>
                <th scope="col">Encoding</th>
                <th scope="col" className="num">Length</th>
                <th scope="col">Value (untrusted text)</th>
              </tr>
            </thead>
            {groups.map(group => <tbody key={group.category}>
              {sort === "category" && <tr><th scope="rowgroup" colSpan={4}>{group.category} · heuristic group, current page</th></tr>}
              {group.items.map((item) => (
                <tr key={`${item.offset}-${item.encoding}`}>
                  <td className="num">
                    <code>{hex(item.offset)}</code>
                    <div>{item.section ? <a href={`/versions/${versionId}#section-${item.section.index}`} onClick={onSection}>Section {item.section.index}: {item.section.name}</a> : <span className="hint">Unique containing raw section not established</span>}</div>
                  </td>
                  <td>{item.encoding === "ascii" ? "ASCII" : "UTF-16LE"}</td>
                  <td className="num">{item.length_chars.toLocaleString("en")}</td>
                  <td>
                    <div className="hint">{item.category ?? "other"} (heuristic)</div>
                    <code className="untrusted string-value">{item.category === "path_like" && !showPaths ? "Path-like text hidden; use the privacy control to reveal it." : item.value}</code>
                    {item.value_truncated && (
                      <div className="hint">
                        first 256 of {item.length_chars.toLocaleString("en")} characters shown
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>)}
          </table>
        </div>
      )}
      <div className="actions">
        <button
          type="button"
          className="button button-small"
          disabled={data.offset === 0}
          onClick={() => setOffset(Math.max(0, data.offset - STRINGS_PAGE))}
        >
          Previous
        </button>
        <button
          type="button"
          className="button button-small"
          disabled={last >= data.matched}
          onClick={() => setOffset(data.offset + STRINGS_PAGE)}
        >
          Next
        </button>
      </div>
    </>
  );
}

function SectionsTable({ versionId }: { versionId: string }) {
  const sections = useQuery({ queryKey: ["sections", versionId], queryFn: () => api.sections(versionId) });
  if (sections.isPending) return <Loading label="Loading sections…" />;
  if (sections.isError) return <ErrorPanel error={sections.error} />;
  if (sections.data.sections.length === 0) return <Empty>This file declares no sections.</Empty>;
  return (
    <>
      <SectionMap sections={sections.data.sections} versionId={versionId} invocationId={sections.data.metadata_invocation_id} />
      <p className="hint">
        <strong>Entropy</strong> is a measurement in bits per byte (0–8), computed by Bytasm over
        each section's bytes in the file ({sections.data.entropy_method}). It is not a verdict: high
        values are common in compressed data and ordinary resources.
      </p>
      {/* Focusable so the table can be scrolled sideways from the keyboard. */}
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Sections table">
        <table className="table table-dense">
          <caption className="sr-only">Sections as declared in the file</caption>
          <thead>
            <tr>
              <th scope="col" className="num">#</th>
              <th scope="col">Name</th>
              <th scope="col">Type</th>
              <th scope="col" className="num">File offset</th>
              <th scope="col" className="num">Bytes in file</th>
              <th scope="col" className="num">Virtual address</th>
              <th scope="col" className="num">Declared size</th>
              <th scope="col">Flags</th>
              <th scope="col" className="num">Entropy (bits/byte)</th>
            </tr>
          </thead>
          <tbody>
            {sections.data.sections.map((section) => (
              <tr id={`section-${section.index}`} key={section.index}>
                <td className="num">{section.index}</td>
                <td>
                  <code className="untrusted">{section.name}</code>
                </td>
                <td>{section.section_type ?? "—"}</td>
                <td className="num"><code>{hex(section.file_offset)}</code></td>
                <td className="num">{section.raw_size.toLocaleString("en")}</td>
                <td className="num"><code>{section.virtual_address_hex ?? hex(section.virtual_address)}</code></td>
                <td className="num">{section.virtual_size_decimal ?? section.virtual_size.toLocaleString("en")}</td>
                <td className="flags">{section.flags.join(", ") || "—"}</td>
                <td className="num">
                  {section.entropy === null ? (
                    <span className="muted">{section.entropy_note ?? "not measured"}</span>
                  ) : (
                    section.entropy.toFixed(3)
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function NameList({ title, names, empty }: { title: string; names: string[]; empty: string }) {
  return (
    <div>
      <h3>
        {title} <span className="count">{names.length}</span>
      </h3>
      {names.length === 0 ? (
        <p className="muted">{empty}</p>
      ) : (
        <ul className="name-list">
          {names.map((name) => (
            <li key={name}>
              <code className="untrusted">{name}</code>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ImportsList({ versionId }: { versionId: string }) {
  const imports = useQuery({ queryKey: ["imports", versionId], queryFn: () => api.imports(versionId) });
  if (imports.isPending) return <Loading label="Loading imports…" />;
  if (imports.isError) return <ErrorPanel error={imports.error} />;
  return (
    <div className="grid-2">
      <NameList title="Linked libraries" names={imports.data.libraries} empty="None declared." />
      <NameList title="Imported functions" names={imports.data.functions} empty="None declared." />
    </div>
  );
}

function ExportsList({ versionId }: { versionId: string }) {
  const exports = useQuery({ queryKey: ["exports", versionId], queryFn: () => api.exports(versionId) });
  if (exports.isPending) return <Loading label="Loading exports…" />;
  if (exports.isError) return <ErrorPanel error={exports.error} />;
  return (
    <NameList title="Exported functions" names={exports.data.functions} empty="None declared." />
  );
}
