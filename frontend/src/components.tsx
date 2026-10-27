// Shared presentational components. Every value derived from a file (names,
// strings, hashes) is rendered as a React text child, so React escapes it.
import { useState, type ReactNode } from "react";
import { ApiError, type Health } from "./api";

export function hex(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `0x${value.toString(16)}`;
}

export function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  const kib = size / 1024;
  if (kib < 1024) return `${kib.toFixed(1)} KiB (${size.toLocaleString("en")} B)`;
  return `${(kib / 1024).toFixed(1)} MiB (${size.toLocaleString("en")} B)`;
}

export function formatDate(iso: string): string {
  return iso.replace("T", " ").replace("Z", " UTC");
}

export function shortHash(sha256: string): string {
  return `${sha256.slice(0, 12)}…`;
}

export const ADMITTED_LABELS: Record<string, string> = {
  fixture_manifest: "Fixture manifest",
  self_built_optin: "Self-built (operator attestation)",
};

export function AdmittedPill({ value }: { value: string }) {
  const tone = value === "self_built_optin" ? "warn" : "ok";
  return (
    <span className={`pill pill-${tone}`}>
      <span className="pill-dot" aria-hidden="true" />
      {ADMITTED_LABELS[value] ?? value}
    </span>
  );
}

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  return (
    <button type="button" className="button button-small" onClick={copy} aria-label={label}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function KeyValues({ items }: { items: Array<[ReactNode, ReactNode]> }) {
  return (
    <dl className="kv">
      {items.map(([key, value], index) => (
        <div className="kv-row" key={index}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Declared() {
  return (
    <span className="hint" title="Declared by the file itself. Bytasm does not verify it.">
      declared in file
    </span>
  );
}

export function ErrorPanel({ error, title }: { error: unknown; title?: string }) {
  const problem = error instanceof ApiError ? error.problem : null;
  return (
    <div className="error" role="alert">
      <p className="error-title">{title ?? problem?.title ?? "Something went wrong"}</p>
      <p>
        {problem?.detail ??
          "Bytasm could not reach its local API. Check that the server is still running " +
            "(make serve or make compose-up), then reload this page."}
      </p>
      {problem && (
        <details>
          <summary>Technical details</summary>
          <KeyValues
            items={[
              ["Code", <code>{problem.code}</code>],
              ["HTTP status", problem.status],
              ["Request ID", <code>{problem.request_id ?? "—"}</code>],
            ]}
          />
        </details>
      )}
    </div>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="skeleton" aria-hidden="true" />
      <span className="skeleton" aria-hidden="true" />
      <span className="sr-only">{label}</span>
      <span className="loading-label">{label}</span>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function SelfBuiltBanner({ health }: { health: Health | undefined }) {
  if (!health?.input_policy.self_built_enabled) return null;
  return (
    <div className="banner banner-warn" role="note">
      <strong>self_built mode is on</strong> (local server configuration). Bytasm also accepts
      binaries you say you compiled from source you wrote. It cannot verify that, and it is not a
      sandbox. Never import downloaded, received, third-party, or suspicious files.
    </div>
  );
}
