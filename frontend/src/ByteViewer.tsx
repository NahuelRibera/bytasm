import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiError } from "./api";
import { CopyButton, ErrorPanel, Loading } from "./components";

export function ByteViewer({ versionId }: { versionId: string }) {
  const [open, setOpen] = useState(false);
  const [offset, setOffset] = useState(0);
  const [input, setInput] = useState("0");
  const window = useQuery({ queryKey: ["byte-window", versionId, offset], enabled: open,
    queryFn: async () => {
      const response = await fetch(`/api/v1/sample-versions/${versionId}/bytes?offset=${offset}&length=256`);
      if (!response.ok) throw new ApiError(await response.json());
      return response.json() as Promise<{ offset: number; length: number; hex: string; printable: string; eof: boolean; size_bytes: number }>;
    } });
  const go = (next: number) => { setOffset(next); setInput(String(next)); };
  return <details className="card byte-viewer" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Inspect exact file bytes</summary><p>Offsets below are bytes from the start of this stored file, not virtual addresses. Bytes are displayed as inert hexadecimal and printable text.</p>
    <form onSubmit={event => { event.preventDefault(); const value = Number(input); if (Number.isSafeInteger(value) && value >= 0 && value <= 64 * 1024 * 1024) go(value); }}>
      <label>File offset (decimal or 0x hex) <input value={input} onChange={event => setInput(event.target.value)} pattern="(?:[0-9]+|0x[0-9a-fA-F]+)" required /></label><button className="button">Go to offset</button>
    </form>
    {window.isLoading && <Loading label="Verifying stored bytes…" />}
    {window.isError && <ErrorPanel error={window.error} title="Could not read bytes" />}
    {window.data && <><div className="table-scroll" role="region" tabIndex={0} aria-label="Hexadecimal bytes"><table className="table"><caption>256-byte window from file offset {offset}</caption><thead><tr><th>File offset</th><th>Hexadecimal</th><th>Printable text</th></tr></thead><tbody>{Array.from({ length: Math.ceil(window.data.length / 16) }, (_, index) => <tr key={index}><th scope="row">0x{(offset + index * 16).toString(16)}</th><td><code>{window.data!.hex.slice(index * 32, index * 32 + 32).match(/../g)?.join(" ")}</code></td><td><code>{window.data!.printable.slice(index * 16, index * 16 + 16)}</code></td></tr>)}</tbody></table></div>
      <CopyButton value={window.data.hex} label="Copy hexadecimal bytes (no separators)" />
      <button className="button" disabled={offset === 0} onClick={() => go(Math.max(0, offset - 256))}>Previous byte window</button><button className="button" disabled={window.data.eof} onClick={() => go(offset + window.data!.length)}>Next byte window</button>
      {window.data.eof && <p>End of file.</p>}
    </>}
  </details>;
}
