import type { Section } from "./api";

export function sectionTotal(sections: Section[]): number | null {
  if (sections.some(section => !Number.isSafeInteger(section.raw_size) || section.raw_size < 0)) return null;
  const total = sections.reduce((sum, section) => sum + section.raw_size, 0);
  return Number.isSafeInteger(total) ? total : null;
}

export function SectionMap({ sections, versionId, invocationId }: { sections: Section[]; versionId: string; invocationId?: string | null }) {
  const total = sectionTotal(sections);
  return <figure className="section-map" aria-labelledby="section-map-title">
    <h3 id="section-map-title">Section sizes and entropy measurements</h3>
    <figcaption>Version <code>{versionId}</code> · import invocation <code>{invocationId ?? "not recorded"}</code>. Raw-size bars use the sum of declared raw section sizes ({total ?? "unavailable"} bytes), not file coverage. Overlaps are not deduplicated. Entropy uses 0–8 bits per byte, never a risk scale. The exact table below is the text alternative.</figcaption>
    {!total && <p>No nonzero raw-size denominator is available; size bars are omitted.</p>}
    {sections.length > 24 && <p>First 24 of {sections.length} sections plotted; the table contains every section.</p>}
    <ul>{sections.slice(0, 24).map(section => <li key={section.index}>
      <a href={`#section-${section.index}`} className="untrusted">{section.name || "Unnamed section"}</a>: {section.raw_size.toLocaleString("en")} raw bytes · {section.virtual_size_decimal ?? section.virtual_size.toLocaleString("en")} declared virtual bytes · permissions {section.flags.join(", ") || "not recorded"}.
      {total !== null && total > 0 && <div className="measurement-track" role="img" aria-label={`${section.name}: ${section.raw_size} of ${total} declared raw section bytes`}><span style={{ width: `${section.raw_size / total * 100}%` }} /></div>}
      <p className="hint">Entropy: {section.entropy === null ? `not measured (${section.entropy_note ?? "unavailable"})` : `${section.entropy.toFixed(3)} bits per byte, scale 0–8`}.</p>
      {section.entropy !== null && section.entropy >= 0 && section.entropy <= 8 && <div className="measurement-track" role="img" aria-label={`${section.name}: entropy ${section.entropy} bits per byte on a 0–8 scale`}><span style={{ width: `${section.entropy / 8 * 100}%` }} /></div>}
    </li>)}</ul>
  </figure>;
}
