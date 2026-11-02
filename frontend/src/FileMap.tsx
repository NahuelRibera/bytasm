// File map (M2 instrument): the stored file as one horizontal track, with the sections' raw byte
// ranges as declared in the file and, optionally, the byte ranges where rules matched. Positions
// are file offsets only; nothing here says anything about memory layout or execution. The tables
// next to the map stay the exact, keyboard-accessible record.
import type { Section } from "./api";
import { hex } from "./components";

export interface MapMark {
  key: string;
  offset: number;
  length: number;
  group: string;
  label: string;
}

const MAX_MARKS = 400;
const VIEW_W = 1000;

function sectionAt(sections: Section[], offset: number): Section | undefined {
  return sections.find((section) => section.raw_size > 0 && offset >= section.file_offset && offset < section.file_offset + section.raw_size);
}

export function FileMap({
  size,
  sections,
  marks = [],
  selectedGroup,
  onSelect,
  title,
}: {
  size: number;
  sections: Section[];
  marks?: MapMark[];
  selectedGroup?: string | null;
  onSelect?: (group: string) => void;
  title: string;
}) {
  if (!Number.isSafeInteger(size) || size <= 0) return null;
  const scale = (offset: number) => Math.min(VIEW_W, Math.max(0, (offset / size) * VIEW_W));
  const placed = sections
    .filter((section) => section.raw_size > 0 && section.file_offset >= 0 && section.file_offset < size)
    .sort((a, b) => a.file_offset - b.file_offset);
  const shown = marks.filter((mark) => mark.offset >= 0 && mark.offset < size).slice(0, MAX_MARKS);
  const inside = shown.filter((mark) => sectionAt(placed, mark.offset)).length;
  // Union of the declared ranges, so overlapping sections are not counted twice.
  let covered = 0;
  let reach = 0;
  for (const section of placed) {
    const start = Math.max(section.file_offset, reach);
    const end = Math.min(size, section.file_offset + section.raw_size);
    if (end > start) covered += end - start;
    reach = Math.max(reach, end);
  }
  const summary =
    `${title}. File of ${size.toLocaleString("en")} bytes; ${placed.length} section${placed.length === 1 ? "" : "s"} with raw data` +
    (marks.length ? `; ${shown.length} matched byte range${shown.length === 1 ? "" : "s"}, ${inside} inside a section.` : ".");

  return (
    <figure className="file-map">
      <figcaption className="file-map-head">
        <span className="file-map-title">{title}</span>
        <span className="hint">
          0 → {hex(size)} · file offsets · sections as declared, overlaps not resolved
          {marks.length > MAX_MARKS && ` · first ${MAX_MARKS} of ${marks.length} ranges drawn`}
        </span>
      </figcaption>
      <svg className="file-map-svg" viewBox={`0 0 ${VIEW_W} 74`} preserveAspectRatio="none" role="img" aria-label={summary}>
        <rect className="file-map-track" x="0" y="18" width={VIEW_W} height="34" />
        {placed.map((section, index) => {
          const x = scale(section.file_offset);
          const w = Math.max(1.5, scale(section.file_offset + section.raw_size) - x);
          return (
            <g key={section.index} className={`file-map-section tone-${index % 4}`}>
              <rect x={x} y="18" width={w} height="34">
                <title>{`${section.name || "Unnamed section"}: ${hex(section.file_offset)}–${hex(section.file_offset + section.raw_size)} (${section.raw_size.toLocaleString("en")} B)`}</title>
              </rect>
            </g>
          );
        })}
        {shown.map((mark) => {
          const x = scale(mark.offset);
          const selected = selectedGroup === mark.group;
          return (
            <g
              key={mark.key}
              className={`file-map-mark${selected ? " is-selected" : ""}${onSelect ? " is-interactive" : ""}`}
              onClick={onSelect ? () => onSelect(mark.group) : undefined}
            >
              <line x1={x} x2={x} y1={selected ? 4 : 10} y2="58" />
              <rect x={x - 4} y="0" width="8" height="74" fill="transparent" />
              <title>{`${mark.label} at ${hex(mark.offset)} (${mark.length.toLocaleString("en")} B)`}</title>
            </g>
          );
        })}
      </svg>
      <ol className="file-map-legend" aria-label="Sections on the map">
        {placed.slice(0, 16).map((section, index) => (
          <li key={section.index} className={`tone-${index % 4}`}>
            <span className="file-map-swatch" aria-hidden="true" />
            <code className="untrusted">{section.name || "Unnamed"}</code>
            <span className="hint">{hex(section.file_offset)}</span>
          </li>
        ))}
        {placed.length > 16 && <li className="hint">+{placed.length - 16} more in the sections table</li>}
        <li className="file-map-gap-key">
          <span className="file-map-swatch" aria-hidden="true" />
          <span className="hint">outside every section ({(size - covered).toLocaleString("en")} B)</span>
        </li>
        {marks.length > 0 && (
          <li className="file-map-mark-key">
            <span className="file-map-swatch" aria-hidden="true" />
            <span className="hint">matched byte range</span>
          </li>
        )}
      </ol>
    </figure>
  );
}
