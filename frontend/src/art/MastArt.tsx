// Secondary masthead art (M2.1): a family of right-side compositions that fade toward the copy.
// Kinds: a character on a backlit ground (figure), engraved gothic architecture (arcade, twin
// lights, niche), and an astrolabe instrument for dense workstations. Original artwork composed
// here from arches and rings; nothing is traced. Decorative only: aria-hidden, no data, hidden
// when atmosphere is reduced. Characters are never placed beside errors or sample verdicts.
import type { ReactNode } from "react";
import { BinaryArt } from "./BinaryArt";
import { BinaryField } from "./binaryField";
import type { CharacterName } from "./characters";

const n = (value: number) => Math.round(value * 10) / 10;

/** An equilateral pointed arch from x0 to x1 springing at y (the gothic two-centred arch). */
function arch(x0: number, x1: number, spring: number): string {
  const w = x1 - x0;
  const apex = spring - (w * Math.sqrt(3)) / 2;
  return `M${n(x0)} ${n(spring)}A${n(w)} ${n(w)} 0 0 1 ${n(x0 + w / 2)} ${n(apex)}A${n(w)} ${n(w)} 0 0 1 ${n(x1)} ${n(spring)}`;
}

/** A lancet light: a pointed opening with straight jambs down to the sill. */
function lancet(x0: number, x1: number, spring: number, sill: number): string {
  return `${arch(x0, x1, spring)}V${n(sill)}H${n(x0)}Z`;
}

function Defs({ id }: { id: string }) {
  return (
    <defs>
      <pattern id={`${id}-hatch`} width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(-40)">
        <path d="M0 2H4" stroke="#efebe4" strokeWidth="0.5" strokeOpacity="0.16" />
      </pattern>
      <pattern id={`${id}-hatch-b`} width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(40)">
        <path d="M0 2H4" stroke="#efebe4" strokeWidth="0.5" strokeOpacity="0.12" />
      </pattern>
      <linearGradient id={`${id}-stone`} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stopColor="#2a2436" />
        <stop offset="1" stopColor="#0c0a12" />
      </linearGradient>
      <radialGradient id={`${id}-glow`} cx="50%" cy="55%" r="55%">
        <stop offset="0" stopColor="#8a6cc0" stopOpacity="0.32" />
        <stop offset="1" stopColor="#8a6cc0" stopOpacity="0" />
      </radialGradient>
    </defs>
  );
}

/** A ruined arcade of three pointed bays, the last one broken off. */
export function Arcade() {
  const id = "ma-arcade";
  const bays = [
    [70, 170],
    [190, 290],
    [310, 410],
  ] as const;
  return (
    <svg className="mast-ornament ornament-arcade" viewBox="0 -26 440 266" preserveAspectRatio="xMaxYMax meet" focusable="false">
      <Defs id={id} />
      <ellipse cx="250" cy="150" rx="200" ry="110" fill={`url(#${id}-glow)`} />
      {/* Piers with hatched stone, then the arches with a double engraved line. */}
      {[50, 170, 290, 410].map((x, index) => (
        <g key={x}>
          <rect x={x} y={index === 3 ? 150 : 104} width="20" height={index === 3 ? 90 : 136} fill={`url(#${id}-stone)`} />
          <rect x={x} y={index === 3 ? 150 : 104} width="20" height={index === 3 ? 90 : 136} fill={`url(#${id}-hatch)`} />
          <path d={`M${x - 3} ${index === 3 ? 150 : 104}h26v6h-26z`} className="orn-line" fill="#1c1826" />
        </g>
      ))}
      {bays.map(([x0, x1], index) => (
        <g key={x0} className={index === 2 ? "orn-broken" : undefined}>
          <path d={arch(x0 - 20, x1 + 20, 104)} className="orn-line orn-strong" fill="none" />
          <path d={arch(x0 - 12, x1 + 12, 104)} className="orn-line" fill="none" />
          {/* Tracery: two sub-arches and an oculus. */}
          <path d={arch(x0, x0 + 50, 128)} className="orn-line orn-faint" fill="none" />
          <path d={arch(x0 + 50, x1, 128)} className="orn-line orn-faint" fill="none" />
          <circle cx={(x0 + x1) / 2} cy="76" r="13" className="orn-line orn-faint" fill="none" />
          <path d={`M${(x0 + x1) / 2} 128V240`} className="orn-line orn-faint" />
        </g>
      ))}
      {/* The broken bay: masonry fallen from the last arch, a jagged top and rubble. */}
      <path d="M392 104l8-14 6 9 9-20 7 13 6-6 4 30z" fill="#0b0910" />
      <path d="M300 232l10-8 14 3 8-6 16 5 10-4 18 6 12-3 14 7H300z" fill="#14111b" />
      <path d="M0 239.5H440" className="orn-line" />
    </svg>
  );
}

/** A two-light gothic window: twin lancets under one arch with an oculus (for comparisons). */
export function TwinLights() {
  const id = "ma-twin";
  return (
    <svg className="mast-ornament ornament-twin" viewBox="0 -66 360 326" preserveAspectRatio="xMaxYMax meet" focusable="false">
      <Defs id={id} />
      <ellipse cx="200" cy="150" rx="170" ry="120" fill={`url(#${id}-glow)`} />
      <path d={lancet(80, 320, 150, 260)} fill={`url(#${id}-stone)`} />
      <path d={arch(80, 320, 150)} className="orn-line orn-strong" fill="none" />
      <path d={arch(92, 308, 150)} className="orn-line" fill="none" />
      {/* Left light hatched one way, right light the other: two states of one opening. */}
      <path d={lancet(110, 190, 170, 260)} fill="#07060b" />
      <path d={lancet(110, 190, 170, 260)} fill={`url(#${id}-hatch)`} />
      <path d={lancet(210, 290, 170, 260)} fill="#07060b" />
      <path d={lancet(210, 290, 170, 260)} fill={`url(#${id}-hatch-b)`} />
      <path d={lancet(110, 190, 170, 260)} className="orn-line" fill="none" />
      <path d={lancet(210, 290, 170, 260)} className="orn-line" fill="none" />
      <circle cx="200" cy="96" r="22" fill="#07060b" />
      <circle cx="200" cy="96" r="22" className="orn-line orn-strong" fill="none" />
      <circle cx="200" cy="96" r="15" className="orn-line orn-faint" fill="none" />
      {[0, 60, 120, 180, 240, 300].map((angle) => (
        <path key={angle} d="M200 81V74" className="orn-line orn-faint" transform={`rotate(${angle} 200 96)`} />
      ))}
      <path d="M200 150V260" className="orn-line orn-strong" />
      <path d="M0 259.5H360" className="orn-line" />
    </svg>
  );
}

/** A pointed niche: the frame a figure stands in (archive, codex). */
export function Niche() {
  const id = "ma-niche";
  return (
    <svg className="mast-ornament ornament-niche" viewBox="0 -84 300 344" preserveAspectRatio="xMaxYMax meet" focusable="false">
      <Defs id={id} />
      <path d={lancet(50, 250, 120, 260)} fill="#09080d" />
      <path d={arch(36, 264, 120)} className="orn-line orn-strong" fill="none" />
      <path d={arch(50, 250, 120)} className="orn-line" fill="none" />
      <path d="M36 120V260M264 120V260" className="orn-line orn-strong" />
      <path d="M50 120V260M250 120V260" className="orn-line" />
      <rect x="18" y="120" width="18" height="140" fill={`url(#${id}-hatch)`} />
      <rect x="264" y="120" width="18" height="140" fill={`url(#${id}-hatch)`} />
      {/* Ruled lines of a codex page on the jambs: decoration, not text. */}
      {[150, 162, 174, 186, 198, 210, 222].map((y) => (
        <path key={y} d={`M22 ${y}h10M268 ${y}h10`} className="orn-line orn-faint" />
      ))}
      <path d="M0 259.5H300" className="orn-line" />
    </svg>
  );
}

/** An astrolabe edge for dense workstations: rings, a tick ring and an alidade, cut by the border. */
export function Astrolabe() {
  const ticks = Array.from({ length: 72 }, (_, index) => index * 5);
  return (
    <svg className="mast-ornament ornament-astrolabe" viewBox="0 0 280 280" preserveAspectRatio="xMaxYMid meet" focusable="false">
      <g className="orn-astro" fill="none">
        <circle cx="200" cy="140" r="128" className="orn-line" />
        <circle cx="200" cy="140" r="118" className="orn-line orn-faint" strokeDasharray="90 12 30 18" />
        {ticks.map((angle) => (
          <path key={angle} d={`M200 ${angle % 30 === 0 ? 22 : 16}V12`} className={angle % 30 === 0 ? "orn-line orn-strong" : "orn-line orn-faint"} transform={`rotate(${angle} 200 140)`} />
        ))}
        <circle cx="200" cy="140" r="84" className="orn-line orn-faint" />
        <circle cx="200" cy="140" r="52" className="orn-line" strokeDasharray="4 6" />
        <ellipse cx="200" cy="140" rx="84" ry="34" className="orn-line orn-faint" transform="rotate(-24 200 140)" />
        <path d="M200 140L96 62" className="orn-line orn-strong" />
        <path d="M200 140L300 216" className="orn-line" />
        <circle cx="200" cy="140" r="4" className="orn-line orn-strong" />
        <path d="M110 66l5-5 5 5-5 5z" className="orn-line orn-strong" />
      </g>
    </svg>
  );
}

/** Distant ruins on a horizon: a broken tower and a fallen arch (for the project workspace). */
export function Ruins() {
  const id = "ma-ruins";
  return (
    <svg className="mast-ornament ornament-ruins" viewBox="0 0 520 200" preserveAspectRatio="xMaxYMax meet" focusable="false">
      <Defs id={id} />
      <ellipse cx="260" cy="170" rx="260" ry="60" fill={`url(#${id}-glow)`} />
      <path d="M0 200V178L60 172L120 176L170 166L230 170L300 160L360 168L420 158L470 164L520 160V200Z" fill="#0d0b13" />
      {/* Broken tower with a lancet and a jagged crown. */}
      <path d="M96 176V92l6-6 4 8 6-12 5 10 4-4V176Z" fill="#14111c" />
      <path d="M96 176V92l6-6 4 8 6-12 5 10 4-4V176Z" fill={`url(#${id}-hatch)`} />
      <path d={lancet(103, 114, 128, 150)} fill="#07060b" />
      {/* A fallen arch: one pier and half an arch left standing. */}
      <path d="M176 168V124h10V168Z" fill="#14111c" />
      <path d={arch(181, 241, 124)} className="orn-line" fill="none" strokeDasharray="62 400" />
      <path d="M232 166V146h9V166Z" fill="#14111c" />
      <path d="M0 199.5H520" className="orn-line" />
    </svg>
  );
}

export type MastSceneKind = "figure" | "architecture" | "instrument";

/**
 * The art layer of a PageMast: optional binary field, an ornament, and optionally one character.
 * `character` frames are tuned per figure in CSS (.figure-<name>), because the engravings have
 * different tonal weight: one opacity cannot serve every character.
 */
export function MastScene({
  kind,
  character,
  ornament,
  field = kind !== "figure",
}: {
  kind: MastSceneKind;
  character?: CharacterName;
  ornament?: ReactNode;
  field?: boolean;
}) {
  return (
    <div className={`mast-scene mast-scene-${kind} atmo`} aria-hidden="true">
      {field && <BinaryField className="mast-field" light={{ x: 0.82, y: 0.4, radius: 0.1 }} clearLeft={0.5} fadeBottom={0.35} density={0.42} />}
      <span className="mast-backlight" />
      {ornament}
      {character && <BinaryArt character={character} tint="bone" className={`mast-figure figure-${character}`} />}
    </div>
  );
}
