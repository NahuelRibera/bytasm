// A small dithered violet moon with a broken ring, for empty scenes (decoration only).
// Same light as the Journey masthead moon so the family reads as one sky.
import { useId } from "react";

export function DitherMoon({ className, ring = true }: { className?: string; ring?: boolean }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg className={["dither-moon atmo", className].filter(Boolean).join(" ")} viewBox="0 0 120 120" aria-hidden="true" focusable="false">
      <defs>
        <radialGradient id={`${id}-fill`} cx="38%" cy="34%" r="70%">
          <stop offset="0" stopColor="#f3ecfb" />
          <stop offset="0.3" stopColor="#c8b4e8" />
          <stop offset="0.68" stopColor="#8a5fd0" />
          <stop offset="1" stopColor="#3a1a72" />
        </radialGradient>
        <radialGradient id={`${id}-glow`}>
          <stop offset="0" stopColor="#a454fc" stopOpacity="0.35" />
          <stop offset="1" stopColor="#7e22e0" stopOpacity="0" />
        </radialGradient>
        <radialGradient id={`${id}-shade`} cx="72%" cy="70%" r="75%">
          <stop offset="0" stopColor="#fff" />
          <stop offset="0.55" stopColor="#fff" stopOpacity="0.55" />
          <stop offset="1" stopColor="#fff" stopOpacity="0" />
        </radialGradient>
        <mask id={`${id}-mask`}>
          <circle cx="60" cy="60" r="26" fill={`url(#${id}-shade)`} />
        </mask>
        <pattern id={`${id}-dots`} width="2.4" height="2.4" patternUnits="userSpaceOnUse">
          <circle cx="1.2" cy="1.2" r="0.72" fill="#120a22" />
        </pattern>
      </defs>
      <circle cx="60" cy="60" r="58" fill={`url(#${id}-glow)`} />
      {ring && (
        <g fill="none" stroke="#bc85ff">
          <circle cx="60" cy="60" r="36" strokeWidth="0.6" strokeOpacity="0.45" strokeDasharray="60 10 22 14 90 8" />
          <circle cx="60" cy="60" r="44" strokeWidth="3.5" strokeOpacity="0.25" strokeDasharray="0.5 4.1" />
        </g>
      )}
      <circle cx="60" cy="60" r="26" fill={`url(#${id}-fill)`} />
      <g fill="#4a2a86" fillOpacity="0.28">
        <ellipse cx="52" cy="54" rx="5" ry="3.5" />
        <ellipse cx="66" cy="68" rx="6" ry="4" />
      </g>
      <rect x="34" y="34" width="52" height="52" fill={`url(#${id}-dots)`} mask={`url(#${id}-mask)`} />
    </svg>
  );
}
