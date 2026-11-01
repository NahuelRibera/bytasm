// Hand-drawn 24-grid icons, 1.5 px stroke, square caps, currentColor (DESIGN_SYSTEM §9).
// Decorative next to visible text, so they are always aria-hidden.
import type { ReactNode } from "react";

function Icon({ children }: { children: ReactNode }) {
  return (
    <svg
      className="icon"
      viewBox="0 0 24 24"
      width="20"
      height="20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="square"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export const ProjectsIcon = () => (
  <Icon>
    <path d="M3 6h7l2 2h9v11H3z" />
    <path d="M3 10h18" />
  </Icon>
);

export const RulesIcon = () => (
  <Icon>
    <path d="M5 5h14M5 10h14M5 15h9M5 20h6" />
  </Icon>
);

export const ToolsIcon = () => (
  <Icon>
    <circle cx="12" cy="12" r="5" />
    <path d="M12 2v5M12 17v5M2 12h5M17 12h5" />
  </Icon>
);

/** The provisional brand mark: a 2 x 2 bit quadrant crossed by a fine compass line (branding D5 stays open). */
export function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
      <rect x="4" y="4" width="7" height="7" fill="currentColor" />
      <rect x="13" y="13" width="7" height="7" fill="currentColor" />
      <rect x="13.5" y="4.5" width="6" height="6" fill="none" stroke="currentColor" strokeWidth="1" />
      <rect x="4.5" y="13.5" width="6" height="6" fill="none" stroke="currentColor" strokeWidth="1" />
      <path d="M12 0v24M0 12h24" stroke="currentColor" strokeWidth="0.75" opacity="0.55" />
    </svg>
  );
}
