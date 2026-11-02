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

export const WarnIcon = () => (
  <Icon>
    <path d="M12 3.5 21.5 20h-19z" />
    <path d="M12 10v4.5M12 17v.5" />
  </Icon>
);

export const InfoIcon = () => (
  <Icon>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v6M12 7.5V8" />
  </Icon>
);
