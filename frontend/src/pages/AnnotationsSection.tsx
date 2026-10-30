import { useState } from "react";
import { AnnotationsPanel } from "./AnnotationsPanel";
import type { AnnotationTarget } from "../annotations-api";

/** Keep the larger editor out of metadata/evidence inspection until requested. */
export function AnnotationsSection({ versionId, targetType = "sample_version", targetId = versionId }: {
  versionId: string; targetType?: AnnotationTarget; targetId?: string;
}) {
  const [open, setOpen] = useState(() => new URLSearchParams(window.location.search).has("annotations") &&
    (targetType === "sample_version" || window.location.hash === `#${targetType}-${targetId}`));
  return <div className="annotation-entry">
    <button className="button" type="button" aria-expanded={open} onClick={() => setOpen(!open)}>
      {open ? "Hide analyst annotations" : "Add note / View annotations"}
    </button>
    {open && <AnnotationsPanel versionId={versionId} targetType={targetType} targetId={targetId} />}
  </div>;
}
