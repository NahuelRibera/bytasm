import { ApiError, queryString, type Problem, type ReportCreated } from "./api";

export type Category = "metadata" | "sections" | "imports" | "exports" | "strings" | "findings" | "evidence";
export const CATEGORIES: Category[] = ["metadata", "sections", "imports", "exports", "strings", "findings", "evidence"];
export interface ComparisonSide {
  version_id: string;
  sample_id: string;
  project_id: string;
  sha256: string;
  run_id: string | null;
  run_status: string | null;
}
export interface Change {
  key: string;
  change: "added" | "removed" | "changed";
  before_ref?: { run_id: string; finding_id?: string | null; evidence_id?: number | null } | null;
  after_ref?: { run_id: string; finding_id?: string | null; evidence_id?: number | null } | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}
export interface CategoryDiff {
  status: "comparable" | "unavailable" | "incompatible";
  reason: string | null;
  a_status: string;
  b_status: string;
  added: number;
  removed: number;
  changed: number;
  total_rows: number;
  rows: Change[];
  next_offset: number | null;
}
export interface Comparison {
  a: ComparisonSide;
  b: ComparisonSide;
  identical_content: boolean;
  warnings: string[];
  categories: Record<string, CategoryDiff>;
}
async function response<T>(result: Response): Promise<T> {
  if (!result.ok) throw new ApiError(await result.json() as Problem);
  return result.json() as Promise<T>;
}
export const compareApi = {
  compare: (a: string, b: string, _category: Category, offset = 0) =>
    fetch(`/api/v1/compare${queryString({ a, b, offset, limit: 50 })}`)
      .then(response<Comparison>),
  report: (a: string, b: string) =>
    fetch(`/api/v1/sample-versions/${encodeURIComponent(b)}/reports${queryString({ compare_with: a })}`,
      { method: "POST", headers: { "X-Bytasm-Request": "1" } }).then(response<ReportCreated>),
};
