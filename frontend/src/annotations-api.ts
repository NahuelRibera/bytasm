import { ApiError, queryString, type Problem } from "./api";

export type AnnotationTarget = "sample_version" | "finding" | "evidence";

export type AnnotationKind = "note" | "interpretation" | "conclusion";

export type Confidence = "tentative" | "likely" | "well-supported" | null;

export interface Citation {
  target_type: "finding" | "evidence";
  target_id: string;
}

export interface CitationTarget extends Citation {
  run_id: string;
  version_id: string;
  label: string;
}

export interface AnnotationDraft {
  kind: AnnotationKind;
  body: string;
  confidence: Confidence;
  cites: Citation[];
}

export interface Annotation extends AnnotationDraft {
  id: string;
  revision_id: string;
  revision: number;
  target_type: AnnotationTarget;
  target_id: string;
  version_id: string;
  author: {
    id: string;
    display_name: string;
  };
  created_at: string;
  cites: CitationTarget[];
}

export interface Page<T> {
  items: T[];
  next_offset: number | null;
}

async function request<T>(path: string, body?: unknown): Promise<T> {
  const init: RequestInit = body === undefined
    ? { headers: { Accept: "application/json" } }
    : {
        method: "POST",
        headers: { "X-Bytasm-Request": "1", "Content-Type": "application/json" },
        body: JSON.stringify(body),
      };
  const response = await fetch(`/api/v1${path}`, init);
  if (!response.ok) {
    let problem: Problem;
    try {
      problem = await response.json() as Problem;
    } catch {
      problem = {
        type: "about:blank",
        code: "http_error",
        status: response.status,
        title: "Request failed",
        detail: "The server returned an unexpected response.",
      };
    }
    throw new ApiError(problem);
  }
  return await response.json() as T;
}

export const annotationsApi = {
  list: (type: AnnotationTarget, id: string, offset = 0) =>
    request<Page<Annotation>>(
      `/annotations${queryString({ target_type: type, target_id: id, offset, limit: 25 })}`,
    ),
  history: (id: string, offset = 0) =>
    request<Page<Annotation>>(
      `/annotations/${encodeURIComponent(id)}/revisions${queryString({ offset, limit: 25 })}`,
    ),
  targets: (version: string, offset = 0) =>
    request<Page<CitationTarget>>(
      `/sample-versions/${encodeURIComponent(version)}/citation-targets${queryString({ offset, limit: 100 })}`,
    ),
  create: (
    target_type: AnnotationTarget,
    target_id: string,
    draft: AnnotationDraft,
    request_id?: string,
  ) => request<Annotation>("/annotations", { target_type, target_id, ...draft, request_id }),
  revise: (id: string, expected_revision: number, draft: AnnotationDraft) =>
    request<Annotation>(`/annotations/${encodeURIComponent(id)}/revisions`, {
      expected_revision,
      ...draft,
    }),
};
