import type { Review } from "./api";

export function ReviewPanel({ review, snapshot = false }: { review: Review; snapshot?: boolean }) {
  return <section className="card review-panel" aria-label="Evidence-led explanations">
    <h2>Why these observations appear</h2>
    <p>Scope: version <code>{review.version_id}</code>, run <code>{review.run_id ?? "not selected"}</code>. Reviewed templates {review.template_version}.</p>
    <p className="hint">These automatic explanations are cautious hypotheses, separate from analyst-authored conclusions. A static match does not show executed behavior.</p>
    {review.selection_explanation && <p>{review.selection_explanation}</p>}
    <p>{review.observations.length} of {review.total} observations shown.{review.capped && " This overview is capped; all findings remain in the technical details."}</p>
    {review.total === 0 && <p>No rule observations are available here. Check which steps completed; missing data is not a no-match result.</p>}
    {review.observations.map(item => <article className="review-observation" id={`review-${item.key}`} key={item.key}>
      <h3>{item.title ?? item.rule_id}</h3><p>{item.statement}</p><p><strong>Possible interpretation:</strong> {item.hypothesis}</p>
      {item.title && <details><summary>Technical rule identifier</summary><code>{item.rule_id}</code></details>}
      {!snapshot && <a href={item.source_href}>Inspect exact finding and evidence</a>}
      <dl className="diff-values"><dt>Tool / adapter versions</dt><dd>{item.tool} {item.tool_version} / {item.adapter_version}</dd><dt>Rule version / SHA-256</dt><dd>{item.rule_version} / <code>{item.rule_sha256}</code></dd></dl>
      <ul>{item.locations.map((location, i) => <li key={i}>{location}<span className="hint"> · original JSON pointer <code>{item.pointers[i]}</code></span></li>)}</ul>
      {item.evidence_capped && <p className="notice">Evidence display is capped or truncated. Inspect the full finding and original output.</p>}
    </article>)}
    <details><summary>Short glossary</summary><dl className="diff-values">{Object.entries(review.glossary).map(([term, meaning]) => <div key={term}><dt>{term}</dt><dd>{meaning}</dd></div>)}</dl></details>
  </section>;
}
