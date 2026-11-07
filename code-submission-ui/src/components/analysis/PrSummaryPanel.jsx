import React from 'react';
import { AlertOctagon, CheckCircle2, ClipboardList, FileText, Info, MessageSquareWarning } from 'lucide-react';
import { CATEGORY_LABEL, SeverityBadge } from './common';

/**
 * M3 PR summary panel, rendered from `agents/pr_summary_agent.py` output.
 *
 * Contract (GET /api/analysis/{run_id}/summary -> { summary }):
 *   { review_status: { code: 'APPROVED'|'APPROVED_WITH_SUGGESTIONS'|
 *       'CHANGES_REQUESTED'|'INCOMPLETE_REVIEW', label, rationale },
 *     executive_overview, finding_count, severity_breakdown, severity_counts,
 *     category_counts, categorized_findings, prioritized_fixes,
 *     remediation_summary, health, final_recommendation, caveats,
 *     agent_results, consistency }
 *
 * The caveats/limitations list is always rendered: a PARTIAL or FAILED run must
 * never read like a successful review, so INCOMPLETE_REVIEW is called out.
 */

const STATUS_STYLES = {
  APPROVED: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/40',
  APPROVED_WITH_SUGGESTIONS: 'bg-sky-500/10 text-sky-300 border-sky-500/40',
  CHANGES_REQUESTED: 'bg-rose-500/10 text-rose-300 border-rose-500/40',
  INCOMPLETE_REVIEW: 'bg-amber-500/10 text-amber-300 border-amber-500/40',
};

function StatusBlock({ review, analysisStatus }) {
  if (!review) return null;
  const tone = STATUS_STYLES[review.code] || 'bg-slate-500/10 text-slate-300 border-slate-500/40';
  const Icon =
    review.code === 'APPROVED'
      ? CheckCircle2
      : review.code === 'INCOMPLETE_REVIEW'
      ? AlertOctagon
      : MessageSquareWarning;
  return (
    <div className={`rounded-lg border px-3 py-2.5 ${tone}`}>
      <div className="flex flex-wrap items-center gap-2">
        <Icon className="w-4 h-4 shrink-0" />
        <span className="text-sm font-bold">{review.label}</span>
        {analysisStatus && (
          <span className="text-[10px] font-mono opacity-70">analysis: {analysisStatus}</span>
        )}
      </div>
      {review.rationale && <p className="mt-1 text-[11px] opacity-90">{review.rationale}</p>}
    </div>
  );
}

function Section({ title, icon: Icon, children }) {
  return (
    <div className="space-y-1.5">
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
        {Icon && <Icon className="w-3 h-3" />} {title}
      </span>
      {children}
    </div>
  );
}

export function PrSummaryPanel({ summary, state, error, onRetry }) {
  if (state === 'loading') {
    return (
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <span className="text-xs text-slate-400">Generating PR summary from the real findings…</span>
      </section>
    );
  }

  if (state === 'error') {
    return (
      <section className="rounded-xl border border-rose-500/40 bg-rose-950/40 p-4 space-y-2">
        <div className="flex items-center gap-1.5 text-xs font-bold text-rose-200">
          <AlertOctagon className="w-4 h-4" /> PR summary unavailable
        </div>
        <p className="text-[11px] text-rose-200/80">
          {error || 'The PR summary agent failed for this run.'} Findings and remediation are
          unaffected — no summary text is being fabricated.
        </p>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="text-[11px] font-semibold px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
          >
            Retry summary
          </button>
        )}
      </section>
    );
  }

  if (!summary) return null;

  // The agent returns a LIST of category groups:
  // [{ category, finding_count, severity_counts, rule_ids, findings: [...] }]
  // An object map is still tolerated so a shape change cannot white-screen the app.
  const categories = Array.isArray(summary.categorized_findings)
    ? summary.categorized_findings
    : Object.entries(summary.categorized_findings || {}).map(([category, list]) => ({
        category,
        finding_count: Array.isArray(list) ? list.length : 0,
        rule_ids: [],
        findings: Array.isArray(list) ? list : [],
      }));
  const priorities = Array.isArray(summary.prioritized_fixes) ? summary.prioritized_fixes : [];
  const caveats = Array.isArray(summary.caveats) ? summary.caveats : [];
  const inconsistency =
    summary.consistency &&
    (summary.consistency.severity_total_matches_finding_count === false ||
      summary.consistency.category_total_matches_finding_count === false);

  return (
    <section
      aria-label="PR summary"
      className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <FileText className="w-3.5 h-3.5 text-indigo-400" /> PR Review Summary
        </span>
        <span className="text-[10px] font-mono text-slate-500">
          {summary.finding_count ?? 0} finding(s) · {summary.language || 'unknown'}
        </span>
      </div>

      <StatusBlock review={summary.review_status} analysisStatus={summary.analysis_status} />

      {summary.executive_overview && (
        <Section title="Executive overview">
          <p className="text-xs text-slate-300 leading-relaxed">{summary.executive_overview}</p>
        </Section>
      )}

      {Array.isArray(summary.severity_breakdown) && summary.severity_breakdown.length > 0 && (
        <Section title="Severity breakdown">
          <div className="flex flex-wrap gap-2">
            {summary.severity_breakdown.map((s) => (
              <span
                key={s.severity}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-950/60 px-2.5 py-1 text-[11px]"
              >
                <SeverityBadge severity={s.severity} />
                <span className="font-mono font-bold text-white">{s.count}</span>
                <span className="text-slate-500">({Math.round((s.share ?? 0) * 100)}%)</span>
              </span>
            ))}
          </div>
        </Section>
      )}

      {categories.length > 0 && (
        <Section title="Categorized findings" icon={ClipboardList}>
          <div className="space-y-2">
            {categories.map((group) => {
              const items = Array.isArray(group.findings) ? group.findings : [];
              const count = group.finding_count ?? items.length;
              return (
                <div
                  key={group.category}
                  className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5"
                >
                  <div className="flex items-center justify-between text-[11px] font-semibold text-slate-300">
                    <span>{CATEGORY_LABEL[group.category] || group.category}</span>
                    <span className="font-mono text-slate-500">{count}</span>
                  </div>
                  <ul className="mt-1 space-y-0.5">
                    {items.slice(0, 6).map((f, i) => (
                      <li key={`${f.id || f.rule_id}-${i}`} className="text-[11px] text-slate-400">
                        <span className="font-mono text-slate-500">{f.rule_id}</span> · {f.title}
                        {f.line_start != null && (
                          <span className="text-slate-600"> (line {f.line_start})</span>
                        )}
                      </li>
                    ))}
                    {count > items.slice(0, 6).length && (
                      <li className="text-[10px] text-slate-600">
                        +{count - items.slice(0, 6).length} more in the findings table
                      </li>
                    )}
                  </ul>
                  {Array.isArray(group.rule_ids) && group.rule_ids.length > 0 && (
                    <div className="mt-1 text-[10px] font-mono text-slate-600">
                      rules: {group.rule_ids.join(', ')}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {priorities.length > 0 && (
        <Section title="Prioritized fixes">
          <ol className="space-y-1.5">
            {priorities.slice(0, 10).map((p) => (
              <li
                key={`${p.priority}-${p.finding_id}-${p.rule_id}`}
                className="rounded-lg border border-slate-800 bg-slate-950/60 px-2.5 py-2 text-[11px]"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-bold text-indigo-300">#{p.priority}</span>
                  <SeverityBadge severity={p.severity} />
                  <span className="font-mono text-slate-500">{p.rule_id}</span>
                  {p.location?.line_start != null && (
                    <span className="font-mono text-[10px] text-slate-600">
                      {p.location.file_path || '—'}:{p.location.line_start}
                    </span>
                  )}
                  {p.remediation_available === false && (
                    <span className="text-[9px] uppercase tracking-wide text-amber-300/80">
                      manual review
                    </span>
                  )}
                </div>
                <p className="mt-1 text-slate-300">{p.title}</p>
                {p.why && <p className="mt-0.5 text-slate-400">{p.why}</p>}
                {p.action && <p className="mt-0.5 text-slate-400">{p.action}</p>}
              </li>
            ))}
          </ol>
        </Section>
      )}

      {summary.remediation_summary && (
        <Section title="Remediation summary">
          <p className="text-xs text-slate-300 leading-relaxed">
            {summary.remediation_summary.available === false
              ? summary.remediation_summary.message
              : `${summary.remediation_summary.total ?? 0} finding(s) covered · ${
                  summary.remediation_summary.suggested ?? 0
                } with illustrative fixes · ${
                  summary.remediation_summary.manual_review_required ?? 0
                } requiring manual review.`}
          </p>
        </Section>
      )}

      {summary.final_recommendation && (
        <Section title="Final recommendation">
          <p className="text-xs text-slate-200 leading-relaxed">{summary.final_recommendation}</p>
        </Section>
      )}

      {caveats.length > 0 && (
        <Section title="Limitations & caveats" icon={Info}>
          <ul className="space-y-0.5">
            {caveats.map((c, i) => (
              <li key={i} className="text-[11px] text-slate-500">
                • {c}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {inconsistency && (
        <p className="text-[11px] text-rose-300">
          Internal consistency check failed: the severity/category counts do not add up to the finding
          count. Treat this summary as unreliable and inspect the findings table directly.
        </p>
      )}
    </section>
  );
}

export default PrSummaryPanel;
