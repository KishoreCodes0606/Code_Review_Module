import React from 'react';
import { AlertTriangle, BookOpen, CheckCircle2, FileWarning, Lightbulb, Wrench, XCircle } from 'lucide-react';
import { SeverityBadge } from './common';

/**
 * M3 remediation rendering, driven exclusively by
 * `agents/remediation_agent.py` output (never generated in the browser).
 *
 * Per finding:
 *   { finding_id, rule_id, remediation_family, title, severity, category,
 *     problem_explanation, recommended_fix, corrected_code, original_code,
 *     best_practice, reason_for_fix, source_location, remediation_status,
 *     language, limitations, references: [{ title, section, source, url, owasp,
 *     cwe, score, excerpt }], cwe_id, owasp_category }
 *
 * remediation_status is 'suggested' (an illustrative fix exists) or
 * 'manual_review_required' (no safe deterministic fix — the agent explains why
 * instead of inventing code). Nothing is ever applied to the user's source.
 */

function CodeBlock({ code, tone = 'slate', label }) {
  return (
    <div className="min-w-0">
      <span
        className={`text-[10px] font-bold uppercase tracking-wider ${
          tone === 'bad' ? 'text-rose-300' : tone === 'good' ? 'text-emerald-300' : 'text-slate-500'
        }`}
      >
        {label}
      </span>
      <pre className="mt-1 rounded-lg bg-slate-950 border border-slate-800 p-3 overflow-x-auto text-[11px] leading-relaxed font-mono text-slate-200 whitespace-pre">
        {code}
      </pre>
    </div>
  );
}

export function RemediationStatusBadge({ status }) {
  if (status === 'suggested') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border bg-emerald-500/10 text-emerald-300 border-emerald-500/40">
        <CheckCircle2 className="w-3 h-3" /> Fix suggested
      </span>
    );
  }
  if (status === 'manual_review_required') {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border bg-amber-500/10 text-amber-300 border-amber-500/40"
        title="No safe deterministic fix exists for this finding — the agent explains the manual steps instead of inventing code"
      >
        <FileWarning className="w-3 h-3" /> Manual review
      </span>
    );
  }
  return null;
}

function References({ references }) {
  if (!Array.isArray(references) || references.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
        <BookOpen className="w-3 h-3" /> Knowledge-base references
      </span>
      <ul className="space-y-1.5">
        {references.map((ref, i) => (
          <li
            key={`${ref.source}-${ref.section}-${i}`}
            className="rounded-lg border border-slate-800 bg-slate-950/60 px-2.5 py-2 text-[11px]"
          >
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="font-semibold text-slate-200">{ref.title}</span>
              {ref.section && <span className="text-slate-500">› {ref.section}</span>}
              {ref.owasp && (
                <span className="px-1.5 py-0.5 rounded border border-slate-700 text-[9px] font-mono text-slate-400">
                  {ref.owasp}
                </span>
              )}
            </div>
            {ref.excerpt && <p className="mt-1 text-slate-400 leading-relaxed">{ref.excerpt}</p>}
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] font-mono text-slate-600">
              <span>{ref.source}</span>
              {Array.isArray(ref.cwe) && ref.cwe.length > 0 && <span>{ref.cwe.join(', ')}</span>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Per-finding remediation detail, embedded in the finding detail panel. */
export function RemediationBlock({ remedy, state, error, onRetry }) {
  if (state === 'loading') {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-[11px] text-slate-400">
        Generating remediation for this finding…
      </div>
    );
  }

  if (state === 'error') {
    return (
      <div className="rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 space-y-1.5">
        <div className="flex items-center gap-1.5 text-[11px] font-bold text-rose-200">
          <AlertTriangle className="w-3.5 h-3.5" /> Remediation could not be generated
        </div>
        <p className="text-[11px] text-rose-200/80">
          {error || 'The remediation agent failed for this run.'} The M2 findings above are unaffected —
          no remediation content is being invented here.
        </p>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="text-[11px] font-semibold px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
          >
            Retry remediation
          </button>
        )}
      </div>
    );
  }

  if (!remedy) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-[11px] text-slate-400 flex items-start gap-1.5">
        <XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0 text-slate-500" />
        No remediation entry was returned for this finding — the finding itself is still listed above.
      </div>
    );
  }

  const hasComparison = Boolean(remedy.original_code || remedy.corrected_code);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
          <Wrench className="w-3 h-3" /> Remediation
        </span>
        <RemediationStatusBadge status={remedy.remediation_status} />
        {remedy.remediation_family && (
          <span
            className="px-1.5 py-0.5 rounded border border-slate-700 text-[9px] font-mono text-slate-400"
            title={`Rule ${remedy.rule_id} is remediated with the ${remedy.remediation_family} family template`}
          >
            family: {remedy.remediation_family}
          </span>
        )}
        {remedy.severity && <SeverityBadge severity={remedy.severity} />}
      </div>

      {remedy.problem_explanation && (
        <div>
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Problem explanation
          </span>
          <p className="mt-0.5 text-xs text-slate-300 leading-relaxed">{remedy.problem_explanation}</p>
        </div>
      )}

      {remedy.recommended_fix && (
        <div>
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Recommended fix
          </span>
          <p className="mt-0.5 text-xs text-slate-200 leading-relaxed">{remedy.recommended_fix}</p>
        </div>
      )}

      {hasComparison && (
        <div className="grid grid-cols-1 gap-2">
          {remedy.original_code && (
            <CodeBlock label="Your code (unchanged)" code={remedy.original_code} tone="bad" />
          )}
          {remedy.corrected_code && (
            <CodeBlock label="Suggested pattern" code={remedy.corrected_code} tone="good" />
          )}
          <p className="text-[10px] text-slate-500">
            Illustrative comparison only — your submitted source is never modified or auto-applied.
          </p>
        </div>
      )}

      {remedy.best_practice && (
        <div>
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
            <Lightbulb className="w-3 h-3" /> Best practice
          </span>
          <p className="mt-0.5 text-xs text-slate-300 leading-relaxed">{remedy.best_practice}</p>
        </div>
      )}

      {remedy.reason_for_fix && (
        <div>
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Why this fixes it
          </span>
          <p className="mt-0.5 text-xs text-slate-300 leading-relaxed">{remedy.reason_for_fix}</p>
        </div>
      )}

      {Array.isArray(remedy.limitations) && remedy.limitations.length > 0 && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-2.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-amber-300">
            Limitations
          </span>
          <ul className="mt-1 space-y-0.5">
            {remedy.limitations.map((l, i) => (
              <li key={i} className="text-[11px] text-amber-200/90">
                • {l}
              </li>
            ))}
          </ul>
        </div>
      )}

      <References references={remedy.references} />
    </div>
  );
}

/** Run-level remediation summary: counts, mode, limitations, coverage note. */
export function RemediationOverview({ remediation }) {
  if (!remediation) return null;
  const counts = remediation.counts || {};
  return (
    <section
      aria-label="Remediation overview"
      className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2.5"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Wrench className="w-3.5 h-3.5 text-indigo-400" /> Remediation
        </span>
        <span className="text-[10px] font-mono text-slate-500">
          {remediation.mode === 'llm_assisted' ? 'LLM-assisted' : 'deterministic'} ·{' '}
          {remediation.finding_count ?? 0} finding(s)
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-3 py-2">
          <div className="text-lg font-bold font-mono text-emerald-300">{counts.suggested ?? 0}</div>
          <div className="text-[10px] text-emerald-300/70">fix suggested</div>
        </div>
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
          <div className="text-lg font-bold font-mono text-amber-300">
            {counts.manual_review_required ?? 0}
          </div>
          <div className="text-[10px] text-amber-300/70">manual review</div>
        </div>
      </div>

      {remediation.notice && <p className="text-[10px] text-slate-500">{remediation.notice}</p>}

      {Array.isArray(remediation.limitations) && remediation.limitations.length > 0 && (
        <ul className="space-y-0.5">
          {remediation.limitations.map((l, i) => (
            <li key={i} className="text-[10px] text-slate-500">
              • {l}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default RemediationBlock;
