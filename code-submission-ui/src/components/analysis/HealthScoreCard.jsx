import React from 'react';
import { AlertOctagon, Calculator, Info, ShieldAlert } from 'lucide-react';
import { healthScoreBar, healthScoreTone } from './common';

/**
 * M3 code health score.
 *
 * The number, label, penalty breakdown, duplicate grouping and the
 * PARTIAL/FAILED withholding decision all come from the backend
 * (`m3/health.py`, surfaced as `run.health`). This component performs no
 * scoring of its own — it would otherwise be able to disagree with the API,
 * the PR summary and the exported report.
 *
 * Contract (server.py -> m3.service.run_payload):
 *   health: {
 *     available, score|null, label|null, reason|null, explanation?,
 *     formula, weights, components: [{ severity, count, weight_each, deduction }],
 *     penalty, capped, duplicates_ignored, duplicate_details,
 *     scored_finding_count, caveat
 *   }
 */

const LABEL_STYLES = {
  excellent: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/40',
  good: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/40',
  fair: 'bg-amber-500/10 text-amber-300 border-amber-500/40',
  poor: 'bg-orange-500/10 text-orange-300 border-orange-500/40',
  critical: 'bg-rose-500/10 text-rose-300 border-rose-500/40',
};

export function HealthScoreCard({ health, runStatus }) {
  if (!health) return null;

  const available = health.available === true && typeof health.score === 'number';
  const components = Array.isArray(health.components) ? health.components : [];
  const active = components.filter((c) => c.count > 0);

  return (
    <section
      aria-label="Code health score"
      className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" /> Code Health Score
        </span>
        <div className="flex items-center gap-2">
          {available && health.label && (
            <span
              className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${
                LABEL_STYLES[health.label] || LABEL_STYLES.fair
              }`}
            >
              {health.label}
            </span>
          )}
          <span
            className={`text-2xl font-bold font-mono ${
              available ? healthScoreTone(health.score) : 'text-amber-300'
            }`}
          >
            {available ? `${health.score}/100` : 'withheld'}
          </span>
        </div>
      </div>

      {available ? (
        <>
          <div
            className="h-2 rounded-full bg-slate-800 overflow-hidden"
            role="meter"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={health.score}
            aria-label="Code health score"
          >
            <div
              className={`h-full rounded-full ${healthScoreBar(health.score)}`}
              style={{ width: `${Math.max(0, Math.min(100, health.score))}%` }}
            />
          </div>

          {health.explanation && (
            <p className="text-[11px] text-slate-300">{health.explanation}</p>
          )}

          {active.length > 0 && (
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 space-y-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                <Calculator className="w-3 h-3" /> Deduction breakdown (de-duplicated)
              </span>
              <ul className="space-y-1">
                {active.map((c) => (
                  <li key={c.severity} className="flex items-baseline justify-between gap-3 text-[11px]">
                    <span className="text-slate-400 capitalize">
                      {c.count} × {c.severity}{' '}
                      <span className="text-slate-600">({c.weight_each} each)</span>
                    </span>
                    <span className="font-mono text-rose-300">−{c.deduction}</span>
                  </li>
                ))}
                <li className="flex items-baseline justify-between gap-3 pt-1 border-t border-slate-800 text-[11px]">
                  <span className="text-slate-400">
                    Penalty{health.capped ? ' (capped at 100)' : ''}
                  </span>
                  <span className="font-mono text-rose-300">−{Math.min(100, health.penalty ?? 0)}</span>
                </li>
              </ul>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-slate-500">
            <span>
              {health.scored_finding_count} scored finding
              {health.scored_finding_count === 1 ? '' : 's'}
            </span>
            {health.duplicates_ignored > 0 && (
              <span>
                {health.duplicates_ignored} duplicate report
                {health.duplicates_ignored === 1 ? '' : 's'} grouped (same rule family + location)
              </span>
            )}
            <span className="font-mono text-slate-600">{health.formula}</span>
          </div>

          {Array.isArray(health.duplicate_details) && health.duplicate_details.length > 0 && (
            <details className="text-[11px] text-slate-400">
              <summary className="cursor-pointer text-slate-500 hover:text-slate-300">
                Grouped duplicates ({health.duplicate_details.length})
              </summary>
              <ul className="mt-1.5 space-y-1">
                {health.duplicate_details.map((d, i) => (
                  <li key={`${d.rule_id}-${d.line_start}-${i}`} className="font-mono">
                    {d.rule_id} duplicates {d.duplicate_of} at {d.file_path || '—'}:{d.line_start ?? '?'}
                  </li>
                ))}
              </ul>
            </details>
          )}

          {health.caveat && (
            <p className="text-[10px] text-slate-500 flex items-start gap-1.5">
              <Info className="w-3 h-3 mt-0.5 shrink-0" /> {health.caveat}
            </p>
          )}
        </>
      ) : (
        <div className="rounded-lg border border-amber-500/40 bg-amber-950/30 p-3 space-y-1.5">
          <div className="flex items-center gap-1.5 text-xs font-bold text-amber-200">
            <AlertOctagon className="w-4 h-4 shrink-0" />
            Score withheld for this {runStatus || health.reason ? 'run' : 'analysis'}
          </div>
          <p className="text-[11px] text-amber-200/90">
            {health.reason ||
              'The analysis did not complete, so a score would be computed from an incomplete set of findings.'}
          </p>
          <p className="text-[10px] text-amber-200/70">
            Findings below are real, but the absence of a finding is not evidence that the issue is
            absent. Re-run once the reported agent failure is resolved.
          </p>
        </div>
      )}
    </section>
  );
}

export default HealthScoreCard;
