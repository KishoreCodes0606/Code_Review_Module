import React from 'react';
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Clock,
  FileSearch,
  Scale,
  ShieldAlert,
} from 'lucide-react';
import { healthScoreBar, healthScoreTone } from './common';

/**
 * Analysis summary cards rendered ONLY from real backend run-summary fields:
 * severity_counts {critical,high,medium,low,info}, finding_count, health_score,
 * status, agent_results. Unknown/extra severity keys are still shown rather
 * than dropped. No fake statistics or charts.
 */

/**
 * Detection-coverage notes derived from the real run metrics.
 * `parsed === false` means the built-in rule engine could not read the source,
 * so its detectors never ran — a degraded scan must say so instead of looking
 * like a clean one.
 */
function coverageNotes(metrics) {
  if (!metrics || typeof metrics !== 'object') return [];
  const notes = [];
  if (metrics.parsed === false) {
    notes.push({
      tone: 'bad',
      text: `The built-in rule engine could not parse this source${metrics.parse_error ? ` (${metrics.parse_error})` : ''} — every detector it provides was skipped for this run.`,
    });
  }
  const pmd = metrics.pmd_status;
  if (pmd === 'unavailable') {
    notes.push({ tone: 'warn', text: 'PMD (Java analyzer) is not installed in this environment — Java rule coverage was reduced; the built-in detectors carried the analysis.' });
  } else if (pmd === 'error') {
    notes.push({ tone: 'bad', text: 'PMD reported a processing/parse error on this source — Java violations from PMD are incomplete.' });
  } else if (pmd === 'skipped') {
    notes.push({ tone: 'warn', text: 'PMD was skipped for this run — Java rule coverage was reduced.' });
  } else if (pmd === 'ok') {
    notes.push({ tone: 'ok', text: 'PMD ran successfully on this source.' });
  }
  return notes;
}

const COVERAGE_TONE = {
  bad: 'text-rose-300',
  warn: 'text-amber-300',
  ok: 'text-emerald-300',
};
const SEVERITY_CARDS = [
  { key: 'critical', label: 'Critical', accent: 'text-rose-300', ring: 'border-rose-500/40' },
  { key: 'high', label: 'High', accent: 'text-orange-300', ring: 'border-orange-500/40' },
  { key: 'medium', label: 'Medium', accent: 'text-amber-300', ring: 'border-amber-500/40' },
  { key: 'low', label: 'Low', accent: 'text-sky-300', ring: 'border-sky-500/40' },
  { key: 'info', label: 'Info', accent: 'text-slate-300', ring: 'border-slate-600/60' },
];

function statusChip(status, agentResults) {
  if (status === 'COMPLETED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border bg-emerald-500/10 text-emerald-300 border-emerald-500/40">
        <CheckCircle2 className="w-3.5 h-3.5" /> Analysis completed
      </span>
    );
  }
  if (status === 'PARTIAL') {
    const failed = (agentResults || []).filter((a) => a.status !== 'succeeded');
    return (
      <span
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border bg-amber-500/10 text-amber-300 border-amber-500/40"
        title={failed.map((a) => `${a.agent}: ${a.status}${a.error ? ` — ${a.error}` : ''}`).join('\n')}
      >
        <AlertOctagon className="w-3.5 h-3.5" />
        Partial result — {failed.length} agent {failed.length === 1 ? 'issue' : 'issues'}
      </span>
    );
  }
  if (status === 'FAILED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border bg-rose-500/10 text-rose-300 border-rose-500/40">
        <AlertOctagon className="w-3.5 h-3.5" /> Analysis failed
      </span>
    );
  }
  if (status) {
    // Intermediate states exposed by the backend (QUEUED / PARSING / ANALYZING)
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border bg-indigo-500/10 text-indigo-300 border-indigo-500/40">
        <Activity className="w-3.5 h-3.5 animate-pulse" /> {status.toLowerCase()}
      </span>
    );
  }
  return null;
}

function AgentResultsRow({ agentResults }) {
  if (!agentResults?.length) return null;
  return (
    <div className="space-y-1.5 text-xs">
      {agentResults.map((a) => (
        <div key={a.agent} className="flex flex-wrap items-center gap-2">
          <span className="text-slate-400 font-medium">{a.agent}</span>
          {a.status === 'succeeded' ? (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-mono text-[10px]">
              <CheckCircle2 className="w-3 h-3" /> succeeded · {a.duration_seconds}s
            </span>
          ) : (
            <span
              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[10px] border ${
                a.status === 'timeout'
                  ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                  : 'bg-rose-500/10 text-rose-300 border-rose-500/30'
              }`}
            >
              <AlertOctagon className="w-3 h-3" /> {a.status}
              {a.error ? ` — ${a.error}` : ''}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

export function AnalysisSummaryCard({ run, findingsCount }) {
  if (!run) return null;

  const severityCounts = run.severity_counts || {};
  const extraSeverities = Object.keys(severityCounts).filter(
    (s) => !SEVERITY_CARDS.some((c) => c.key === s)
  );
  const total = run.finding_count ?? findingsCount ?? 0;
  const score = run.health_score;
  const coverage = coverageNotes(run.metrics);

  return (
    <section
      aria-label="Analysis summary"
      className="space-y-3"
    >
      <div className="flex flex-wrap items-center gap-2">
        {statusChip(run.status, run.agent_results)}
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono bg-slate-900 border border-slate-800 text-slate-300">
          <FileSearch className="w-3.5 h-3.5 text-indigo-400" /> {run.run_id}
        </span>
        {run.filename && (
          <span className="text-xs text-slate-400 font-mono">{run.filename}</span>
        )}
        {run.duration_seconds !== null && run.duration_seconds !== undefined && (
          <span className="inline-flex items-center gap-1 text-xs text-slate-500">
            <Clock className="w-3.5 h-3.5" /> {run.duration_seconds}s
          </span>
        )}
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="rounded-xl border border-indigo-500/40 bg-indigo-500/10 p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-indigo-300">
            <Scale className="w-3.5 h-3.5" /> Total
          </div>
          <div className="mt-1 text-2xl font-bold text-white font-mono">{total}</div>
          <div className="text-[10px] text-indigo-300/70">findings</div>
        </div>

        {SEVERITY_CARDS.map((c) => (
          <div key={c.key} className={`rounded-xl border ${c.ring} bg-slate-900/60 p-3`}>
            <div className={`text-[11px] font-semibold uppercase tracking-wider ${c.accent}`}>
              {c.label}
            </div>
            <div className="mt-1 text-2xl font-bold text-white font-mono">
              {severityCounts[c.key] ?? 0}
            </div>
            <div className="text-[10px] text-slate-500">severity</div>
          </div>
        ))}
      </div>

      {extraSeverities.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span className="uppercase tracking-wider font-semibold text-[11px]">Other severities:</span>
          {extraSeverities.map((s) => (
            <span
              key={s}
              className="px-2 py-0.5 rounded border border-slate-700 bg-slate-900 font-mono"
            >
              {s}: <span className="text-white font-bold">{severityCounts[s]}</span>
            </span>
          ))}
        </div>
      )}

      {/* Code health score — rendered straight from the backend value */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" /> Code Health Score
          </span>
          <span
            className={`text-2xl font-bold font-mono ${
              run.status === 'COMPLETED' ? healthScoreTone(score) : 'text-amber-300'
            }`}
          >
            {score === null || score === undefined ? '—' : score}/100
          </span>
        </div>
        <div
          className="h-2 rounded-full bg-slate-800 overflow-hidden"
          role="meter"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={score ?? undefined}
          aria-label="Code health score"
        >
          <div
            className={`h-full rounded-full ${healthScoreBar(score)}`}
            style={{ width: `${Math.max(0, Math.min(100, score ?? 0))}%` }}
          />
        </div>
        {run.status === 'COMPLETED' ? (
          <p className="text-[10px] text-slate-500">
            Computed by the orchestrator from the merged findings' severity weights. NOT a security
            guarantee — heuristic warnings are included in the weighting.
          </p>
        ) : (
          <p className="text-[10px] text-amber-300">
            This run is {run.status} — the score only reflects the findings that were actually
            collected. A high score here is <strong>not</strong> a clean bill of health: findings may
            be missing because part of the analysis did not run.
          </p>
        )}
      </div>

      {/* Agent outcome transparency (esp. for PARTIAL / FAILED) */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Agent results
        </span>
        <div className="mt-2">
          <AgentResultsRow agentResults={run.agent_results} />
        </div>
        {coverage.length > 0 && (
          <div className="mt-3 pt-3 border-t border-slate-800 space-y-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
              Detection coverage
            </span>
            <ul className="space-y-1">
              {coverage.map((note, i) => (
                <li key={i} className={`text-[11px] ${COVERAGE_TONE[note.tone] || 'text-slate-300'}`}>
                  • {note.text}
                </li>
              ))}
            </ul>
          </div>
        )}
        {run.status === 'PARTIAL' && (
          <p className="mt-2 text-xs text-amber-300">
            Part of this analysis did not run. The findings shown are real, but the absence of a
            finding is <strong>not</strong> proof that the issue is absent — re-run once the
            reported agent issue is resolved.
          </p>
        )}
        {run.status === 'FAILED' && (
          <p className="mt-2 text-xs text-rose-300">
            No agent completed successfully — these results cannot be trusted as a clean scan. Fix
            the reported agent issue and re-run the analysis.
          </p>
        )}
      </div>
    </section>
  );
}

export default AnalysisSummaryCard;
