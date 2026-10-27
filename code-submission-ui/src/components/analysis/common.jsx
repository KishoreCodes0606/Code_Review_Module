import React from 'react';
import { ShieldAlert, Lightbulb } from 'lucide-react';

/**
 * Shared presentation helpers for M2 findings, driven by the backend's actual
 * enums: severity in {'critical','high','medium','low','info'} (any extra values
 * get a neutral fallback), finding_kind in {'vulnerability','heuristic_warning'}.
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_STYLES = {
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  info: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  unknown: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
};

const SEVERITY_DOTS = {
  critical: 'bg-rose-400',
  high: 'bg-orange-400',
  medium: 'bg-amber-400',
  low: 'bg-sky-400',
  info: 'bg-slate-400',
  unknown: 'bg-slate-400',
};

export function severityStyle(severity) {
  return SEVERITY_STYLES[severity] || SEVERITY_STYLES.unknown;
}

export function severityDot(severity) {
  return SEVERITY_DOTS[severity] || SEVERITY_DOTS.unknown;
}

export function severityRank(severity) {
  const idx = SEVERITY_ORDER.indexOf(severity);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

export function SeverityBadge({ severity, score }) {
  const label = severity ? String(severity) : 'unknown';
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono font-bold text-[11px] border capitalize ${severityStyle(label)}`}
      title={score !== undefined ? `Severity score: ${score} / 10` : label}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${severityDot(label)}`} />
      {label}
    </span>
  );
}

/** Backend distinguishes proven vulnerabilities from pattern-level heuristics. */
export function FindingKindBadge({ findingKind }) {
  if (findingKind === 'vulnerability') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border bg-rose-500/15 text-rose-300 border-rose-500/40"
        title="A concrete dangerous pattern flowing into a sink (evidence-backed)">
        <ShieldAlert className="w-3 h-3" />
        Vulnerability
      </span>
    );
  }
  if (findingKind === 'heuristic_warning') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border bg-purple-500/10 text-purple-300 border-purple-500/40"
        title="Heuristic concern from a code pattern — not a confirmed vulnerability">
        <Lightbulb className="w-3 h-3" />
        Heuristic
      </span>
    );
  }
  return null;
}

export function healthScoreTone(score) {
  if (score === null || score === undefined) return 'text-slate-300';
  if (score >= 85) return 'text-emerald-400';
  if (score >= 60) return 'text-amber-400';
  return 'text-rose-400';
}

export function healthScoreBar(score) {
  if (score === null || score === undefined) return 'bg-slate-600';
  if (score >= 85) return 'bg-emerald-500';
  if (score >= 60) return 'bg-amber-500';
  return 'bg-rose-500';
}

export const CATEGORY_LABEL = { security: 'Security', quality: 'Code Quality' };
