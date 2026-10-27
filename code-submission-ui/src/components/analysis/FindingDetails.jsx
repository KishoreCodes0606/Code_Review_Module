import React, { useEffect } from 'react';
import { ExternalLink, File, MapPin, X } from 'lucide-react';
import { CATEGORY_LABEL, FindingKindBadge, SeverityBadge } from './common';

/**
 * Detail panel for a single finding. Renders ONLY fields the backend actually
 * provides; every optional field (owasp_category, cwe_id, remediation_advice,
 * code_snippet…) is handled as potentially missing/null. Snippets are rendered
 * as plain text nodes — never as raw HTML — so untrusted source code cannot
 * inject markup.
 */

function Field({ label, children }) {
  if (children === null || children === undefined || children === '') return null;
  return (
    <div className="min-w-0">
      <dt className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-xs text-slate-200 break-words">{children}</dd>
    </div>
  );
}

export function FindingDetails({ finding, onClose }) {
  useEffect(() => {
    if (!finding) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [finding, onClose]);

  if (!finding) return null;

  const cweNum = typeof finding.cwe_id === 'string' && finding.cwe_id.startsWith('CWE-')
    ? finding.cwe_id.slice(4)
    : null;
  const lineSpan = finding.line_start === finding.line_end || finding.line_end == null
    ? `${finding.line_start ?? '?'}`
    : `${finding.line_start}–${finding.line_end}`;

  return (
    <aside
      aria-label="Finding details"
      className="rounded-xl border border-indigo-500/40 bg-slate-900/80 shadow-2xl"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3 px-4 py-3 border-b border-slate-800 bg-slate-950/70">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} score={finding.severity_score} />
            <FindingKindBadge findingKind={finding.finding_kind} />
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                finding.category === 'security'
                  ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                  : 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
              }`}
            >
              {CATEGORY_LABEL[finding.category] || finding.category}
            </span>
          </div>
          <h3 className="text-sm font-bold text-white leading-snug">{finding.title}</h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close finding details"
          className="shrink-0 p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="px-4 py-4 space-y-4 max-h-[560px] overflow-y-auto">
        <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-3">
          <Field label="Severity score">
            <span className="font-mono font-bold">{finding.severity_score}</span>
            <span className="text-slate-500"> / 10</span>
          </Field>
          <Field label="Confidence (heuristic tier)">
            {finding.confidence != null ? (
              <>
                <span className="font-mono font-bold">{finding.confidence}</span>
                <span className="text-slate-500"> — rule-based certainty tier, not a probability</span>
              </>
            ) : null}
          </Field>
          <Field label="Source agent">{finding.source_agent}</Field>
          <Field label="Detection">{finding.detection}</Field>
          <Field label="Rule ID">
            <span className="font-mono">{finding.rule_id}</span>
          </Field>
          <Field label="Category">{CATEGORY_LABEL[finding.category] || finding.category}</Field>
          <Field label={`File & ${finding.line_start === finding.line_end || finding.line_end == null ? 'line' : 'lines'}`}>
            <span className="inline-flex items-center gap-1.5 font-mono">
              <MapPin className="w-3 h-3 text-indigo-400" />
              {finding.file_path || '—'} : {lineSpan}
            </span>
          </Field>
          <Field label="Finding ID">
            <span className="font-mono text-[10px]">{finding.id}</span>
          </Field>
        </dl>

        {finding.code_snippet && (
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
              <File className="w-3 h-3" /> Code snippet (lines {lineSpan})
            </span>
            <pre className="mt-1.5 rounded-lg bg-slate-950 border border-slate-800 p-3 overflow-x-auto text-[11px] leading-relaxed font-mono text-slate-300 whitespace-pre">
              {finding.code_snippet}
            </pre>
          </div>
        )}

        <Field label="Remediation guidance">{finding.remediation_advice}</Field>

        {(finding.cwe_id || finding.owasp_category) && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">References</span>
            {finding.cwe_id && (
              <a
                href={cweNum ? `https://cwe.mitre.org/data/definitions/${cweNum}.html` : '#'}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[11px] border bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
              >
                {finding.cwe_id} <ExternalLink className="w-3 h-3" />
              </a>
            )}
            {finding.owasp_category && (
              <span className="px-2 py-0.5 rounded text-[11px] border bg-slate-800 text-slate-300">
                OWASP {finding.owasp_category}
              </span>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}

export default FindingDetails;
