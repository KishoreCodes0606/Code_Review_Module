import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Loader2,
  RotateCw,
  ShieldCheck,
  XCircle,
} from 'lucide-react';

/**
 * Automatic syntax-validation status for the unified workspace.
 *
 * `status` is the validation lifecycle, never an analysis result:
 *   idle       -> Waiting for Input (editor empty)
 *   validating -> request in flight (debounce + backend round trip)
 *   accepted   -> backend accepted the latest editor content
 *   rejected   -> backend rejected the source (syntax / unsupported language)
 *   error      -> the validation service could not complete (network/server)
 *
 * The `error` state is deliberately amber and worded differently from
 * `rejected` so a backend outage is never mistaken for invalid syntax.
 */

const STATUS_META = {
  idle: {
    label: 'Waiting for Input',
    icon: CircleDashed,
    chip: 'bg-slate-500/10 text-slate-300 border-slate-600/60',
    text: 'text-slate-400',
  },
  validating: {
    label: 'Validating',
    icon: Loader2,
    spin: true,
    chip: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/40',
    text: 'text-indigo-200',
  },
  accepted: {
    label: 'Accepted',
    icon: CheckCircle2,
    chip: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/40',
    text: 'text-emerald-200',
  },
  rejected: {
    label: 'Rejected',
    icon: XCircle,
    chip: 'bg-rose-500/10 text-rose-300 border-rose-500/40',
    text: 'text-rose-200',
  },
  error: {
    label: 'Validation Error',
    icon: AlertTriangle,
    chip: 'bg-amber-500/10 text-amber-300 border-amber-500/40',
    text: 'text-amber-200',
  },
};

const DEFAULT_MESSAGE = {
  idle: 'Paste or type Python or Java code to start automatic validation and AI analysis.',
  validating: 'Checking the current editor content…',
  accepted: 'Syntax accepted — AI code analysis starts automatically.',
  rejected: 'The code was rejected. Fix the reported issue and validation will re-run automatically.',
  error: 'The validation service could not complete the request.',
};

export default function ValidationStatusBar({
  status = 'idle',
  message,
  languageLabel,
  issueCount = 0,
  onRetry,
}) {
  const meta = STATUS_META[status] || STATUS_META.idle;
  const Icon = meta.icon;

  return (
    <div
      role="status"
      aria-live="polite"
      className="rounded-xl border border-slate-800 bg-slate-900/60 px-3.5 py-2.5 space-y-1.5"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-400">
          <ShieldCheck className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
          <span className="uppercase tracking-wider text-[11px]">Automatic Syntax Validation</span>
          <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-bold uppercase tracking-wider ${meta.chip}`}
          >
            <Icon className={`w-3.5 h-3.5 ${meta.spin ? 'animate-spin' : ''}`} />
            {meta.label}
          </span>
        </div>

        <div className="flex items-center gap-2 text-[11px]">
          {languageLabel && (
            <span className="font-mono text-slate-400">{languageLabel}</span>
          )}
          {status === 'rejected' && issueCount > 0 && (
            <span className="px-2 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-300 font-mono">
              {issueCount} {issueCount === 1 ? 'issue' : 'issues'}
            </span>
          )}
          {status === 'error' && onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
            >
              <RotateCw className="w-3.5 h-3.5" />
              Retry
            </button>
          )}
        </div>
      </div>

      <p className={`text-xs leading-relaxed ${meta.text}`}>
        {message || DEFAULT_MESSAGE[status] || DEFAULT_MESSAGE.idle}
      </p>
    </div>
  );
}
