import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileCheck,
  Hash,
  Copy,
  Check,
  Send,
  Code,
  Info,
  ShieldAlert,
  AlertOctagon,
  Ban
} from 'lucide-react';

export default function ValidationResultCard({
  classification,
  validationResult,
  metrics,
  sourceType,
  filename,
  onOpenPayloadModal,
  onSubmitToPipeline
}) {
  const [copiedHash, setCopiedHash] = useState(false);

  if (!validationResult && !classification) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center text-slate-500">
        <FileCheck className="w-10 h-10 mx-auto text-slate-600 mb-2" />
        <p className="text-sm font-medium">No code analyzed yet</p>
        <p className="text-xs text-slate-600 mt-1">
          Paste or upload your code, then click "Validate Syntax" or press Ctrl+Enter.
        </p>
      </div>
    );
  }

  const isLanguageAccepted = classification?.isAcceptable;
  const isSyntaxValid = Boolean(validationResult?.valid);
  const detectedName = classification?.languageName || 'Unknown';
  const errors = validationResult?.errors || [];
  const warnings = validationResult?.warnings || [];
  const hasMissingItem = Boolean(
    validationResult?.hasMissingItem ||
    errors.some(e => e.is_missing_item || e.isMissingItem)
  );
  const missingItemErrors = errors.filter(e => e.is_missing_item || e.isMissingItem);

  const copyHash = () => {
    if (metrics?.hash) {
      navigator.clipboard.writeText(metrics.hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  return (
    <div className="space-y-4">
      {/* =========================================================================
          SCENARIO 1: CODE IS REJECTED (DIFFERENT LANGUAGE, NOT PYTHON OR JAVA)
         ========================================================================= */}
      {!isLanguageAccepted ? (
        <div className="rounded-xl p-5 border bg-rose-950/30 border-rose-500/60 shadow-lg shadow-rose-950/30 space-y-4">
          <div className="flex items-start gap-3.5">
            <div className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border bg-rose-500/20 text-rose-400 border-rose-500/40">
              <Ban className="w-6 h-6" />
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  Code Rejected: Unsupported Language
                </h3>
                <span className="text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-rose-500/20 text-rose-300 border-rose-500/40">
                  REJECTED
                </span>
              </div>
              <p className="text-xs text-rose-200/90 leading-relaxed">
                This code is not acceptable as it is from a different language (
                <strong className="text-white underline">{detectedName}</strong>).
                This module strictly accepts only <strong className="text-yellow-300">Python</strong> and <strong className="text-orange-300">Java</strong> source code.
              </p>
            </div>
          </div>

          {/* Evidence / Detected Language Reason */}
          <div className="bg-slate-950/70 rounded-lg p-3 border border-rose-500/30 text-xs space-y-2">
            <div className="flex items-center justify-between text-slate-300 font-semibold text-[11px]">
              <span>Detected Characteristics:</span>
              <span className="text-rose-400 font-mono">{detectedName}</span>
            </div>
            {classification?.evidence && classification.evidence.length > 0 ? (
              <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px]">
                {classification.evidence.map((ev, idx) => (
                  <li key={idx}>
                    <span className="text-slate-300">{ev}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-slate-400 text-[11px]">
                Language syntax does not conform to either Python or Java grammar standards.
              </p>
            )}
            <div className="pt-1.5 border-t border-slate-800 text-[11px] text-amber-300/90 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 shrink-0" />
              <span>Please replace the code with valid Python (.py) or Java (.java) source.</span>
            </div>
          </div>
        </div>
      ) : (
        /* =========================================================================
           SCENARIO 2: CODE IS RECOGNIZED AS PYTHON OR JAVA
           ========================================================================= */
        <div
          className={`rounded-xl p-5 border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 transition-all ${
            isSyntaxValid
              ? 'bg-emerald-950/25 border-emerald-500/50 shadow-lg shadow-emerald-950/20'
              : 'bg-rose-950/35 border-rose-500/60 shadow-lg shadow-rose-950/30'
          }`}
        >
          <div className="flex items-start sm:items-center gap-3.5">
            <div
              className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border ${
                isSyntaxValid
                  ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                  : 'bg-rose-500/20 text-rose-400 border-rose-500/40'
              }`}
            >
              {isSyntaxValid ? (
                <CheckCircle2 className="w-6 h-6" />
              ) : (
                <AlertTriangle className="w-6 h-6" />
              )}
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  {isSyntaxValid
                    ? `Accepted: Valid ${detectedName} Code`
                    : `Code Rejected: ${hasMissingItem ? 'Missing Item Detected' : 'Incorrect Code'} in ${detectedName}`}
                </h3>
                <span
                  className={`text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${
                    isSyntaxValid
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                      : hasMissingItem
                      ? 'bg-amber-500/25 text-amber-300 border-amber-500/50'
                      : 'bg-rose-500/25 text-rose-300 border-rose-500/50'
                  }`}
                >
                  {isSyntaxValid
                    ? 'ACCEPTED · SYNTAX VALID'
                    : hasMissingItem
                    ? 'REJECTED: MISSING ITEM'
                    : 'REJECTED: INCORRECT CODE'}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                {isSyntaxValid
                  ? `The code is verified as ${detectedName} and the syntax is acceptable. Code is ready for inspection.`
                  : `This code was recognized as ${detectedName}, but is REJECTED because it contains syntax errors or missing code items. Incomplete or broken code cannot proceed to code review.`}
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 w-full sm:w-auto shrink-0">
            <button
              type="button"
              onClick={onOpenPayloadModal}
              className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
            >
              <Code className="w-3.5 h-3.5" />
              <span>View JSON</span>
            </button>

            {isSyntaxValid ? (
              <button
                type="button"
                onClick={onSubmitToPipeline}
                className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-md shadow-emerald-900/30 transition-all hover:scale-[1.02]"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Submit Code</span>
              </button>
            ) : (
              <span className="flex-1 sm:flex-initial px-3 py-2 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs font-semibold flex items-center justify-center gap-1.5">
                <Ban className="w-3.5 h-3.5 text-rose-400" />
                <span>Blocked: Resolve Errors</span>
              </span>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
          HIGHLIGHTED MISSING ITEMS BANNER (Prominent callout when code has missing parts)
         ========================================================================= */}
      {isLanguageAccepted && !isSyntaxValid && hasMissingItem && missingItemErrors.length > 0 && (
        <div className="rounded-xl p-4 border bg-amber-950/30 border-amber-500/50 shadow-md shadow-amber-950/20 space-y-3">
          <div className="flex items-center gap-2 text-amber-300 font-bold text-sm">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Missing Item Highlighted ({missingItemErrors.length})</span>
          </div>
          <div className="grid grid-cols-1 gap-2.5">
            {missingItemErrors.map((mErr, mIdx) => (
              <div
                key={mIdx}
                className="bg-slate-950/90 rounded-lg p-3 border border-amber-500/40 text-xs space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-amber-500/25 text-amber-300 font-mono font-bold text-[11px] border border-amber-500/40">
                      Line {mErr.line}:{mErr.col}
                    </span>
                    <span className="font-bold text-amber-200">
                      Missing Item: <span className="text-yellow-300 font-mono underline">{mErr.missing_item || mErr.missingItem || 'Required syntax token'}</span>
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-amber-400/80">
                    rule: {mErr.rule || 'missing_item'}
                  </span>
                </div>

                <p className="text-slate-300 text-[11px] leading-relaxed">
                  {mErr.missing_detail || mErr.missingDetail || mErr.message}
                </p>

                {(mErr.snippet || mErr.text) && (
                  <div className="bg-slate-900/90 p-2 rounded border border-slate-800 font-mono text-[11px] text-slate-300">
                    <span className="text-slate-600 mr-2">{mErr.line} |</span>
                    <span className="text-amber-200 font-semibold">{mErr.snippet || mErr.text}</span>
                  </div>
                )}

                {mErr.hint && (
                  <div className="flex items-start gap-1.5 text-emerald-400 text-[11px] pt-1 border-t border-slate-800/80">
                    <span className="font-semibold shrink-0">👉 Suggested Fix:</span>
                    <span>{mErr.hint}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Syntax Errors List */}
      {isLanguageAccepted && !isSyntaxValid && errors.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-semibold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4" />
              {`Issues in ${detectedName} (${errors.length})`}
            </span>
            <span>Resolve issues before code can be submitted</span>
          </div>

          <div className="space-y-2">
            {errors.map((err, idx) => {
              const isMissing = Boolean(err.is_missing_item || err.isMissingItem);
              return (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl bg-slate-900/90 border text-xs space-y-2 ${
                    isMissing ? 'border-amber-500/40' : 'border-rose-500/30'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] border ${
                        isMissing
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      }`}>
                        Line {err.line}:{err.col}
                      </span>
                      {isMissing ? (
                        <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold text-[10px] border border-amber-500/40 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          MISSING: {err.missing_item || err.missingItem || 'Token'}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold text-[10px] border border-rose-500/40 flex items-center gap-1">
                          <XCircle className="w-3 h-3" />
                          INCORRECT CODE
                        </span>
                      )}
                      <span className="font-semibold text-rose-200">{err.message}</span>
                    </div>
                    {err.rule && (
                      <span className="text-[10px] text-slate-500 font-mono">
                        rule: {err.rule}
                      </span>
                    )}
                  </div>

                  {(err.snippet || err.text) && (
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                      <span className="text-slate-600 select-none mr-2">{err.line} |</span>
                      <span className={isMissing ? 'text-amber-300 font-semibold' : 'text-rose-300'}>
                        {err.snippet || err.text}
                      </span>
                    </div>
                  )}

                  {err.hint && (
                    <div className="flex items-start gap-1.5 text-slate-400 text-[11px]">
                      <span className="text-emerald-400 font-semibold">Suggested fix:</span>
                      <span>{err.hint}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Warnings List */}
      {isLanguageAccepted && warnings && warnings.length > 0 && (
        <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs space-y-1.5">
          <div className="flex items-center gap-1.5 text-amber-300 font-semibold">
            <AlertTriangle className="w-4 h-4" />
            <span>Notices ({warnings.length})</span>
          </div>
          <ul className="list-disc list-inside space-y-1 text-slate-300 pl-1 text-[11px]">
            {warnings.map((w, idx) => (
              <li key={idx}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Source Code Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900/60 p-3 rounded-xl border border-slate-800">
          <div className="text-[11px] text-slate-400 font-medium">Total Lines</div>
          <div className="text-base font-bold text-white font-mono mt-0.5">
            {metrics?.lines || 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            {metrics?.codeLines || 0} code · {metrics?.commentLines || 0} comments
          </div>
        </div>

        <div className="bg-slate-900/60 p-3 rounded-xl border border-slate-800">
          <div className="text-[11px] text-slate-400 font-medium">Payload Size</div>
          <div className="text-base font-bold text-white font-mono mt-0.5">
            {((metrics?.sizeBytes || 0) / 1024).toFixed(2)} KB
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            {metrics?.chars || 0} characters
          </div>
        </div>

        <div className="bg-slate-900/60 p-3 rounded-xl border border-slate-800">
          <div className="text-[11px] text-slate-400 font-medium">Detected Language</div>
          <div
            className={`text-base font-bold capitalize mt-0.5 truncate ${
              isLanguageAccepted ? 'text-indigo-400' : 'text-rose-400'
            }`}
          >
            {detectedName}
          </div>
          <div className="text-[10px] text-slate-500 mt-1 truncate">
            {isLanguageAccepted ? 'Allowed (Python/Java)' : 'Not Allowed'}
          </div>
        </div>

        <div className="bg-slate-900/60 p-3 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 font-medium">SHA-256</span>
            <button
              onClick={copyHash}
              className="text-slate-400 hover:text-white transition-colors"
              title="Copy full SHA-256 hash"
            >
              {copiedHash ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
          <div className="text-xs font-mono text-slate-300 mt-1 truncate" title={metrics?.hash}>
            {metrics?.hash ? `${metrics.hash.slice(0, 12)}...` : 'Computing...'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Deduplication Hash</div>
        </div>
      </div>
    </div>
  );
}
