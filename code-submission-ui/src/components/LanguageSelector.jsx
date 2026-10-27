import React from 'react';
import { Sparkles, CheckCircle2, AlertOctagon } from 'lucide-react';

export default function LanguageSelector({
  classification // { isAcceptable, language, languageName, confidence, reason }
}) {
  const isAcceptable = classification?.isAcceptable;
  const detectedName = classification?.languageName || 'Detecting...';

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
      <div className="flex items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Target Language:
        </span>
        <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-xs font-medium shadow-sm">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Auto-Detect</span>
        </div>
      </div>

      {/* Detection Status Indicator */}
      <div className="flex items-center gap-2 text-xs">
        <span className="text-slate-400">Language Status:</span>
        {classification && classification.language !== 'unknown' ? (
          isAcceptable ? (
            <span
              className={`px-2.5 py-1 rounded-md font-mono font-medium inline-flex items-center gap-1.5 border ${
                classification.language === 'python'
                  ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30'
                  : 'bg-orange-500/10 text-orange-300 border-orange-500/30'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>{detectedName} (Accepted)</span>
              {classification.confidence > 0 && (
                <span className="text-[10px] text-slate-400 font-sans ml-0.5">
                  · {Math.round(classification.confidence * 100)}%
                </span>
              )}
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded-md font-mono font-medium inline-flex items-center gap-1.5 border bg-rose-500/10 text-rose-300 border-rose-500/30">
              <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
              <span>{detectedName} (Rejected)</span>
            </span>
          )
        ) : (
          <span className="px-2.5 py-1 rounded-md font-mono text-slate-400 border border-slate-800 bg-slate-950">
            Waiting for code input
          </span>
        )}
      </div>
    </div>
  );
}
