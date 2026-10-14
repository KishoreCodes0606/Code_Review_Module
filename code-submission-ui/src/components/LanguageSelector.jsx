import React from 'react';
import { Sparkles, CheckCircle2, AlertOctagon, HelpCircle } from 'lucide-react';

export default function LanguageSelector({
  selectedMode, // 'auto' | 'python' | 'java'
  classification, // { isAcceptable, language, languageName, confidence, reason }
  onSelectMode
}) {
  const isAcceptable = classification?.isAcceptable;
  const detectedName = classification?.languageName || 'Detecting...';

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
      <div className="flex items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Target Language:
        </span>
        <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
          <button
            type="button"
            onClick={() => onSelectMode('auto')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
              selectedMode === 'auto'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            Auto-Detect
          </button>

          <button
            type="button"
            onClick={() => onSelectMode('python')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
              selectedMode === 'python'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="text-yellow-400 font-bold font-mono">py</span>
            Python
          </button>

          <button
            type="button"
            onClick={() => onSelectMode('java')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
              selectedMode === 'java'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="text-orange-400 font-bold font-mono">☕</span>
            Java
          </button>
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
              {selectedMode === 'auto' && classification.confidence > 0 && (
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
