import React from 'react';
import { History, Clock, FileCode2, CheckCircle2, XCircle, Trash2, ArrowUpRight } from 'lucide-react';

export default function SubmissionHistory({
  history = [],
  onLoadSubmission,
  onClearHistory
}) {
  if (!history || history.length === 0) {
    return null;
  }

  return (
    <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
          <History className="w-4 h-4 text-indigo-400" />
          <span>Recent Submissions ({history.length})</span>
        </div>

        <button
          type="button"
          onClick={onClearHistory}
          className="text-[11px] text-slate-500 hover:text-rose-400 flex items-center gap-1 transition-colors"
        >
          <Trash2 className="w-3 h-3" />
          <span>Clear History</span>
        </button>
      </div>

      <div className="divide-y divide-slate-800/60 max-h-56 overflow-y-auto">
        {history.map((item) => {
          const date = new Date(item.created_at);
          const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

          return (
            <div
              key={item.id}
              className="py-2.5 flex items-center justify-between gap-3 text-xs hover:bg-slate-800/40 px-2 rounded-lg transition-colors group cursor-pointer"
              onClick={() => onLoadSubmission(item)}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                {item.syntax_valid ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                )}

                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-slate-200 truncate font-medium">
                      {item.filename || `Pasted ${item.language}`}
                    </span>
                    <span
                      className={`text-[10px] uppercase font-bold px-1.5 py-0.2 rounded ${
                        item.language === 'python'
                          ? 'bg-yellow-500/10 text-yellow-400'
                          : 'bg-orange-500/10 text-orange-400'
                      }`}
                    >
                      {item.language}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 flex items-center gap-2">
                    <span>{item.line_count} lines</span>
                    <span>·</span>
                    <span>{(item.size_bytes / 1024).toFixed(1)} KB</span>
                    <span>·</span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {timeStr}
                    </span>
                  </div>
                </div>
              </div>

              <div className="opacity-0 group-hover:opacity-100 flex items-center gap-1 text-indigo-400 text-xs font-semibold shrink-0 transition-opacity">
                <span>Load</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
