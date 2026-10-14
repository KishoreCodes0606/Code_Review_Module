import React from 'react';
import { ShieldCheck, Cpu, Terminal, FileCode2, Layers, CheckCircle2 } from 'lucide-react';

export default function Header({ onReset }) {
  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-cyan-400 p-0.5 flex items-center justify-center shadow-lg shadow-indigo-500/20">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="h-5 w-5 text-indigo-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base sm:text-lg font-bold text-white tracking-tight">
                  Code Submission Module
                </h1>
                <span className="text-[11px] font-semibold tracking-wide uppercase px-2.5 py-0.5 rounded-full bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  Python & Java Only
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Automated Language Detection & Syntax Verification Engine
              </p>
            </div>
          </div>

          {/* Module Specs & Actions */}
          <div className="flex items-center gap-3">
            <div className="hidden md:flex items-center gap-2 text-xs text-slate-400 bg-slate-800/60 border border-slate-700/60 rounded-lg px-3 py-1.5">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
                Validator Active
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-yellow-400 font-mono font-medium">Python 3.x</span>
              <span className="text-slate-600">·</span>
              <span className="text-orange-400 font-mono font-medium">Java 17+</span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">Max 200KB</span>
            </div>

            <button
              onClick={onReset}
              className="text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors"
              title="Clear and start new submission"
            >
              New Submission
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
