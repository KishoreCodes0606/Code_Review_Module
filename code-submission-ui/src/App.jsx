import React, { useState } from 'react';
import Header from './components/Header';
import AnalysisWorkspace from './components/analysis/AnalysisWorkspace';

/**
 * Code Review Module.
 *
 * One workspace only: the former Code Submission (M1) and AI Code Analysis (M2)
 * panels are merged into AnalysisWorkspace, which validates submitted code
 * automatically and then runs the existing multi-agent analysis pipeline.
 */
export default function App() {
  // Bumping this token resets the unified workspace (header "New Submission").
  const [resetToken, setResetToken] = useState(0);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-indigo-500 selection:text-white">
      <Header onReset={() => setResetToken((t) => t + 1)} />

      <AnalysisWorkspace resetToken={resetToken} />

      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-center text-xs text-slate-500">
        AI Code Review &amp; Security Analysis Agent · Smart Code Inspection Platform
      </footer>
    </div>
  );
}
