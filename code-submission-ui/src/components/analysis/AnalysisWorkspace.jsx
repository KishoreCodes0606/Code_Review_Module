import React, { useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  FileUp,
  FlaskConical,
  Languages,
  ShieldAlert,
  Sparkles,
  X,
} from 'lucide-react';
import CodeEditor from '../CodeEditor';
import LanguageSelector from '../LanguageSelector';
import { classifyLanguage } from '../../utils/languageClassifier';
import { ApiError, getFindings, runAnalysis } from '../../utils/analysisApi';
import AnalysisSummaryCard from './AnalysisSummary';
import FindingsTable from './FindingsTable';
import FindingDetails from './FindingDetails';

/**
 * M2 AI Code Analysis workspace.
 *
 * Flow (mirrors the real backend contract):
 *   client-side gate -> POST /api/analysis (synchronous pipeline) -> run summary
 *   -> GET /api/analysis/{run_id}/findings (server-side deduped list).
 * No polling: the backend returns the terminal run directly (status
 * COMPLETED/PARTIAL/FAILED). Nothing is reported complete before the backend
 * says so, and agent failures are surfaced, never masked as a clean scan.
 */

const MAX_BYTES = 200 * 1024;   // backend analysis size guard (validated live)
const MAX_LINES = 2000;

const LANG_CHOICES = [
  { value: 'auto', label: 'Auto-Detect' },
  { value: 'python', label: 'Python' },
  { value: 'java', label: 'Java' },
];

function RequestErrorBanner({ error, onDismiss, onRetry }) {
  if (!error) return null;

  const isSyntax = error.kind === 'syntax_error';
  const isLanguage = error.kind === 'unsupported_language';
  const syntaxErrors = isSyntax ? error.payload?.syntax_errors || [] : [];

  return (
    <div
      role="alert"
      className="rounded-xl border border-rose-500/40 bg-rose-950/60 p-4 space-y-2"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-bold text-rose-200">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>
            {isSyntax && 'The backend rejected this code — syntax errors were detected'}
            {isLanguage && 'Unsupported language — the backend accepts only Python and Java'}
            {error.kind === 'payload_too_large' && 'Submission too large'}
            {error.kind === 'analysis_unavailable' && 'Analysis pipeline unavailable'}
            {error.kind === 'pipeline_failure' && 'The analysis pipeline crashed'}
            {error.kind === 'network' && 'Cannot reach the backend'}
            {['not_found', 'bad_json', 'unexpected'].includes(error.kind) && 'Unexpected backend error'}
          </span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200"
            >
              Retry
            </button>
          )}
          <button
            type="button"
            onClick={onDismiss}
            aria-label="Dismiss error"
            className="p-1 rounded text-rose-300 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <p className="text-xs text-rose-200/90">{error.message}</p>

      {syntaxErrors.length > 0 && (
        <ul className="space-y-1.5 mt-1">
          {syntaxErrors.map((e, i) => (
            <li key={i} className="text-xs text-rose-100/90 bg-rose-900/40 rounded-md px-3 py-1.5">
              <span className="font-mono font-bold">Line {e.line}, Col {e.col}:</span>{' '}
              {e.message}
              {e.missing_detail ? ` — ${e.missing_detail}` : ''}
              {e.hint ? ` (${e.hint})` : ''}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function AnalysisWorkspace() {
  // Inputs
  const [code, setCode] = useState('');
  const [filename, setFilename] = useState('');
  const [langChoice, setLangChoice] = useState('auto'); // auto | python | java

  // Run state
  const [analyzing, setAnalyzing] = useState(false);
  const [run, setRun] = useState(null);          // run summary from the backend
  const [findings, setFindings] = useState([]);  // merged, backend-deduplicated
  const [requestError, setRequestError] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const abortRef = useRef(null);

  // Client-side language gate mirrors M1's (classify heuristics / explicit choice)
  const classification = useMemo(
    () => classifyLanguage(code, filename, langChoice),
    [code, filename, langChoice]
  );

  const sizeWarning = useMemo(() => {
    const bytes = new Blob([code]).size;
    const lines = code ? code.split('\n').length : 0;
    if (bytes > MAX_BYTES) return `Payload is ${(bytes / 1024).toFixed(1)} KB — the analysis limit is 200 KB.`;
    if (lines > MAX_LINES) return `${lines} lines — the analysis limit is ${MAX_LINES} lines.`;
    return null;
  }, [code]);

  const canAnalyze = Boolean(code.trim()) && !analyzing && !sizeWarning;

  const resetResults = () => {
    setRun(null);
    setFindings([]);
    setSelectedFinding(null);
  };

  const handleClear = () => {
    setCode('');
    setFilename('');
    setRequestError(null);
    resetResults();
  };

  const handleLoadSample = (sample) => {
    setCode(sample.code);
    setFilename(sample.filename || '');
    setRequestError(null);
    resetResults();
  };

  const performAnalysisRequest = async () => {
    setRequestError(null);
    resetResults();
    setAnalyzing(true);

    const controller = new AbortController();
    abortRef.current = controller;
    try {
      // 1. The POST runs the pipeline synchronously and returns the terminal summary
      const summary = await runAnalysis({
        code,
        language: langChoice,
        filename: filename.trim(),
      });
      setRun(summary);

      // 2. Fetch the merged findings (server-side dedup) for the run
      try {
        const payload = await getFindings(summary.run_id);
        setFindings(payload.findings || []);
      } catch (err) {
        // Summary succeeded but findings fetch didn't — show summary, surface error
        setRequestError(err instanceof ApiError ? err
          : new ApiError('unexpected', 0, 'Could not load the findings list for this run.'));
      }
    } catch (err) {
      if (controller.signal.aborted) return; // superseded/stopped — do not show stale errors
      setRequestError(err instanceof ApiError ? err
        : new ApiError('unexpected', 0, `Unexpected error: ${err.message || String(err)}`));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setAnalyzing(false);
    }
  };

  // Analyze = client-side gate first, then the real backend call
  const handleAnalyze = () => {
    if (!canAnalyze) return;
    if (!classification?.isAcceptable) {
      setRequestError(new ApiError(
        'unsupported_language', 0,
        `Not sent to the backend: this is detected as ${classification?.languageName || 'unknown language'}.`
      ));
      return;
    }
    performAnalysisRequest();
  };

  return (
    <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Module banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-rose-950/30 to-slate-900 p-6 border border-slate-800 shadow-md">
        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-semibold mb-3">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Multi-Agent Quality & Security Analysis</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            AI Code Analysis Module
          </h2>
          <p className="text-xs sm:text-sm text-slate-300 mt-2 leading-relaxed">
            Run the parallel <strong className="text-rose-300">Code Analysis Agent</strong> and{' '}
            <strong className="text-rose-300">Security Vulnerability Agent</strong> over Python or
            Java source. Analysis is purely static — submitted code is <strong>never executed</strong> —
            and heuristic warnings are always labeled separately from confirmed vulnerabilities.
          </p>
        </div>
      </div>

      <RequestErrorBanner
        error={requestError}
        onDismiss={() => setRequestError(null)}
        onRetry={code.trim() && !analyzing ? handleAnalyze : undefined}
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: input + results */}
        <div className="lg:col-span-8 space-y-4">
          {/* Source config bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800 self-start text-xs font-semibold">
              <Languages className="w-3.5 h-3.5 text-indigo-400 mx-2" />
              {LANG_CHOICES.map((c) => (
                <button
                  key={c.value}
                  type="button"
                  onClick={() => setLangChoice(c.value)}
                  aria-pressed={langChoice === c.value}
                  className={`px-3 py-2 rounded-lg transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
                    langChoice === c.value
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>

            <label className="flex items-center gap-2 text-xs text-slate-400">
              <FileUp className="w-3.5 h-3.5 shrink-0" />
              <span className="font-semibold uppercase tracking-wider text-[10px]">Filename</span>
              <input
                type="text"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                placeholder="e.g. auth_service.py or Demo.java"
                className="bg-slate-900 border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 w-52 focus:outline-none focus:border-indigo-500 font-mono"
              />
            </label>
          </div>

          {langChoice === 'auto' && (
            <LanguageSelector classification={classification} />
          )}

          {sizeWarning && (
            <div role="alert" className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-950/60 px-3 py-2 text-xs text-amber-200">
              <Ban className="w-4 h-4 shrink-0" />
              {sizeWarning}
            </div>
          )}

          {/* Reusable editor (Analyze replaces the M1 validate action) */}
          <CodeEditor
            code={code}
            language={classification?.language === 'java' ? 'java' : 'python'}
            onChangeCode={setCode}
            onValidate={handleAnalyze}
            onClear={handleClear}
            onLoadSample={handleLoadSample}
            errors={requestError?.kind === 'syntax_error' ? requestError.payload?.syntax_errors || [] : []}
            isValidating={analyzing}
            metrics={null}
            validateLabel="Analyze Code"
          />

          {/* Progress */}
          {analyzing && (
            <div
              role="status"
              className="flex items-center gap-2.5 rounded-lg border border-indigo-500/40 bg-indigo-950/50 px-3.5 py-2.5 text-xs text-indigo-200"
            >
              <Activity className="w-4 h-4 animate-spin shrink-0 text-indigo-400" />
              <span>
                Running the multi-agent pipeline — quality and security agents are analyzing in
                parallel (static only). The scanner subprocesses can take a few seconds; the
                result appears the moment the backend reports a terminal status.
              </span>
            </div>
          )}

          {/* Summary + findings for the current run */}
          {run && (
            <AnalysisSummaryCard run={run} findingsCount={findings.length} />
          )}
          {run && (
            <FindingsTable
              findings={findings}
              onViewDetails={setSelectedFinding}
              selectedFindingId={selectedFinding?.id}
              runStatus={run.status}
            />
          )}

          {/* Empty state (before any run) */}
          {!run && !analyzing && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center space-y-2">
              <FlaskConical className="w-9 h-9 text-slate-600 mx-auto" />
              <h3 className="text-sm font-bold text-slate-300">No analysis run yet</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Paste Python or Java code (or load a sample inside the editor), then press{' '}
                <span className="font-semibold text-slate-300">Analyze Code</span>. Findings,
                severity scores and remediation guidance appear here from the real backend run.
              </p>
            </div>
          )}
        </div>

        {/* Right: finding details */}
        <div className="lg:col-span-4 space-y-4 lg:sticky lg:top-6">
          {selectedFinding ? (
            <FindingDetails finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 text-center">
              <Sparkles className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <h3 className="text-sm font-bold text-slate-300">Finding Details</h3>
              <p className="mt-1 text-xs text-slate-500">
                Select <span className="font-semibold text-slate-400">View Details</span> on any
                finding to see its code snippet, severity score, CWE/OWASP references and
                remediation guidance.
              </p>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
