import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  FileCode,
  FlaskConical,
  Languages,
  RotateCw,
  ShieldAlert,
  Sparkles,
  UploadCloud,
  X,
} from 'lucide-react';
import CodeEditor from '../CodeEditor';
import LanguageSelector from '../LanguageSelector';
import FileUploadZone from '../FileUploadZone';
import ValidationStatusBar from './ValidationStatusBar';
import AnalysisSummaryCard from './AnalysisSummary';
import FindingsTable from './FindingsTable';
import FindingDetails from './FindingDetails';
import { classifyLanguage } from '../../utils/languageClassifier';
import { calculateCodeMetrics } from '../../utils/syntaxValidator';
import {
  ApiError,
  getFindings,
  getPrSummary,
  getRemediation,
  runAnalysis,
  validateSubmission,
} from '../../utils/analysisApi';
import HealthScoreCard from './HealthScoreCard';
import PrSummaryPanel from './PrSummaryPanel';
import AssistantPanel from './AssistantPanel';
import ReportExportBar from './ReportExportBar';
import { RemediationOverview } from './RemediationPanel';

/**
 * Unified code review workspace: submission -> automatic syntax validation ->
 * automatic multi-agent quality & security analysis.
 *
 * Contract notes (verified against server.py):
 *  - POST /api/submissions/validate is the single source of truth for language
 *    and syntax. 200 = decision (valid true/false), 422 = unsupported language.
 *    Network/server failures raise ApiError and are shown as "Validation Error"
 *    — never as a syntax rejection.
 *  - POST /api/analysis runs the pipeline synchronously and returns the terminal
 *    run summary, then GET /api/analysis/{run_id}/findings returns the merged,
 *    server-deduplicated findings. No polling, no mock data.
 *
 * Automatic flow:
 *   code/language change -> 700 ms debounce -> validate -> accepted -> analyze
 *   Every change invalidates prior results, aborts in-flight work, and bumps a
 *   sequence token so late responses from an older request are ignored.
 */

const DEBOUNCE_MS = 700;
const MAX_BYTES = 200 * 1024; // backend analysis size guard
const MAX_LINES = 2000;
const CACHE_LIMIT = 8;

const LANG_CHOICES = [
  { value: 'auto', label: 'Auto-Detect' },
  { value: 'python', label: 'Python' },
  { value: 'java', label: 'Java' },
];

const freshValidation = () => ({
  status: 'idle', // idle | validating | accepted | rejected | error
  message: '',
  errors: [],
  warnings: [],
  language: null,
  languageName: null,
  rejectedLanguage: false,
  hasMissingItem: false,
  issueCount: 0,
});

/** Small, dependency-free hash so cached runs can be matched without keeping code copies. */
function hashSource(code) {
  let h = 0x811c9dc5;
  for (let i = 0; i < code.length; i += 1) {
    h ^= code.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

function RequestErrorBanner({ error, onDismiss, onRetry }) {
  if (!error) return null;

  const isSyntax = error.kind === 'syntax_error';
  const isLanguage =
    error.kind === 'unsupported_language' || error.kind === 'validation_rejected';
  const syntaxErrors = isSyntax ? error.payload?.syntax_errors || [] : [];

  const title = {
    syntax_error: 'The backend rejected this code — syntax errors were detected',
    unsupported_language: 'Unsupported language — the backend accepts only Python and Java',
    validation_rejected: 'The backend rejected this submission',
    payload_too_large: 'Submission too large',
    analysis_unavailable: 'Analysis pipeline unavailable',
    pipeline_failure: 'The analysis pipeline crashed',
    network: 'Cannot reach the backend',
    timeout: 'The request timed out',
    not_found: 'Analysis run not found',
    bad_json: 'Malformed backend response',
    unexpected: 'Unexpected backend error',
  }[error.kind] || 'Unexpected backend error';

  return (
    <div
      role="alert"
      className="rounded-xl border border-rose-500/40 bg-rose-950/60 p-4 space-y-2"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-bold text-rose-200">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{title}</span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200"
            >
              <RotateCw className="w-3.5 h-3.5" />
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

      {isLanguage && (
        <p className="text-xs text-rose-200/70">
          This workspace analyzes Python and Java only. Choose the language explicitly if the
          auto-detector misread your source.
        </p>
      )}

      {syntaxErrors.length > 0 && (
        <ul className="space-y-1.5 mt-1">
          {syntaxErrors.map((e, i) => (
            <li key={i} className="text-xs text-rose-100/90 bg-rose-900/40 rounded-md px-3 py-1.5">
              <span className="font-mono font-bold">
                Line {e.line}, Col {e.col}:
              </span>{' '}
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

export default function AnalysisWorkspace({ resetToken = 0 }) {
  // Inputs
  const [code, setCode] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);
  const [langChoice, setLangChoice] = useState('auto');
  const [showUpload, setShowUpload] = useState(false);

  // Automatic validation state
  const [validation, setValidation] = useState(freshValidation);

  // Analysis state
  const [analysisStatus, setAnalysisStatus] = useState('idle'); // idle | running | done
  const [run, setRun] = useState(null);
  const [findings, setFindings] = useState([]);
  const [requestError, setRequestError] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // M3 artifacts generated from this run's real findings.
  const [m3State, setM3State] = useState({
    runId: null,
    remediation: null,
    remediationStatus: 'idle', // idle | loading | ready | error
    remediationError: '',
    summary: null,
    summaryStatus: 'idle',
    summaryError: '',
  });
  const [m3Nonce, setM3Nonce] = useState(0);

  // Artifacts are latched to the run that produced them, so a new run derives a
  // fresh "loading" view during render instead of clearing six pieces of state
  // inside an effect (which caused an extra render and tripped the
  // set-state-in-effect lint rule).
  const activeRunId = run?.run_id || null;
  const m3 =
    m3State.runId === activeRunId
      ? m3State
      : {
          runId: activeRunId,
          remediation: null,
          remediationStatus: activeRunId ? 'loading' : 'idle',
          remediationError: '',
          summary: null,
          summaryStatus: activeRunId ? 'loading' : 'idle',
          summaryError: '',
        };
  const remediation = m3.remediation;
  const remediationStatus = m3.remediationStatus;
  const remediationError = m3.remediationError;
  const prSummary = m3.summary;
  const summaryStatus = m3.summaryStatus;
  const summaryError = m3.summaryError;

  // Request bookkeeping
  const seqRef = useRef(0);
  const validationAbortRef = useRef(null);
  const analysisAbortRef = useRef(null);
  const cacheRef = useRef(new Map());

  const filename = uploadedFile?.name || '';

  const classification = useMemo(
    () => classifyLanguage(code, filename, langChoice),
    [code, filename, langChoice]
  );

  // Editor + metrics language: explicit choice wins, otherwise the language the
  // backend confirmed (so validation and analysis can never disagree).
  const effectiveLanguage = useMemo(() => {
    if (langChoice !== 'auto') return langChoice;
    if (validation.language === 'java' || validation.language === 'python') {
      return validation.language;
    }
    return 'python';
  }, [langChoice, validation.language]);

  const codeMetrics = useMemo(
    () => calculateCodeMetrics(code, effectiveLanguage),
    [code, effectiveLanguage]
  );

  const sizeProblem = useMemo(() => {
    if (!code.trim()) return null;
    const bytes = new Blob([code]).size;
    const lines = code.split('\n').length;
    if (bytes > MAX_BYTES) {
      return `The submission is ${(bytes / 1024).toFixed(1)} KB — the analysis limit is 200 KB.`;
    }
    if (lines > MAX_LINES) {
      return `${lines} lines — the analysis limit is ${MAX_LINES} lines.`;
    }
    return null;
  }, [code]);

  const cacheKey = useMemo(() => {
    if (!code.trim()) return '';
    return `${langChoice}|${filename}|${code.length}|${hashSource(code)}`;
  }, [code, langChoice, filename]);

  const pushCache = useCallback((key, entry) => {
    const cache = cacheRef.current;
    cache.set(key, entry);
    while (cache.size > CACHE_LIMIT) {
      const oldest = cache.keys().next().value;
      cache.delete(oldest);
    }
  }, []);

  const startAnalysis = useCallback(async ({ source, language, cacheLanguage, seq }) => {
    const controller = new AbortController();
    analysisAbortRef.current = controller;

    setAnalysisStatus('running');
    setRequestError(null);

    try {
      const summary = await runAnalysis({ code: source, language, filename, signal: controller.signal });
      if (seq !== seqRef.current || controller.signal.aborted) return;

      setRun(summary);

      let list = [];
      try {
        const payload = await getFindings(summary.run_id, { signal: controller.signal });
        list = Array.isArray(payload?.findings) ? payload.findings : [];
      } catch (err) {
        if (seq !== seqRef.current || controller.signal.aborted || err?.kind === 'aborted') return;
        setFindings([]);
        setAnalysisStatus('done');
        setRequestError(
          err instanceof ApiError
            ? err
            : new ApiError('unexpected', 0, 'Could not load the findings list for this run.')
        );
        return;
      }

      if (seq !== seqRef.current || controller.signal.aborted) return;

      setFindings(list);
      setAnalysisStatus('done');
      pushCache(cacheKey, {
        code: source,
        language: cacheLanguage || language,
        filename,
        summary,
        findings: list,
      });
    } catch (err) {
      if (seq !== seqRef.current || controller.signal.aborted || err?.kind === 'aborted') return;
      setAnalysisStatus('idle');
      setRequestError(
        err instanceof ApiError
          ? err
          : new ApiError('unexpected', 0, `Unexpected error: ${err?.message || String(err)}`)
      );
    } finally {
      if (analysisAbortRef.current === controller) analysisAbortRef.current = null;
    }
  }, [filename, cacheKey, pushCache]);

  const runValidationAndAnalysis = useCallback(async ({ source, language, seq }) => {
    // A retry supersedes anything still in flight, including an earlier validation.
    validationAbortRef.current?.abort();
    const controller = new AbortController();
    validationAbortRef.current = controller;

    setValidation({ ...freshValidation(), status: 'validating' });
    setRequestError(null);

    let result;
    try {
      result = await validateSubmission({ code: source, language, signal: controller.signal });
    } catch (err) {
      if (seq !== seqRef.current || controller.signal.aborted || err?.kind === 'aborted') return;
      setValidation({
        ...freshValidation(),
        status: 'error',
        message:
          err instanceof ApiError
            ? err.message
            : `The validation service failed: ${err?.message || 'unknown error'}`,
      });
      setAnalysisStatus('idle');
      return;
    } finally {
      if (validationAbortRef.current === controller) validationAbortRef.current = null;
    }

    if (seq !== seqRef.current || controller.signal.aborted) return;

    if (result.valid) {
      setValidation({
        ...freshValidation(),
        status: 'accepted',
        language: result.language,
        languageName: result.languageName,
        warnings: result.warnings,
      });
      // Analyze exactly the language the backend accepted, so an auto-detected
      // run can never be validated as one language and analyzed as another.
      const resolvedLanguage =
        result.language === 'python' || result.language === 'java'
          ? result.language
          : language;
      await startAnalysis({
        source,
        language: resolvedLanguage,
        cacheLanguage: language,
        seq,
      });
      return;
    }

    setValidation({
      ...freshValidation(),
      status: 'rejected',
      language: result.language,
      languageName: result.languageName,
      rejectedLanguage: result.rejectedLanguage,
      hasMissingItem: result.hasMissingItem,
      errors: result.errors,
      warnings: result.warnings,
      issueCount: result.errors.length,
      message:
        result.message ||
        (result.rejectedLanguage
          ? `Detected ${result.languageName || 'an unsupported language'}. Only Python and Java are accepted.`
          : result.errors.length > 0
          ? `${result.errors.length} syntax ${result.errors.length === 1 ? 'issue' : 'issues'} found. Fix the reported lines and validation re-runs automatically.`
          : 'The backend rejected this code.'),
    });
    setAnalysisStatus('idle');
  }, [startAnalysis]);

  // Reset from the header action; bumping the token starts a clean workspace.
  const lastResetToken = useRef(resetToken);
  useEffect(() => {
    if (lastResetToken.current === resetToken) return;
    lastResetToken.current = resetToken;
    seqRef.current += 1;
    validationAbortRef.current?.abort();
    analysisAbortRef.current?.abort();
    cacheRef.current.clear();
    setCode('');
    setUploadedFile(null);
    setLangChoice('auto');
    setShowUpload(false);
    setValidation(freshValidation());
    setAnalysisStatus('idle');
    setRun(null);
    setFindings([]);
    setRequestError(null);
    setSelectedFinding(null);
  }, [resetToken]);

  // Retry is a user event, so marking the panels as loading here is legitimate;
  // the effect below only writes state after an await resolves.
  const retryM3 = useCallback(() => {
    setM3State((prev) => ({
      ...prev,
      remediationStatus: 'loading',
      remediationError: '',
      summaryStatus: 'loading',
      summaryError: '',
    }));
    setM3Nonce((n) => n + 1);
  }, []);

  // The automatic workflow. Any change to the analyzed inputs clears every
  // previous result immediately, then debounces validate -> analyze.
  useEffect(() => {
    const seq = seqRef.current + 1;
    seqRef.current = seq;

    validationAbortRef.current?.abort();
    analysisAbortRef.current?.abort();
    validationAbortRef.current = null;
    analysisAbortRef.current = null;

    setValidation(freshValidation());
    setAnalysisStatus('idle');
    setRun(null);
    setFindings([]);
    setRequestError(null);
    setSelectedFinding(null);

    if (!code.trim()) return undefined;

    if (sizeProblem) {
      setValidation({
        ...freshValidation(),
        status: 'error',
        message: `${sizeProblem} Nothing was sent to the backend.`,
      });
      return undefined;
    }

    const cached = cacheRef.current.get(cacheKey);
    if (cached && cached.code === code && cached.language === langChoice && cached.filename === filename) {
      setValidation({
        ...freshValidation(),
        status: 'accepted',
        language: cached.summary?.language || null,
        languageName: null,
      });
      setRun(cached.summary);
      setFindings(cached.findings);
      setAnalysisStatus('done');
      return undefined;
    }

    setValidation({ ...freshValidation(), status: 'validating' });

    const timer = setTimeout(() => {
      runValidationAndAnalysis({ source: code, language: langChoice, seq });
    }, DEBOUNCE_MS);

    return () => clearTimeout(timer);
    // `filename` and `cacheKey` derive from `uploadedFile`/`code`; listing them
    // keeps re-validation correct after uploads and language switches.
  }, [code, langChoice, filename, cacheKey, sizeProblem, runValidationAndAnalysis]);

  // M3: generate remediation, then the PR summary, from this run's findings.
  // Both come from the backend service layer; a failure leaves the M2 findings
  // untouched and surfaces an honest error in the corresponding panel. Every
  // state write happens after an await, so this effect never causes the
  // render-then-immediately-set-state cycle lint flags.
  useEffect(() => {
    const runId = run?.run_id;
    if (!runId) return undefined;

    let cancelled = false;
    const controller = new AbortController();
    const describe = (err) =>
      err instanceof ApiError
        ? err.message
        : `Unexpected error: ${err?.message || String(err)}`;

    (async () => {
      let remediationPayload = null;
      let nextRemediationStatus = 'ready';
      let nextRemediationError = '';
      try {
        const payload = await getRemediation(runId, { signal: controller.signal });
        remediationPayload = payload?.remediation || null;
      } catch (err) {
        if (cancelled || err?.kind === 'aborted') return;
        nextRemediationStatus = 'error';
        nextRemediationError = describe(err);
      }
      if (cancelled) return;

      setM3State((prev) => ({
        ...prev,
        runId,
        remediation: remediationPayload,
        remediationStatus: nextRemediationStatus,
        remediationError: nextRemediationError,
        summaryStatus: 'loading',
        summaryError: '',
      }));

      let summaryPayload = null;
      let nextSummaryStatus = 'ready';
      let nextSummaryError = '';
      try {
        const payload = await getPrSummary(runId, { signal: controller.signal });
        summaryPayload = payload?.summary || null;
      } catch (err) {
        if (cancelled || err?.kind === 'aborted') return;
        nextSummaryStatus = 'error';
        nextSummaryError = describe(err);
      }
      if (cancelled) return;

      setM3State({
        runId,
        remediation: remediationPayload,
        remediationStatus: nextRemediationStatus,
        remediationError: nextRemediationError,
        summary: summaryPayload,
        summaryStatus: nextSummaryStatus,
        summaryError: nextSummaryError,
      });
    })();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [run?.run_id, m3Nonce]);

  // Unmount cleanup: stop any request so nothing updates an unmounted tree.
  useEffect(() => () => {
    validationAbortRef.current?.abort();
    analysisAbortRef.current?.abort();
  }, []);

  const handleClear = () => {
    setCode('');
    setUploadedFile(null);
    setShowUpload(false);
  };

  const handleLoadSample = (sample) => {
    setCode(sample.code);
    setUploadedFile(
      sample.filename
        ? {
            name: sample.filename,
            size: new Blob([sample.code]).size,
            extension: sample.filename.split('.').pop(),
            content: sample.code,
          }
        : null
    );
  };

  const handleFileLoaded = (fileData) => {
    setUploadedFile(fileData);
    setCode(fileData.content);
  };

  const handleRemoveFile = () => {
    setUploadedFile(null);
  };

  const canRetry =
    Boolean(code.trim()) &&
    !sizeProblem &&
    validation.status === 'accepted' &&
    analysisStatus !== 'running';

  const retry = useCallback(() => {
    if (!code.trim() || sizeProblem) return;
    const seq = seqRef.current + 1;
    seqRef.current = seq;
    analysisAbortRef.current?.abort();
    setRun(null);
    setFindings([]);
    setSelectedFinding(null);
    setAnalysisStatus('idle');
    runValidationAndAnalysis({ source: code, language: langChoice, seq });
  }, [code, sizeProblem, langChoice, runValidationAndAnalysis]);

  // Per-finding remediation lookup for the detail panel (real agent output only).
  const remediationByFinding = useMemo(() => {
    const map = new Map();
    for (const item of remediation?.findings || []) {
      if (item?.finding_id) map.set(item.finding_id, item);
    }
    return map;
  }, [remediation]);

  const selectedRemediation = selectedFinding?.id
    ? remediationByFinding.get(selectedFinding.id) || null
    : null;

  const languageLabel = !code.trim()
    ? null
    : validation.languageName ||
      (validation.language
        ? validation.language.charAt(0).toUpperCase() + validation.language.slice(1)
        : langChoice !== 'auto'
        ? langChoice.charAt(0).toUpperCase() + langChoice.slice(1)
        : classification?.languageName);

  const emptyState = (() => {
    if (sizeProblem) {
      return {
        title: 'Submission too large',
        body: 'Reduce the code to the 200 KB / 2000 line limit. Automatic validation and analysis resume as soon as the source fits.',
      };
    }
    if (validation.status === 'error') {
      return {
        title: 'Validation service unavailable',
        body: 'Analysis cannot start until the backend confirms the code. Retry once the service is reachable — the code itself was not judged invalid.',
      };
    }
    if (validation.status === 'validating') {
      return {
        title: 'Validating the current code',
        body: 'Syntax validation runs automatically after you stop typing. Analysis starts only when the backend accepts the code.',
      };
    }
    if (validation.status === 'rejected') {
      return {
        title: 'Analysis held back',
        body: 'Invalid code is never sent to the AI pipeline. Fix the reported syntax issues and both steps run again automatically.',
      };
    }
    if (validation.status === 'accepted') {
      return {
        title: 'Analysis ready to run',
        body: 'The code passed validation — the multi-agent run will appear here as soon as it finishes.',
      };
    }
    return {
      title: 'No analysis yet',
      body: 'Paste Python or Java code (or load a sample inside the editor). Syntax validation starts automatically, and accepted code is analyzed by the real backend pipeline.',
    };
  })();

  return (
    <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Unified workspace banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-rose-950/30 to-slate-900 p-6 border border-slate-800 shadow-md">
        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-semibold mb-3">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Automatic Validation · Multi-Agent Quality &amp; Security Analysis</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            AI Code Analysis
          </h2>
          <p className="text-xs sm:text-sm text-slate-300 mt-2 leading-relaxed">
            Submit Python or Java source once. It is validated automatically, then the parallel{' '}
            <strong className="text-rose-300">Code Analysis Agent</strong> and{' '}
            <strong className="text-rose-300">Security Vulnerability Agent</strong> inspect it.
            Analysis is purely static — submitted code is <strong>never executed</strong>.
          </p>
        </div>
      </div>

      <RequestErrorBanner
        error={requestError}
        onDismiss={() => setRequestError(null)}
        onRetry={canRetry ? retry : undefined}
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: input + results */}
        <div className="lg:col-span-8 space-y-4">
          {/* Language + input source controls */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800 self-start text-xs font-semibold">
              <Languages className="w-3.5 h-3.5 text-indigo-400 mx-2 shrink-0" />
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

            <div className="flex flex-wrap items-center gap-2">
              {uploadedFile && (
                <div className="flex items-center gap-2 text-[11px] text-slate-400 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5">
                  <FileCode className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                  <span className="font-mono text-slate-200 max-w-[14rem] truncate">
                    {uploadedFile.name}
                  </span>
                  <button
                    type="button"
                    onClick={handleRemoveFile}
                    aria-label="Remove uploaded file"
                    className="text-slate-500 hover:text-rose-400"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
              <button
                type="button"
                onClick={() => setShowUpload((v) => !v)}
                className="inline-flex items-center gap-2 text-xs font-semibold px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 transition-colors"
                aria-expanded={showUpload}
              >
                <UploadCloud className="w-3.5 h-3.5" />
                {showUpload ? 'Hide Upload' : 'Upload File'}
              </button>
            </div>
          </div>

          {langChoice === 'auto' && <LanguageSelector classification={classification} />}

          {(showUpload || uploadedFile) && (
            <FileUploadZone
              uploadedFile={uploadedFile}
              onFileLoaded={handleFileLoaded}
              onRemoveFile={handleRemoveFile}
            />
          )}

          <CodeEditor
            code={code}
            language={effectiveLanguage}
            onChangeCode={setCode}
            onClear={handleClear}
            onLoadSample={handleLoadSample}
            errors={validation.status === 'rejected' ? validation.errors : []}
            metrics={codeMetrics}
          />

          <ValidationStatusBar
            status={validation.status}
            message={validation.message}
            languageLabel={languageLabel}
            issueCount={validation.issueCount}
            onRetry={code.trim() && !sizeProblem ? retry : undefined}
          />

          {analysisStatus === 'running' && (
            <div
              role="status"
              className="flex items-center gap-2.5 rounded-lg border border-indigo-500/40 bg-indigo-950/50 px-3.5 py-2.5 text-xs text-indigo-200"
            >
              <Activity className="w-4 h-4 animate-spin shrink-0 text-indigo-400" />
              <span>
                Running the existing validation and analysis pipeline — the quality and security
                agents are analyzing the accepted code in parallel (static only). Results appear as
                soon as the backend reports a terminal status.
              </span>
            </div>
          )}

          {run && <AnalysisSummaryCard run={run} findingsCount={findings.length} />}

          {run && <HealthScoreCard health={run.health} runStatus={run.status} />}

          {run && (
            <ReportExportBar
              runId={run.run_id}
              runStatus={run.status}
              disabled={remediationStatus === 'loading'}
            />
          )}

          {run && (
            <FindingsTable
              findings={findings}
              onViewDetails={setSelectedFinding}
              selectedFindingId={selectedFinding?.id}
              runStatus={run.status}
            />
          )}

          {!run && analysisStatus !== 'running' && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center space-y-2">
              <FlaskConical className="w-9 h-9 text-slate-600 mx-auto" />
              <h3 className="text-sm font-bold text-slate-300">{emptyState.title}</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto">{emptyState.body}</p>
            </div>
          )}
        </div>

        {/* Right: finding details */}
        <div className="lg:col-span-4 space-y-4 lg:sticky lg:top-6">
          {selectedFinding ? (
            <FindingDetails
              finding={selectedFinding}
              onClose={() => setSelectedFinding(null)}
              remediation={selectedRemediation}
              remediationState={remediationStatus}
              remediationError={remediationError}
              onRetryRemediation={retryM3}
            />
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

          {run && remediation && (
            <RemediationOverview remediation={remediation} />
          )}
        </div>
      </div>

      {run && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-7">
            <PrSummaryPanel
              summary={prSummary}
              state={summaryStatus}
              error={summaryError}
              onRetry={retryM3}
            />
          </div>
          <div className="lg:col-span-5">
            <AssistantPanel
              runId={run.run_id}
              selectedFindingId={selectedFinding?.id || null}
              onSelectFinding={(id) => {
                const match = findings.find((f) => f.id === id);
                if (match) setSelectedFinding(match);
              }}
            />
          </div>
        </div>
      )}
    </main>
  );
}
