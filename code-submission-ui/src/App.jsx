import React, { useState, useEffect, useMemo } from 'react';
import Header from './components/Header';
import AnalysisWorkspace from './components/analysis/AnalysisWorkspace';
import { Code2, FileSearch } from 'lucide-react';
import LanguageSelector from './components/LanguageSelector';
import FileUploadZone from './components/FileUploadZone';
import CodeEditor from './components/CodeEditor';
import ValidationResultCard from './components/ValidationResultCard';
import SubmissionPayloadModal from './components/SubmissionPayloadModal';
import PipelineSimulationModal from './components/PipelineSimulationModal';
import SubmissionHistory from './components/SubmissionHistory';
import {
  validatePython,
  validateJava,
  calculateCodeMetrics,
  computeSHA256,
  generateUUID
} from './utils/syntaxValidator';
import { classifyLanguage } from './utils/languageClassifier';
import { SAMPLE_CODES } from './data/sampleCodes';
import { FileText, Upload, Info, ShieldCheck } from 'lucide-react';

export default function App() {
  // Module-level navigation: M1 submission / M2 analysis. Both sections stay
  // mounted (hidden with CSS) so neither loses state when you switch tabs.
  const [activeModule, setActiveModule] = useState('submission'); // 'submission' | 'analysis'

  // Input state
  const [activeTab, setActiveTab] = useState('paste'); // 'paste' | 'upload'
  const [code, setCode] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);

  // Dynamic language classification & gatekeeper (auto-detect)
  const classification = useMemo(() => {
    return classifyLanguage(code, uploadedFile?.name, 'auto');
  }, [code, uploadedFile]);

  // Validation & metrics state
  const [validationResult, setValidationResult] = useState(null);
  const [isValidating, setIsValidating] = useState(false);
  const [codeMetrics, setCodeMetrics] = useState(null);
  const [submissionPayload, setSubmissionPayload] = useState(null);

  // Modals state
  const [showPayloadModal, setShowPayloadModal] = useState(false);
  const [showSimulationModal, setShowSimulationModal] = useState(false);

  // Local storage history
  const [history, setHistory] = useState(() => {
    try {
      const saved = localStorage.getItem('code_submissions_history');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  // Effective language for metrics & parser
  const currentLanguage = classification.language === 'java' ? 'java' : 'python';

  // Recalculate metrics when code or language changes
  useEffect(() => {
    let isCancelled = false;

    async function updateMetrics() {
      const baseMetrics = calculateCodeMetrics(code, currentLanguage);
      const hash = await computeSHA256(code || '');

      if (!isCancelled) {
        setCodeMetrics({
          ...baseMetrics,
          hash
        });
      }
    }

    updateMetrics();

    return () => {
      isCancelled = true;
    };
  }, [code, currentLanguage]);

  // Save history to localStorage
  const saveToHistory = (payload) => {
    setHistory((prev) => {
      const updated = [payload, ...prev.filter((p) => p.code_hash !== payload.code_hash)].slice(0, 10);
      try {
        localStorage.setItem('code_submissions_history', JSON.stringify(updated));
      } catch (e) {
        console.error('Failed to save to localStorage', e);
      }
      return updated;
    });
  };

  // Perform language verification and syntax validation
  const handleValidate = async () => {
    if (!code.trim()) {
      setValidationResult({
        valid: false,
        rejectedCode: true,
        hasMissingItem: true,
        rejectionReason: 'empty_input',
        errors: [
          {
            line: 1,
            col: 1,
            message: 'SyntaxError: Empty code submission',
            rule: 'empty_code',
            snippet: '',
            isMissingItem: true,
            missingItem: 'code content',
            missingDetail: 'Please paste code or load a sample test case first.',
            hint: 'Please paste code or load a sample test case first.'
          }
        ],
        warnings: []
      });
      return;
    }

    setIsValidating(true);

    // STEP 1: GATEKEEPER CHECK - IS IT PYTHON OR JAVA?
    if (!classification.isAcceptable) {
      setIsValidating(false);
      setValidationResult({
        valid: false,
        rejectedLanguage: true,
        rejectedCode: true,
        hasMissingItem: false,
        rejectionReason: 'unsupported_language',
        errors: [
          {
            line: 1,
            col: 1,
            message: `Code rejected: Unsupported language (${classification.languageName}). This module accepts only Python and Java.`,
            rule: 'unsupported_language',
            snippet: code.split('\n')[0] || '',
            isMissingItem: false,
            missingItem: null,
            missingDetail: null,
            hint: 'Replace code with Python (.py) or Java (.java) source.'
          }
        ],
        warnings: []
      });
      return;
    }

    // STEP 2: CODE BELONGS TO PYTHON OR JAVA -> PROCEED WITH SYNTAX VALIDATION
    let result;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1000);
      const resp = await fetch('http://localhost:8000/api/submissions/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, language: currentLanguage }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (resp.ok || resp.status === 422) {
        const data = await resp.json();
        const hasMissing = Boolean(data.has_missing_item || (data.errors && data.errors.some(e => e.is_missing_item || e.isMissingItem)));
        result = {
          valid: data.valid,
          rejectedCode: Boolean(data.rejected_code || !data.valid),
          rejectionReason: data.rejection_reason || (hasMissing ? 'missing_item' : 'incorrect_code'),
          hasMissingItem: hasMissing,
          errors: data.errors || [],
          warnings: data.warnings || []
        };
      } else {
        result = currentLanguage === 'python' ? validatePython(code) : validateJava(code);
      }
    } catch {
      // Backend not running or offline: high-fidelity client-side parser
      result = currentLanguage === 'python' ? validatePython(code) : validateJava(code);
    }

    setValidationResult(result);
    setIsValidating(false);

    // STEP 3: CREATE SUBMISSION PAYLOAD
    const hash = await computeSHA256(code);
    const payload = {
      id: generateUUID(),
      source_type: activeTab === 'upload' ? 'upload' : 'paste',
      filename: uploadedFile ? uploadedFile.name : null,
      language: currentLanguage,
      code: code,
      code_hash: hash,
      line_count: code.split('\n').length,
      size_bytes: new Blob([code]).size,
      syntax_valid: result.valid,
      rejected_code: Boolean(result.rejectedCode),
      rejection_reason: result.rejectionReason,
      has_missing_item: Boolean(result.hasMissingItem),
      syntax_errors: result.errors.map((e) => ({
        line: e.line,
        col: e.col,
        message: e.message,
        is_missing_item: Boolean(e.is_missing_item || e.isMissingItem),
        missing_item: e.missing_item || e.missingItem || null,
        missing_detail: e.missing_detail || e.missingDetail || null,
        hint: e.hint || null
      })),
      created_at: new Date().toISOString()
    };

    setSubmissionPayload(payload);
    saveToHistory(payload);
  };

  // Handle file loaded
  const handleFileLoaded = (fileData) => {
    setUploadedFile(fileData);
    setCode(fileData.content);
  };

  // Remove uploaded file
  const handleRemoveFile = () => {
    setUploadedFile(null);
  };

  // Load sample code
  const handleLoadSample = (sample) => {
    setCode(sample.code);
    setUploadedFile({
      name: sample.filename,
      size: new Blob([sample.code]).size,
      extension: sample.filename.split('.').pop(),
      content: sample.code
    });
  };

  // Reset editor
  const handleReset = () => {
    setCode('');
    setUploadedFile(null);
    setValidationResult(null);
    setSubmissionPayload(null);
  };

  // Load from submission history
  const handleLoadFromHistory = (item) => {
    setCode(item.code);
    if (item.filename) {
      setUploadedFile({
        name: item.filename,
        size: item.size_bytes,
        extension: item.filename.split('.').pop(),
        content: item.code
      });
      setActiveTab('upload');
    } else {
      setUploadedFile(null);
      setActiveTab('paste');
    }
    setSubmissionPayload(item);
    setValidationResult({
      valid: item.syntax_valid,
      errors: item.syntax_errors || [],
      warnings: []
    });
  };

  // Clear history
  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('code_submissions_history');
    } catch {}
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-indigo-500 selection:text-white">
      {/* Top Header */}
      <Header onReset={handleReset} />

      {/* Module switcher: M1 submission (existing) / M2 AI analysis (new) */}
      <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800 w-fit text-xs font-semibold">
          <button
            type="button"
            onClick={() => setActiveModule('submission')}
            aria-pressed={activeModule === 'submission'}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
              activeModule === 'submission'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileSearch className="w-4 h-4" />
            <span>Code Submission / Syntax Validation</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveModule('analysis')}
            aria-pressed={activeModule === 'analysis'}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
              activeModule === 'analysis'
                ? 'bg-rose-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-4 h-4" />
            <span>AI Code Analysis (M2)</span>
          </button>
        </div>
      </div>

      {/* M1 module — remains mounted while hidden so state is not destroyed */}
      <div className={activeModule === 'submission' ? 'contents' : 'hidden'}>
      {/* Main Workspace Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Module Banner / Introduction */}
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 p-6 border border-slate-800 shadow-md">
          <div className="relative z-10 max-w-3xl">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-semibold mb-3">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Language Gatekeeper & Code Submission Gateway</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Code Submission & Language Validation Module
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 mt-2 leading-relaxed">
              Place your piece of code via direct paste or file upload. The module strictly accepts code only from{' '}
              <strong className="text-yellow-400">Python (.py)</strong> and{' '}
              <strong className="text-orange-400">Java (.java)</strong>. If the code belongs to Python or Java, it verifies that the syntax is acceptable. If the code is from any other language, it is immediately rejected with a clear explanation.
            </p>
          </div>
        </div>

        {/* Input Controls & Configuration */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Main Left Section: Input tabs & Code Editor (8 cols) */}
          <div className="lg:col-span-8 space-y-4">
            {/* Input Method Selector Tabs + Language Selector */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
              {/* Method Switcher Tabs */}
              <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800 self-start text-xs font-semibold">
                <button
                  type="button"
                  onClick={() => setActiveTab('paste')}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                    activeTab === 'paste'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileText className="w-4 h-4" />
                  <span>Direct Code Paste</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('upload')}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                    activeTab === 'upload'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Upload className="w-4 h-4" />
                  <span>File Upload</span>
                </button>
              </div>

              {/* Language Selector */}
              <LanguageSelector
                classification={classification}
              />
            </div>

            {/* If Upload Tab is active, show the file drag and drop zone */}
            {activeTab === 'upload' && (
              <FileUploadZone
                uploadedFile={uploadedFile}
                onFileLoaded={handleFileLoaded}
                onRemoveFile={handleRemoveFile}
              />
            )}

            {/* Code Editor with Line Numbers, Status Bar & Quick Actions */}
            <CodeEditor
              code={code}
              language={currentLanguage}
              onChangeCode={setCode}
              onValidate={handleValidate}
              onClear={handleReset}
              onLoadSample={handleLoadSample}
              errors={validationResult?.errors || []}
              isValidating={isValidating}
              metrics={codeMetrics}
            />
          </div>

          {/* Right Section: Validation Results & Actions & History (4 cols) */}
          <div className="lg:col-span-4 space-y-5">
            {/* Validation Outcome Card */}
            <ValidationResultCard
              classification={classification}
              validationResult={validationResult}
              metrics={codeMetrics}
              sourceType={activeTab}
              filename={uploadedFile?.name}
              onOpenPayloadModal={() => setShowPayloadModal(true)}
              onSubmitToPipeline={() => setShowSimulationModal(true)}
            />

            {/* Submission History */}
            <SubmissionHistory
              history={history}
              onLoadSubmission={handleLoadFromHistory}
              onClearHistory={handleClearHistory}
            />

            {/* Ingestion Rules Card */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 text-xs space-y-2">
              <div className="flex items-center gap-1.5 font-bold text-slate-300">
                <Info className="w-4 h-4 text-indigo-400 shrink-0" />
                <span>Language Gatekeeper & Validation Rules</span>
              </div>
              <p className="text-slate-400 leading-relaxed text-[11px]">
                This module accepts source code exclusively in <strong className="text-yellow-400">Python (.py)</strong> and <strong className="text-orange-400">Java (.java)</strong>. Code originating from any other language (JavaScript, C/C++, C#, PHP, HTML, etc.) is rejected immediately. Accepted code is validated for AST syntax correctness before proceeding to security and quality inspection.
              </p>
            </div>
          </div>
        </div>
      </main>
      </div>

      {/* M2 AI Code Analysis module — also kept mounted so runs survive tab switches */}
      <div className={activeModule === 'analysis' ? 'contents' : 'hidden'}>
        <AnalysisWorkspace />
      </div>

      {/* Submission Entity Schema Modal */}
      <SubmissionPayloadModal
        isOpen={showPayloadModal && activeModule === 'submission'}
        onClose={() => setShowPayloadModal(false)}
        submissionPayload={submissionPayload}
      />

      {/* Multi-Agent Pipeline Simulation Modal */}
      <PipelineSimulationModal
        isOpen={showSimulationModal && activeModule === 'submission'}
        onClose={() => setShowSimulationModal(false)}
        submission={submissionPayload}
      />

      {/* Bottom Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-center text-xs text-slate-500">
        AI Code Review & Security Analysis Agent · Smart Code Inspection Platform
      </footer>
    </div>
  );
}
