import React, { useRef, useState, useEffect } from 'react';
import {
  Clipboard,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Sparkles,
  FileCode,
  BookOpen
} from 'lucide-react';
import { SAMPLE_CODES } from '../data/sampleCodes';

export default function CodeEditor({
  code,
  language,
  onChangeCode,
  onValidate,
  onClear,
  onLoadSample,
  errors = [],
  isValidating = false,
  metrics
}) {
  const textareaRef = useRef(null);
  const [cursorPos, setCursorPos] = useState({ line: 1, col: 1 });
  const [selectedSample, setSelectedSample] = useState('');

  // Extract set of error lines for quick gutter marker
  const errorLineSet = new Set(errors.map(err => err.line));

  const lines = code ? code.split('\n') : [''];
  const lineCount = lines.length;

  const handleCursorMove = (e) => {
    const textarea = e.target;
    const textBeforeCursor = textarea.value.substring(0, textarea.selectionStart);
    const lineIndex = textBeforeCursor.split('\n').length;
    const lastNewlinePos = textBeforeCursor.lastIndexOf('\n');
    const colIndex = textarea.selectionStart - lastNewlinePos;
    setCursorPos({ line: lineIndex, col: colIndex });
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        onChangeCode(text);
      }
    } catch {
      // In case clipboard permission is denied, focus textarea
      textareaRef.current?.focus();
    }
  };

  const handleSampleChange = (e) => {
    const sampleId = e.target.value;
    setSelectedSample(sampleId);
    if (!sampleId) return;

    const sample = SAMPLE_CODES.find(s => s.id === sampleId);
    if (sample) {
      onLoadSample(sample);
    }
  };

  // Keyboard shortcut Ctrl+Enter / Cmd+Enter to validate
  const handleKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      onValidate();
    }
    // Handle tab key in code editor
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = e.target.selectionStart;
      const end = e.target.selectionEnd;
      const indent = '    ';
      const newCode = code.substring(0, start) + indent + code.substring(end);
      onChangeCode(newCode);
      setTimeout(() => {
        if (textareaRef.current) {
          textareaRef.current.selectionStart = textareaRef.current.selectionEnd = start + 4;
        }
      }, 0);
    }
  };

  return (
    <div className="flex flex-col rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl overflow-hidden">
      {/* Editor Top Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 bg-slate-950/70 border-b border-slate-800 text-xs">
        {/* Left: Code status & preset selector */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-slate-300 font-medium">
            <FileCode className="w-4 h-4 text-indigo-400" />
            <span>Editor</span>
          </div>

          <div className="h-4 w-px bg-slate-800 hidden sm:block"></div>

          {/* Sample Snippet Selector */}
          <div className="flex items-center gap-1.5">
            <BookOpen className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={selectedSample}
              onChange={handleSampleChange}
              className="bg-slate-900 border border-slate-700/80 rounded-md px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="">-- Load Sample Test Case --</option>
              <optgroup label="✅ Accepted: Python Code">
                <option value="py-sqli-valid">🐍 Python: SQL Injection (Valid Syntax)</option>
                <option value="py-syntax-err">🐍 Python: Syntax Error (Missing colon)</option>
              </optgroup>
              <optgroup label="✅ Accepted: Java Code">
                <option value="java-sqli-valid">☕ Java: SQL Injection Concatenation (Valid Syntax)</option>
                <option value="java-syntax-err">☕ Java: Syntax Error (Missing semicolon)</option>
              </optgroup>
              <optgroup label="🚫 Rejected: Unsupported Languages">
                <option value="reject-javascript">🚫 JavaScript / Node (Rejected)</option>
                <option value="reject-cpp">🚫 C++ Code (Rejected)</option>
                <option value="reject-html">🚫 HTML Markup (Rejected)</option>
              </optgroup>
            </select>
          </div>
        </div>

        {/* Right: Quick actions */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handlePasteClipboard}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            title="Paste from clipboard"
          >
            <Clipboard className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Paste</span>
          </button>

          <button
            type="button"
            onClick={onClear}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-rose-900/30 text-slate-300 hover:text-rose-300 transition-colors"
            title="Clear code"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Clear</span>
          </button>

          <button
            type="button"
            onClick={onValidate}
            disabled={isValidating || !code.trim()}
            className={`flex items-center gap-1.5 px-3.5 py-1 rounded-md font-semibold text-xs shadow transition-all ${
              !code.trim()
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                : isValidating
                ? 'bg-indigo-700 text-indigo-200 cursor-wait'
                : 'bg-indigo-600 hover:bg-indigo-500 text-white'
            }`}
            title="Run syntax validation (Ctrl+Enter)"
          >
            {isValidating ? (
              <RotateCcw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            <span>Validate Syntax</span>
            <span className="hidden lg:inline text-[10px] text-indigo-200 font-mono font-normal">
              (Ctrl+↵)
            </span>
          </button>
        </div>
      </div>

      {/* Editor Body: Line numbers + Textarea */}
      <div className="relative flex font-mono text-sm leading-relaxed min-h-[360px] max-h-[540px] bg-slate-950 overflow-hidden">
        {/* Line Numbers Gutter */}
        <div className="select-none py-3 px-3 bg-slate-950 border-r border-slate-800/80 text-right text-slate-600 text-xs overflow-hidden shrink-0">
          {lines.map((_, i) => {
            const lineNum = i + 1;
            const hasError = errorLineSet.has(lineNum);
            return (
              <div
                key={lineNum}
                className={`h-6 flex items-center justify-end gap-1 px-1 rounded ${
                  hasError
                    ? 'text-rose-400 font-bold bg-rose-500/10'
                    : lineNum === cursorPos.line
                    ? 'text-slate-300'
                    : ''
                }`}
              >
                {hasError && <span className="text-[10px] text-rose-500">●</span>}
                <span className="w-6">{lineNum}</span>
              </div>
            );
          })}
        </div>

        {/* Textarea */}
        <textarea
          ref={textareaRef}
          value={code}
          onChange={(e) => onChangeCode(e.target.value)}
          onKeyUp={handleCursorMove}
          onClick={handleCursorMove}
          onKeyDown={handleKeyDown}
          placeholder={`// Paste your ${language === 'python' ? 'Python (.py)' : 'Java (.java)'} code here, or choose a sample above...\n\n# Example:\ndef inspect_data(payload):\n    return process(payload)`}
          spellCheck={false}
          className="flex-1 w-full py-3 px-4 bg-transparent text-slate-100 placeholder-slate-600 resize-none focus:outline-none overflow-y-auto leading-6 whitespace-pre font-mono selection:bg-indigo-600 selection:text-white"
        />
      </div>

      {/* Editor Bottom Status Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 bg-slate-950 border-t border-slate-800/80 text-[11px] text-slate-400">
        <div className="flex items-center gap-4">
          <span className="font-mono">
            Ln {cursorPos.line}, Col {cursorPos.col}
          </span>
          <span className="text-slate-600">|</span>
          <span
            className={`font-mono ${
              lineCount > 2000 ? 'text-amber-400 font-semibold' : ''
            }`}
          >
            {lineCount.toLocaleString()} / 2,000 lines
          </span>
          <span className="text-slate-600">|</span>
          <span
            className={`font-mono ${
              metrics?.sizeBytes > 200 * 1024 ? 'text-amber-400 font-semibold' : ''
            }`}
          >
            {((metrics?.sizeBytes || 0) / 1024).toFixed(1)} KB / 200 KB
          </span>
        </div>

        <div className="flex items-center gap-3">
          {errorLineSet.size > 0 && (
            <span className="flex items-center gap-1 text-rose-400 font-medium">
              <AlertTriangle className="w-3.5 h-3.5" />
              {errorLineSet.size} syntax {errorLineSet.size === 1 ? 'error' : 'errors'}
            </span>
          )}
          <span className="text-slate-500 uppercase tracking-wider font-semibold">
            UTF-8 · LF
          </span>
        </div>
      </div>
    </div>
  );
}
