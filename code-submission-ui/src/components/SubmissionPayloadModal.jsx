import React, { useState } from 'react';
import {
  X,
  Copy,
  Check,
  Download,
  Terminal,
  Layers,
  ArrowRight,
  ShieldCheck,
  Cpu,
  FileText,
  MessageSquare
} from 'lucide-react';

export default function SubmissionPayloadModal({
  isOpen,
  onClose,
  submissionPayload
}) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('json'); // 'json' | 'pipeline'

  if (!isOpen || !submissionPayload) return null;

  const jsonString = JSON.stringify(submissionPayload, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `submission-${submissionPayload.id.slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                Submission Entity Payload (Data Model)
              </h2>
              <p className="text-xs text-slate-400">
                Standardized System Data Model Schema
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex items-center px-6 pt-3 border-b border-slate-800 bg-slate-950/30 gap-4 text-xs font-semibold">
          <button
            type="button"
            onClick={() => setActiveTab('json')}
            className={`pb-2.5 transition-colors border-b-2 ${
              activeTab === 'json'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Standardized JSON Schema
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('pipeline')}
            className={`pb-2.5 transition-colors border-b-2 ${
              activeTab === 'pipeline'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Multi-Agent Pipeline Handoff
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto flex-1 font-mono text-xs">
          {activeTab === 'json' ? (
            <div className="relative">
              <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-slate-200 overflow-x-auto leading-relaxed">
                {jsonString}
              </pre>
            </div>
          ) : (
            <div className="space-y-4 font-sans text-xs">
              <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/30 text-slate-300 space-y-1">
                <span className="font-bold text-indigo-400">
                  Orchestrator Shared State (PipelineState)
                </span>
                <p className="text-slate-400">
                  Upon valid syntax confirmation, this submission enters the Orchestrator with status <code className="text-emerald-400 font-mono">QUEUED</code> and dispatches the multi-agent pipeline:
                </p>
              </div>

              {/* 5 Agents visual flow */}
              <div className="space-y-2.5">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-7 h-7 rounded bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold">1</div>
                    <div>
                      <div className="font-semibold text-slate-200">Agent 1: Code Analysis Agent</div>
                      <div className="text-[11px] text-slate-400">Detects code smells, complexity metrics (radon/ast), design anti-patterns.</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-blue-500/20 text-blue-300 font-mono">FAN-OUT 1</span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-7 h-7 rounded bg-rose-500/10 text-rose-400 flex items-center justify-center font-bold">2</div>
                    <div>
                      <div className="font-semibold text-slate-200">Agent 2: Security Vulnerability Agent</div>
                      <div className="text-[11px] text-slate-400">Scans OWASP Top 10 (SQLi, XSS, CSRF, secrets, auth) with CWE tags & severity.</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 font-mono">FAN-OUT 2</span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-7 h-7 rounded bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold">3</div>
                    <div>
                      <div className="font-semibold text-slate-200">Agent 3: Remediation Agent (RAG-Grounded)</div>
                      <div className="text-[11px] text-slate-400">Queries ChromaDB vector knowledge base for exact code fixes with citations.</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 font-mono">FAN-IN</span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-7 h-7 rounded bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold">4</div>
                    <div>
                      <div className="font-semibold text-slate-200">Agent 4: PR Summary Agent</div>
                      <div className="text-[11px] text-slate-400">Produces human-readable PR review summary, verdict, and prioritized roadmap.</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 font-mono">SUMMARY</span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-7 h-7 rounded bg-cyan-500/10 text-cyan-400 flex items-center justify-center font-bold">5</div>
                    <div>
                      <div className="font-semibold text-slate-200">Agent 5: Conversational Code Assistant</div>
                      <div className="text-[11px] text-slate-400">Interactive chat over findings, explanations, and secure coding guidelines.</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-300 font-mono">INTERACTIVE</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-3.5 border-t border-slate-800 bg-slate-950/80">
          <div className="text-xs text-slate-500 font-mono">
            ID: {submissionPayload.id.slice(0, 18)}...
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              {copied ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>

            <button
              type="button"
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
