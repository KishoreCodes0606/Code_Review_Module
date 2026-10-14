import React, { useState, useEffect } from 'react';
import {
  X,
  Play,
  CheckCircle2,
  Cpu,
  ShieldCheck,
  Wrench,
  FileCheck2,
  MessageSquare,
  Sparkles,
  ArrowRight
} from 'lucide-react';

export default function PipelineSimulationModal({
  isOpen,
  onClose,
  submission
}) {
  const [currentStep, setCurrentStep] = useState(0);
  const [isFinished, setIsFinished] = useState(false);

  const steps = [
    {
      agent: 'Preprocessor & Parser',
      role: 'AST generation & deterministic metrics calculation',
      details: `Parsing AST for ${submission?.language?.toUpperCase()} (AST Tree constructed, metrics computed).`
    },
    {
      agent: 'Agent 1: Code Analysis Agent',
      role: 'Code smells, design anti-patterns, cyclomatic complexity',
      details: 'Analyzing function lengths, nesting depths, smell catalog (Bloaters, Dispensables).'
    },
    {
      agent: 'Agent 2: Security Vulnerability Agent',
      role: 'OWASP Top 10 & CWE vulnerability scanner',
      details: 'Deterministic regex/AST sink scan + LLM semantic confirmation (SQLi, XSS, Command Inj).'
    },
    {
      agent: 'Agent 3: Remediation Agent',
      role: 'RAG-grounded fix generation with source citations',
      details: 'Retrieving secure coding guidelines & chunked remediation templates from ChromaDB.'
    },
    {
      agent: 'Agent 4: PR Summary Agent',
      role: 'Review summary compilation & severity scoring',
      details: 'Compiling findings into pull-request format with CVSS severity scoring & action roadmap.'
    }
  ];

  useEffect(() => {
    if (!isOpen) {
      setCurrentStep(0);
      setIsFinished(false);
      return;
    }

    const timer = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev < steps.length - 1) {
          return prev + 1;
        } else {
          setIsFinished(true);
          clearInterval(timer);
          return prev;
        }
      });
    }, 1200);

    return () => clearInterval(timer);
  }, [isOpen]);

  if (!isOpen || !submission) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">
                Multi-Agent Pipeline Dispatch (Simulated)
              </h3>
              <p className="text-[11px] text-slate-400">
                Submission {submission.id.slice(0, 8)} successfully ingested by Module 1
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Pipeline Progression */}
        <div className="p-6 space-y-4">
          <div className="space-y-3">
            {steps.map((step, idx) => {
              const isCompleted = isFinished || currentStep > idx;
              const isCurrent = !isFinished && currentStep === idx;

              return (
                <div
                  key={idx}
                  className={`p-3 rounded-xl border transition-all ${
                    isCurrent
                      ? 'bg-indigo-950/30 border-indigo-500/60 scale-[1.01]'
                      : isCompleted
                      ? 'bg-slate-950/60 border-emerald-500/30'
                      : 'bg-slate-950/30 border-slate-800/60 opacity-40'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2.5">
                      <div
                        className={`w-6 h-6 rounded-md flex items-center justify-center text-[11px] font-bold ${
                          isCompleted
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : isCurrent
                            ? 'bg-indigo-600 text-white animate-pulse'
                            : 'bg-slate-800 text-slate-500'
                        }`}
                      >
                        {isCompleted ? <CheckCircle2 className="w-3.5 h-3.5" /> : idx + 1}
                      </div>

                      <div>
                        <span className="font-semibold text-slate-200">{step.agent}</span>
                        <div className="text-[10px] text-slate-400">{step.role}</div>
                      </div>
                    </div>

                    <span className="text-[10px] font-mono">
                      {isCompleted ? (
                        <span className="text-emerald-400 font-bold">DONE</span>
                      ) : isCurrent ? (
                        <span className="text-indigo-400 font-bold animate-pulse">RUNNING...</span>
                      ) : (
                        <span className="text-slate-600">QUEUED</span>
                      )}
                    </span>
                  </div>

                  {isCurrent && (
                    <div className="mt-2 text-[11px] text-indigo-300/90 bg-indigo-950/50 p-2 rounded border border-indigo-500/20 font-mono">
                      {step.details}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {isFinished && (
            <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center justify-between">
              <div>
                <span className="font-bold">Pipeline Execution Complete!</span>
                <p className="text-[11px] text-slate-300 mt-0.5">
                  Submission data model successfully verified and handed over to downstream inspection agents.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-950/80 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition-colors"
          >
            Close Simulation
          </button>
        </div>
      </div>
    </div>
  );
}
