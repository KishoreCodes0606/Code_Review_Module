import React, { useCallback, useRef, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  Bot,
  CornerDownLeft,
  Loader2,
  MessageSquare,
  Send,
  User,
} from 'lucide-react';
import { ApiError, askAssistant } from '../../utils/analysisApi';

/**
 * Conversational code assistant (M3 RAG).
 *
 * Every answer comes from `agents/assistant_agent.py`:
 *   { answer, mode: 'retrieval_only'|'llm'|..., grounded, citations: [{ index, title,
 *     section, source, url, owasp, cwe, excerpt }], knowledge_base: { available,
 *     message }, analysis_references, history }
 *
 * Honest states that must stay visible:
 *  - grounded === false  -> the KB had no matching passage and the answer says so;
 *  - knowledge_base.message -> why no passage matched;
 *  - citations are exactly the retrieved chunks, never invented in the browser.
 */

function CitationList({ citations }) {
  if (!Array.isArray(citations) || citations.length === 0) return null;
  return (
    <div className="mt-2 space-y-1.5">
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
        <BookOpen className="w-3 h-3" /> Sources
      </span>
      <ul className="space-y-1.5">
        {citations.map((c, i) => (
          <li
            key={`${c.chunk_id || c.source}-${c.index ?? i}`}
            className="rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-2"
          >
            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="font-mono text-indigo-300">[{c.index ?? i + 1}]</span>
              <span className="font-semibold text-slate-200">{c.title}</span>
              {c.section && <span className="text-slate-500">› {c.section}</span>}
              {c.language && (
                <span className="px-1.5 py-0.5 rounded border border-slate-700 text-[9px] font-mono text-slate-400">
                  {c.language}
                </span>
              )}
            </div>
            {c.excerpt && (
              <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">{c.excerpt}</p>
            )}
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] font-mono text-slate-600">
              <span>{c.source}</span>
              {Array.isArray(c.cwe) && c.cwe.length > 0 && <span>{c.cwe.join(', ')}</span>}
              {c.owasp && <span>{c.owasp}</span>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Message({ message, onSelectFinding }) {
  const isUser = message.role === 'user';
  if (isUser) {
    return (
      <div className="flex items-start gap-2 justify-end">
        <div className="max-w-[85%] rounded-xl rounded-tr-sm border border-indigo-500/30 bg-indigo-500/10 px-3 py-2">
          <p className="text-xs text-indigo-100 whitespace-pre-wrap break-words">{message.content}</p>
        </div>
        <span className="mt-0.5 p-1.5 rounded-lg bg-slate-800 text-slate-300">
          <User className="w-3.5 h-3.5" />
        </span>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-2">
      <span className="mt-0.5 p-1.5 rounded-lg bg-slate-800 text-indigo-300">
        <Bot className="w-3.5 h-3.5" />
      </span>
      <div className="min-w-0 max-w-[90%] rounded-xl rounded-tl-sm border border-slate-800 bg-slate-950/70 px-3 py-2">
        <p className="text-xs text-slate-200 whitespace-pre-wrap break-words">{message.content}</p>

        {message.pending && (
          <span className="mt-1 inline-flex items-center gap-1.5 text-[10px] text-slate-500">
            <Loader2 className="w-3 h-3 animate-spin" /> retrieving…
          </span>
        )}

        {!message.pending && message.grounded === false && (
          <p className="mt-1.5 text-[10px] text-amber-300 flex items-start gap-1.5">
            <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
            No knowledge-base passage supported this answer — treated as unanswerable from the KB.
          </p>
        )}

        {!message.pending && message.knowledgeBaseMessage && (
          <p className="mt-1 text-[10px] text-slate-500">{message.knowledgeBaseMessage}</p>
        )}

        {!message.pending && <CitationList citations={message.citations} />}

        {!message.pending && message.error && (
          <p className="mt-1.5 text-[10px] text-rose-300">{message.error}</p>
        )}

        {!message.pending && Array.isArray(message.analysisReferences) &&
          message.analysisReferences.length > 0 && (
            <div className="mt-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                From this analysis
              </span>
              <ul className="mt-1 space-y-0.5">
                {message.analysisReferences.map((ref, i) => (
                  <li key={`${ref.rule_id}-${i}`} className="text-[11px] text-slate-400">
                    <span className="font-mono text-slate-500">{ref.rule_id}</span> · {ref.title}
                    {ref.finding_id && onSelectFinding && (
                      <button
                        type="button"
                        onClick={() => onSelectFinding(ref.finding_id)}
                        className="ml-1.5 text-indigo-300 hover:text-indigo-200 underline decoration-dotted"
                      >
                        show finding
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
      </div>
    </div>
  );
}

const SUGGESTIONS = [
  'How do I prevent SQL injection in Python?',
  'How should I fix the shell command finding in this run?',
  'How do I prevent XSS in Java?',
];

export function AssistantPanel({ runId, selectedFindingId, onSelectFinding }) {
  const [messages, setMessages] = useState([]);
  const [question, setQuestion] = useState('');
  const [pending, setPending] = useState(false);
  const abortRef = useRef(null);

  const ask = useCallback(
    async (text) => {
      const value = (text ?? question).trim();
      if (!value || !runId || pending) return;
      if (value.length > 2000) {
        setMessages((prev) => [
          ...prev,
          { role: 'user', content: value },
          {
            role: 'assistant',
            content: 'Questions are limited to 2000 characters. Shorten the question and try again.',
            grounded: false,
            citations: [],
            error: 'question_too_long',
          },
        ]);
        setQuestion('');
        return;
      }

      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setQuestion('');
      setPending(true);
      setMessages((prev) => [
        ...prev,
        { role: 'user', content: value },
        { role: 'assistant', content: '', pending: true },
      ]);

      try {
        const data = await askAssistant({
          runId,
          question: value,
          selectedFindingId,
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setMessages((prev) => {
          const next = [...prev];
          const last = next.length - 1;
          next[last] = {
            role: 'assistant',
            content: data.answer || '(empty answer)',
            grounded: data.grounded,
            citations: data.citations || [],
            knowledgeBaseMessage: data.knowledge_base?.message || '',
            analysisReferences: data.analysis_references || [],
            mode: data.mode,
          };
          return next;
        });
      } catch (err) {
        if (err?.kind === 'aborted' || controller.signal.aborted) return;
        const detail =
          err instanceof ApiError
            ? err.message
            : `Unexpected error: ${err?.message || String(err)}`;
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = {
            role: 'assistant',
            content: 'The assistant could not answer that question.',
            grounded: false,
            citations: [],
            error: detail,
          };
          return next;
        });
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
        setPending(false);
      }
    },
    [question, runId, pending, selectedFindingId]
  );

  return (
    <section
      aria-label="Code assistant"
      className="rounded-xl border border-slate-800 bg-slate-900/60 flex flex-col"
    >
      <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-slate-800">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <MessageSquare className="w-3.5 h-3.5 text-indigo-400" /> Code Assistant
        </span>
        <span className="text-[10px] text-slate-500">answers cite the knowledge base</span>
      </div>

      <div className="px-4 py-3 space-y-3 max-h-[520px] overflow-y-auto">
        {messages.length === 0 && (
          <div className="space-y-2">
            <p className="text-xs text-slate-400">
              Ask about the findings in this run or about secure-coding practice. Answers come from the
              local knowledge base with citations; if nothing relevant is indexed, the assistant says so
              instead of guessing.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => ask(s)}
                  disabled={pending || !runId}
                  className="text-[11px] px-2 py-1 rounded-lg border border-slate-700 bg-slate-950/60 text-slate-300 hover:text-white hover:border-indigo-500/50 transition-colors disabled:opacity-50"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <Message key={i} message={m} onSelectFinding={onSelectFinding} />
        ))}
      </div>

      <form
        className="px-3 py-3 border-t border-slate-800 flex items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          ask();
        }}
      >
        <textarea
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              ask();
            }
          }}
          rows={2}
          maxLength={2000}
          placeholder={
            selectedFindingId
              ? 'Ask about the selected finding… (Enter to send)'
              : 'Ask a secure-coding question… (Enter to send)'
          }
          aria-label="Ask the code assistant"
          className="flex-1 resize-none rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
        />
        <button
          type="submit"
          disabled={pending || !question.trim() || !runId}
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-white text-xs font-semibold transition-colors"
        >
          {pending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
          Send
        </button>
      </form>
      <p className="px-3 pb-2 text-[10px] text-slate-600 flex items-center gap-1.5">
        <CornerDownLeft className="w-3 h-3" /> Shift+Enter for a new line · submitted code is never executed
      </p>
    </section>
  );
}

export default AssistantPanel;
