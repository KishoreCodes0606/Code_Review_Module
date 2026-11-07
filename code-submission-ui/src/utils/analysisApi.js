/**
 * Centralized API client for the unified validation + analysis workspace.
 *
 * Contracts mirror server.py exactly (verified against the handlers):
 *  - POST /api/submissions/validate       { code, language: 'auto'|'python'|'java' }
 *      200 -> { valid, rejected_code, rejection_reason, has_missing_item,
 *               errors: [{line, col, message, rule, is_missing_item, missing_item,
 *                         missing_detail, hint, snippet}], warnings, language, language_name }
 *      422 -> { valid: false, rejected_language: true, rejection_reason:
 *               'unsupported_language', message, errors: [...] }
 *  - POST /api/analysis                    { code, language: 'auto'|'python'|'java', filename }
 *      200 -> run summary: { run_id, language, filename, status: 'COMPLETED'|'PARTIAL'|'FAILED',
 *             health_score, agent_results: [{agent, status: 'succeeded'|'failed'|'timeout',
 *             error, duration_seconds}], severity_counts: {critical,high,medium,low,info},
 *             category_counts: {security,quality}, finding_count, metrics, duration_seconds }
 *            The backend runs the pipeline synchronously, so the POST itself is terminal —
 *            no polling is required (see AnalysisWorkspace).
 *      422 -> { error: 'unsupported_language' | 'syntax_error', message, syntax_errors? }
 *      413 -> { error: 'payload_too_large', message }
 *      503 -> { error: 'analysis_unavailable', message }
 *      500 -> { error: 'pipeline_failure', message }
 *  - GET  /api/analysis/{run_id}            -> run summary (same shape)
 *  - GET  /api/analysis/{run_id}/findings   -> { run_id, count, findings: Finding[] }
 *      Finding: { id, category: 'security'|'quality', rule_id, title, description,
 *                 finding_kind: 'vulnerability'|'heuristic_warning', detection, severity,
 *                 severity_score, confidence, file_path, line_start, line_end,
 *                 code_snippet, source_agent, owasp_category, cwe_id,
 *                 remediation_advice }
 *      Optional filters (?category=&severity=) are applied server-side.
 *  - GET  /api/health -> { status: 'healthy', service, timestamp }
 */
export const API_BASE = 'http://localhost:8000';

const ANALYSIS_TIMEOUT_MS = 240000; // PMD JVM run / first-run tool download can be slow
const VALIDATION_TIMEOUT_MS = 15000;
const QUICK_TIMEOUT_MS = 10000;

/**
 * Typed API failure: kind mirrors the backend's error enums so the UI can react.
 * `aborted` means the caller cancelled the request (stale response — ignore it);
 * `timeout` means the request exceeded its deadline (surface it, never treat an
 * unreachable/overloaded backend as a syntax rejection).
 */
export class ApiError extends Error {
  constructor(kind, status, message, payload = {}) {
    super(message || kind);
    this.name = 'ApiError';
    this.kind = kind; // unsupported_language | syntax_error | payload_too_large
                      // | analysis_unavailable | pipeline_failure | not_found
                      // | network | timeout | aborted | bad_json | unexpected
    this.status = status;
    this.payload = payload;
  }
}

async function request(path, { method = 'GET', body, timeoutMs = QUICK_TIMEOUT_MS, signal } = {}) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const onExternalAbort = () => controller.abort();

  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', onExternalAbort, { once: true });
  }

  let resp;
  try {
    resp = await fetch(`${API_BASE}${path}`, {
      method,
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    if (signal?.aborted) {
      throw new ApiError('aborted', 0, 'Request cancelled.');
    }
    if (timedOut || err.name === 'AbortError') {
      throw new ApiError(
        'timeout',
        0,
        'Request timed out before the backend responded. The service may be busy or unreachable.'
      );
    }
    throw new ApiError(
      'network',
      0,
      `Cannot reach the backend (${API_BASE}). Start it with \`python server.py\`.`
    );
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onExternalAbort);
  }

  let data = null;
  try {
    data = await resp.json();
  } catch {
    if (!resp.ok) {
      throw new ApiError('unexpected', resp.status, `Unexpected non-JSON error response (HTTP ${resp.status}).`);
    }
    throw new ApiError('bad_json', resp.status, 'Backend returned malformed JSON.');
  }

  if (!resp.ok) {
    const kind =
      data?.error ||
      (resp.status === 422
        ? 'validation_rejected'
        : resp.status === 404
        ? 'not_found'
        : 'unexpected');
    throw new ApiError(kind, resp.status, data?.message || `HTTP ${resp.status}`, data);
  }
  return data;
}

/** Normalizes both the 200 validation document and the 422 language rejection. */
function normalizeValidation(data) {
  const errors = Array.isArray(data?.errors) ? data.errors : [];
  const rejectedLanguage = Boolean(data?.rejected_language);
  return {
    valid: Boolean(data?.valid),
    language: data?.language || null,
    languageName: data?.language_name || null,
    rejectedLanguage,
    rejectionReason:
      data?.rejection_reason || (rejectedLanguage ? 'unsupported_language' : null),
    hasMissingItem: Boolean(
      data?.has_missing_item ||
        errors.some((e) => e.is_missing_item || e.isMissingItem)
    ),
    errors,
    warnings: Array.isArray(data?.warnings) ? data.warnings : [],
    message: data?.message || '',
  };
}

/**
 * Validate (language gate + syntax) the exact code that will be analyzed.
 * A 422 means the code was rejected (unsupported language / invalid submission);
 * network and server failures throw ApiError so they are never shown as a
 * syntax rejection.
 */
export async function validateSubmission({ code, language = 'auto', signal }) {
  try {
    const data = await request('/api/submissions/validate', {
      method: 'POST',
      body: { code, language },
      timeoutMs: VALIDATION_TIMEOUT_MS,
      signal,
    });
    return normalizeValidation(data);
  } catch (err) {
    if (err instanceof ApiError && err.status === 422) {
      return normalizeValidation(err.payload);
    }
    throw err;
  }
}

/** Run the synchronous multi-agent pipeline. Resolves with the run summary. */
export function runAnalysis({ code, language = 'auto', filename = '', signal }) {
  return request('/api/analysis', {
    method: 'POST',
    body: { code, language, filename },
    timeoutMs: ANALYSIS_TIMEOUT_MS,
    signal,
  });
}

/** Fetch the terminal run summary (status endpoint). */
export function getRun(runId, { signal } = {}) {
  return request(`/api/analysis/${encodeURIComponent(runId)}`, { signal });
}

/** Fetch merged findings, optionally with server-side filters. Resolves { run_id, count, findings }. */
export function getFindings(runId, { category, severity, signal } = {}) {
  const params = new URLSearchParams();
  if (category) params.set('category', category);
  if (severity) params.set('severity', severity);
  const qs = params.toString();
  return request(`/api/analysis/${encodeURIComponent(runId)}/findings${qs ? `?${qs}` : ''}`, { signal });
}

/** Liveness check. */
export function getHealth() {
  return request('/api/health');
}

/* ==========================================================================
 * M3: remediation, PR summary, health score detail, RAG assistant, reports
 * ==========================================================================
 * Every M3 endpoint is backed by the real service layer (agents/remediation_agent.py,
 * agents/pr_summary_agent.py, agents/assistant_agent.py, m3/report.py). Nothing here
 * fabricates content: a failure surfaces as an ApiError the UI must show honestly.
 *
 *  - GET  /api/analysis/{run_id}/remediation -> { status, run_id,
 *        remediation: { run_id, language, analysis_status, generated_at, mode,
 *          llm, counts: { suggested, manual_review_required }, finding_count,
 *          findings: Remediation[], limitations, notice } }
 *      Remediation: { finding_id, rule_id, remediation_family, title, severity,
 *        category, problem_explanation, recommended_fix, corrected_code,
 *        original_code, best_practice, reason_for_fix, source_location:
 *        { file_path, line_start, line_end }, remediation_status:
 *        'suggested'|'manual_review_required', language, limitations,
 *        references: [{ title, source, section?, ... }], cwe_id, owasp_category }
 *  - GET  /api/analysis/{run_id}/summary -> { status, run_id, summary: PrSummary }
 *      PrSummary: { review_status: { code, label, rationale }, executive_overview,
 *        severity_breakdown, categorized_findings, prioritized_fixes,
 *        remediation_summary, health, final_recommendation, caveats, ... }
 *  - POST /api/analysis/chat { run_id, question, selected_finding_id? } ->
 *        { answer, mode, grounded, citations: [{ n, title, source, section, excerpt }],
 *          knowledge_base: { available, message }, history }
 *  - GET  /api/analysis/{run_id}/chat/history -> { run_id, count, messages }
 *  - GET  /api/analysis/{run_id}/report?format=json|pdf -> JSON envelope or PDF bytes
 *  - GET  /api/m3/status -> capabilities (KB, LLM config, PDF availability, limits)
 */

const M3_TIMEOUT_MS = 120000; // remediation/report generation walks every finding
const CHAT_TIMEOUT_MS = 60000;

export function getM3Status({ signal } = {}) {
  return request('/api/m3/status', { signal });
}

/** Generate (or fetch the cached) per-finding remediation bundle for a run. */
export function getRemediation(runId, { signal } = {}) {
  return request(`/api/analysis/${encodeURIComponent(runId)}/remediation`, {
    timeoutMs: M3_TIMEOUT_MS,
    signal,
  });
}

/** Generate (or fetch the cached) PR summary for a run. */
export function getPrSummary(runId, { signal } = {}) {
  return request(`/api/analysis/${encodeURIComponent(runId)}/summary`, {
    timeoutMs: M3_TIMEOUT_MS,
    signal,
  });
}

/** Ask the RAG assistant a question about the current run. */
export function askAssistant({ runId, question, selectedFindingId = null, signal }) {
  return request('/api/analysis/chat', {
    method: 'POST',
    body: {
      run_id: runId,
      question,
      selected_finding_id: selectedFindingId,
    },
    timeoutMs: CHAT_TIMEOUT_MS,
    signal,
  });
}

/** Session history for the run's assistant conversation. */
export function getChatHistory(runId, { signal } = {}) {
  return request(`/api/analysis/${encodeURIComponent(runId)}/chat/history`, { signal });
}

/**
 * Direct download URL. Used with a real anchor click so the browser saves the
 * bytes the backend generated (Content-Disposition) instead of the UI inventing
 * any report content.
 */
export function reportDownloadUrl(runId, format) {
  const fmt = format === 'pdf' ? 'pdf' : 'json';
  return `${API_BASE}/api/analysis/${encodeURIComponent(runId)}/report?format=${fmt}`;
}
