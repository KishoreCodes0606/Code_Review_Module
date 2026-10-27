/**
 * Centralized M2 analysis API client.
 *
 * Contracts mirror server.py exactly (verified against the handlers):
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
const QUICK_TIMEOUT_MS = 10000;

/** Typed API failure: kind mirrors the backend's error enums so the UI can react. */
export class ApiError extends Error {
  constructor(kind, status, message, payload = {}) {
    super(message || kind);
    this.name = 'ApiError';
    this.kind = kind; // unsupported_language | syntax_error | payload_too_large
                      // | analysis_unavailable | pipeline_failure | not_found | network | bad_json | unexpected
    this.status = status;
    this.payload = payload;
  }
}

async function request(path, { method = 'GET', body, timeoutMs = QUICK_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp;
  try {
    resp = await fetch(`${API_BASE}${path}`, {
      method,
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    // AbortError from our own timer == timeout; anything else is a network failure
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      throw new ApiError('network', 0, 'Request timed out. Is the Python backend running on port 8000?');
    }
    throw new ApiError('network', 0, 'Cannot reach the backend (http://localhost:8000). Start it with `python server.py`.');
  }
  clearTimeout(timer);

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
    const kind = data?.error || (resp.status === 404 ? 'not_found' : 'unexpected');
    throw new ApiError(kind, resp.status, data?.message || `HTTP ${resp.status}`, data);
  }
  return data;
}

/** Run the synchronous multi-agent pipeline. Resolves with the run summary. */
export function runAnalysis({ code, language = 'auto', filename = '' }) {
  return request('/api/analysis', {
    method: 'POST',
    body: { code, language, filename },
    timeoutMs: ANALYSIS_TIMEOUT_MS,
  });
}

/** Fetch the terminal run summary (status endpoint). */
export function getRun(runId) {
  return request(`/api/analysis/${encodeURIComponent(runId)}`);
}

/** Fetch merged findings, optionally with server-side filters. Resolves { run_id, count, findings }. */
export function getFindings(runId, { category, severity } = {}) {
  const params = new URLSearchParams();
  if (category) params.set('category', category);
  if (severity) params.set('severity', severity);
  const qs = params.toString();
  return request(`/api/analysis/${encodeURIComponent(runId)}/findings${qs ? `?${qs}` : ''}`);
}

/** Liveness check. */
export function getHealth() {
  return request('/api/health');
}
