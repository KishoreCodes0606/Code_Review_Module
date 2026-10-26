"""Multi-agent orchestrator (design doc section 6).

FAN-OUT: Code Analysis Agent and Security Vulnerability Agent run CONCURRENTLY
on the shared PipelineState (thread pool). FAN-IN: merge, de-duplicate
(same rule_id + same line span), consolidate severities, compute the
overall health score.

Failure semantics (plan section 6):
- a scanner error/timeout -> run status PARTIAL with an explicit error record,
  never a silently-clean findings list;
- both agents failing -> FAILED;
- invalid input never reaches the orchestrator (M1 gate rejects first).
"""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from analysis.findings import PipelineState

AGENT_TIMEOUT_SECONDS = 60.0

_runs: dict[str, PipelineState] = {}
_runs_lock = threading.Lock()


def analyze_code(code: str, language: str, filename: str) -> str:
    """Run the full pipeline synchronously and register it. Returns run_id."""
    from analysis.findings import PipelineState
    from agents import code_analysis_agent, security_agent

    run_id = "run-" + uuid.uuid4().hex[:12]
    file_path = filename or (f"submission.py" if language == "python" else "Submission.java")
    state: PipelineState = PipelineState(
        run_id=run_id, language=language, source_code=code,
        filename=filename or "", file_path=file_path,
        status="ANALYZING", started_at=time.time())

    def quality_task():
        return code_analysis_agent.run_agent(code, language, file_path)

    def security_task():
        return security_agent.run_agent(code, language, file_path)

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="m2agent") as pool:
        future_q = pool.submit(quality_task)
        future_s = pool.submit(security_task)
        try:
            q_findings, q_result, q_metrics = future_q.result(timeout=AGENT_TIMEOUT_SECONDS)
            state.quality_findings = q_findings
            state.metrics.update(q_metrics)
        except Exception as e:  # timeout or crash: explicit failure record
            from analysis.findings import AgentRunResult
            q_result = AgentRunResult(
                agent="code_analysis_agent", status="failed", error=str(e))
        state.agent_results.append(q_result)

        try:
            s_findings, s_result, s_extras = future_s.result(timeout=AGENT_TIMEOUT_SECONDS)
            state.security_findings = s_findings
            state.metrics.update({"security_" + k: v for k, v in s_extras.items()})
        except Exception as e:
            from analysis.findings import AgentRunResult
            s_result = AgentRunResult(
                agent="security_agent", status="failed", error=str(e))
        state.agent_results.append(s_result)

    # FAN-IN: merge + dedup + severity consolidation ------------------------
    state.merged_findings = merge_findings(
        [state.security_findings, state.quality_findings])
    from analysis.severity import health_score
    state.health_score = health_score(state.merged_findings)

    failures = state.agent_results
    if not state.agent_results:
        state.status = "FAILED"
    elif all(r.status != "failed" and r.status != "timeout" for r in state.agent_results):
        state.status = "COMPLETED"
    elif all((r.status in ("failed", "timeout")) for r in state.agent_results) \
            and not state.merged_findings:
        state.status = "FAILED"
    else:
        state.status = "PARTIAL"
    state.finished_at = time.time()

    with _runs_lock:
        _runs[run_id] = state
    return run_id


def merge_findings(lists) -> list:
    """Concatenate agent findings, dropping duplicates by (rule_id, line span
    overlap). Severity/score already computed per finding by its agent."""
    seen: dict[tuple, object] = {}
    merged: list = []
    for findings in lists:
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_start)
            if key in seen:
                continue
            seen[key] = f
            merged.append(f)
    merged.sort(key=lambda f: (f.category != "security", -f.severity_score, f.line_start))
    return merged


def run_summary(state: PipelineState) -> dict:
    """REST payload for a run: statuses, health score, counts and findings."""
    from collections import Counter
    severity_counts = Counter(f.severity for f in state.merged_findings)
    category_counts = Counter(f.category for f in state.merged_findings)
    return {
        "run_id": state.run_id,
        "language": state.language,
        "filename": state.filename,
        "status": state.status,
        "health_score": state.health_score,
        "agent_results": [
            {"agent": r.agent, "status": r.status,
             "error": r.error, "duration_seconds": r.duration_seconds}
            for r in state.agent_results
        ],
        "severity_counts": {s: severity_counts.get(s, 0)
                            for s in ("critical", "high", "medium", "low", "info")},
        "category_counts": {c: category_counts.get(c, 0)
                            for c in ("security", "quality")},
        "finding_count": len(state.merged_findings),
        "metrics": state.metrics,
        "duration_seconds": round(state.finished_at - state.started_at, 2) if state.finished_at else None,
    }


def get_run(run_id: str):
    with _runs_lock:
        return _runs.get(run_id)
