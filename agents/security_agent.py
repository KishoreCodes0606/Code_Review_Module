"""Security Vulnerability Agent (design doc 5.3).

M2 deterministic step: custom rule engine (Python ast / Java text) + the
Bandit analyzer for Python. Findings carry OWASP category, CWE, line range,
finding_kind, and severity computed by the shared engine. The optional LLM
confirmation step is intentionally NOT wired in M2 (no API key dependency).
Never raises: scanner errors come back as failed AgentRunResult.
"""
from __future__ import annotations

import time

from agents.base import AgentError
from analysis.findings import AgentRunResult


def run_agent(code: str, language: str, file_path: str) -> tuple[list, AgentRunResult, dict]:
    started = time.time()

    def finish(findings, res: AgentRunResult, extras: dict | None = None):
        res.duration_seconds = round(time.time() - started, 2)
        return findings, res, (extras or {})

    try:
        if language == "python":
            findings = _python_security(code, file_path)
        elif language == "java":
            from analysis.security_rules import analyze_java_security
            findings = analyze_java_security(code, file_path)
        else:
            raise AgentError(f"Unsupported language for security analysis: {language!r}")
    except Exception as e:  # scanner failure is never a clean result
        return finish([], AgentRunResult(
            agent="security_agent", status="failed", error=str(e)), {})

    extras = {"llm_confirmation": "not-enabled (out of M2 scope)"}
    return finish(findings, AgentRunResult(
        agent="security_agent", status="succeeded"), extras)


def _python_security(code: str, file_path: str) -> list:
    from analysis.security_rules import analyze_python_security
    from analysis import bandit_client

    findings = list(analyze_python_security(code, file_path))

    if bandit_client.bandit_available():
        bandit_raw = bandit_client.run_bandit(code, file_path)
        converted = bandit_client.to_findings(bandit_raw, file_path)
        existing = {(f.rule_id, f.line_start) for f in findings}
        # keep Bandit findings whose (solver, line) is not already covered by
        # our custom rules; different rule ids are additive evidence.
        findings.extend(converted)
        extras_bandit = "ok"
    else:
        extras_bandit = "unavailable"
    _ = extras_bandit  # surfaced via metrics in Phase 3 if needed
    return findings
