"""Orchestrator failure/timeout path tests (plan section 6).

Both agents are replaced with controlled fakes — no Bandit/PMD/radon runs —
so these tests are fast and deterministic. They assert:
- one agent crashing -> PARTIAL + explicit error record, other agent's
  findings retained;
- one agent timing out -> PARTIAL + explicit timeout record, findings retained;
- a failed run is never reported as a clean COMPLETED scan.
"""
import time

import pytest

from agents import code_analysis_agent, security_agent
from orchestrator import pipeline
from analysis.findings import AgentRunResult, Finding
from analysis.rule_catalog import SECURITY, QUALITY
from analysis.severity import compute_finding_score


def make_finding(rule_id: str, line: int, agent: str) -> Finding:
    spec = SECURITY.get(rule_id) or QUALITY[rule_id]
    f = Finding.from_rule(
        rule_id, line, line, "snippet", "submission.py",
        "synthetic test finding", agent, "rule_based", spec)
    compute_finding_score(f)
    return f


SEC_FINDING = "S-PY-SQLI"
QUAL_FINDING = "Q-long-method"


def fake_security_ok(code, language, file_path):
    findings = [make_finding(SEC_FINDING, 7, "security_agent")]
    return (findings,
            AgentRunResult(agent="security_agent", status="succeeded",
                           duration_seconds=0.01),
            {"scanned": True})


def fake_quality_ok(code, language, file_path):
    findings = [make_finding(QUAL_FINDING, 3, "code_analysis_agent")]
    return (findings,
            AgentRunResult(agent="code_analysis_agent", status="succeeded",
                           duration_seconds=0.01),
            {"function_count": 1})


def fake_quality_crash(code, language, file_path):
    raise RuntimeError("quality scanner exploded")


def fake_security_crash(code, language, file_path):
    raise RuntimeError("security scanner exploded")


def fake_quality_hang(code, language, file_path):
    time.sleep(0.8)  # only the patched small timeout matters (see test)
    return fake_quality_ok(code, language, file_path)


def _run(monkeypatch):
    run_id = pipeline.analyze_code("x = 1\n", "python", "submission.py")
    return pipeline.get_run(run_id)


def _record(state, agent):
    matches = [r for r in state.agent_results if r.agent == agent]
    assert len(matches) == 1, f"expected exactly one record for {agent}"
    return matches[0]


# --- 1. quality fails, security succeeds ----------------------------------

def test_quality_failure_yields_partial_with_error_record(monkeypatch):
    monkeypatch.setattr(code_analysis_agent, "run_agent", fake_quality_crash)
    monkeypatch.setattr(security_agent, "run_agent", fake_security_ok)

    state = _run(monkeypatch)

    assert state.status == "PARTIAL"
    q = _record(state, "code_analysis_agent")
    assert q.status == "failed"
    assert q.error and "quality scanner exploded" in q.error
    s = _record(state, "security_agent")
    assert s.status == "succeeded"
    # requirement 5: successful agent's findings retained
    assert any(f.rule_id == SEC_FINDING for f in state.merged_findings)
    # requirement 6: never reported as a clean successful scan
    assert state.status != "COMPLETED"


# --- 2. security fails, quality succeeds ----------------------------------

def test_security_failure_yields_partial_with_error_record(monkeypatch):
    monkeypatch.setattr(code_analysis_agent, "run_agent", fake_quality_ok)
    monkeypatch.setattr(security_agent, "run_agent", fake_security_crash)

    state = _run(monkeypatch)

    assert state.status == "PARTIAL"
    s = _record(state, "security_agent")
    assert s.status == "failed"
    assert s.error and "security scanner exploded" in s.error
    q = _record(state, "code_analysis_agent")
    assert q.status == "succeeded"
    assert any(f.rule_id == QUAL_FINDING for f in state.merged_findings)
    assert state.status != "COMPLETED"


# --- 3. one agent times out ------------------------------------------------

def test_agent_timeout_yields_partial_with_timeout_record(monkeypatch):
    monkeypatch.setattr(pipeline, "AGENT_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(code_analysis_agent, "run_agent", fake_quality_hang)
    monkeypatch.setattr(security_agent, "run_agent", fake_security_ok)

    state = _run(monkeypatch)

    assert state.status == "PARTIAL"
    q = _record(state, "code_analysis_agent")
    assert q.status == "timeout", (
        "a timed-out agent must be recorded as timeout, not silently failed")
    assert q.error and "timed out" in q.error, (
        "timeout record must carry an explicit error message")
    s = _record(state, "security_agent")
    assert s.status == "succeeded"
    assert any(f.rule_id == SEC_FINDING for f in state.merged_findings)
    assert state.status != "COMPLETED"
