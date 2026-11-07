"""Test-only failure simulation (Task 3).

The simulation is closed unless ``CODE_REVIEW_TEST_FAULTS`` was set when the
process started. These tests verify the gate, the PARTIAL/FAILED rewrites, and
that derived artifacts (health, reports) stay honest about an incomplete run.
"""
from __future__ import annotations

import pytest

from m3 import faults, report, service
from m3.health import compute_health
from orchestrator import pipeline

VULNERABLE = '''
import sqlite3
import subprocess


API_KEY = "sk-test-1234567890"


def get_user(conn, uid):
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + uid
    cur.execute(query)
    return cur.fetchone()


def run_tool(name):
    return subprocess.call("tool " + name, shell=True)
'''


@pytest.fixture()
def state():
    run_id = pipeline.analyze_code(VULNERABLE, "python", "vulnerable.py")
    return pipeline.get_run(run_id)


def test_gate_is_closed_by_default(monkeypatch, state):
    monkeypatch.delenv(faults.MODE_ENV, raising=False)
    assert faults.configured_mode() is None
    assert faults.enabled() is False
    before = (state.status, list(state.merged_findings))
    assert faults.apply(state) is None
    assert (state.status, state.merged_findings) == before
    assert "no HTTP" in faults.describe()["scope"]


def test_unknown_values_do_not_enable_simulation(monkeypatch, state):
    monkeypatch.setenv(faults.MODE_ENV, "yes-please")
    assert faults.enabled() is False
    assert faults.apply(state) is None


def test_partial_rewrite_keeps_real_findings_and_withholds_health(monkeypatch, state):
    monkeypatch.setenv(faults.MODE_ENV, "partial")
    assert faults.apply(state) == "partial"

    assert state.status == "PARTIAL"
    security = [r for r in state.agent_results if r.agent == "security_agent"]
    assert security and security[0].status == "failed"
    assert "simulated scanner failure" in security[0].error
    quality = [r for r in state.agent_results if r.agent == "code_analysis_agent"]
    assert quality and quality[0].status == "succeeded"

    # The failed agent's findings are gone; the successful agent's are intact.
    assert state.merged_findings == list(state.quality_findings)
    assert not state.security_findings

    payload = service.run_payload(state)
    assert payload["status"] == "PARTIAL"
    assert payload["health"]["available"] is False
    assert payload["health"]["score"] is None


def test_failed_rewrite_reports_no_findings_and_no_score(monkeypatch, state):
    monkeypatch.setenv(faults.MODE_ENV, "failed")
    assert faults.apply(state) == "failed"

    assert state.status == "FAILED"
    assert state.merged_findings == []
    assert all(r.status == "failed" for r in state.agent_results)

    payload = service.run_payload(state)
    assert payload["finding_count"] == 0
    assert payload["health"]["available"] is False
    assert payload["health"]["score"] is None
    health = compute_health("FAILED", [])
    assert health["available"] is False and health["label"] is None


def test_report_of_a_simulated_run_never_shows_a_score(monkeypatch, state):
    monkeypatch.setenv(faults.MODE_ENV, "failed")
    faults.apply(state)
    payload = service.run_payload(state)
    exported = report.build_json_report(payload, state.merged_findings, None, None)
    assert exported["health"]["available"] is False
    assert exported["health"]["score"] is None
    assert exported["findings"] == []
