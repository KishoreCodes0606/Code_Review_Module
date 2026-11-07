"""Health score / PR summary / report consistency (Task 7).

The backend is the single source of truth: the run payload, the PR summary and
both export formats must carry the same health object, the same de-duplication
and arithmetic, and never present 100 as proof of security.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from agents import pr_summary_agent
from m3 import report, service
from m3.health import compute_health
from orchestrator import pipeline

VULNERABLE = '''
import sqlite3
import subprocess


def get_user(conn, uid):
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + uid
    cur.execute(query)
    return cur.fetchone()


def run_tool(name):
    return subprocess.call("tool " + name, shell=True)
'''

CLEAN = '''
def add(a, b):
    return a + b
'''


def _payload(code, name):
    run_id = pipeline.analyze_code(code, "python", name)
    state = pipeline.get_run(run_id)
    return state, service.run_payload(state)


def test_health_object_is_identical_everywhere():
    state, run = _payload(VULNERABLE, "vulnerable.py")
    expected = compute_health(state.status, state.merged_findings)

    assert run["health"] == expected

    summary = pr_summary_agent.build_pr_summary(run, state.merged_findings)
    for key in ("available", "score", "label", "penalty", "counts", "duplicates_ignored",
                "scored_finding_count", "formula"):
        assert summary["health"][key] == expected[key], key

    exported = report.build_json_report(run, state.merged_findings, None, summary)
    assert exported["health"] == expected


def test_deductions_are_arithmetically_consistent():
    state, run = _payload(VULNERABLE, "vulnerable.py")
    health = run["health"]
    assert health["available"] is True

    total = sum(component["deduction"] for component in health["components"])
    for component in health["components"]:
        assert component["deduction"] == component["count"] * component["weight_each"]
    assert health["penalty"] == total
    assert health["score"] == max(0, 100 - min(100, total))
    assert sum(health["counts"].values()) == health["scored_finding_count"]
    assert str(min(100, total)) in health["explanation"]
    assert f"{health['score']}/100" in health["explanation"]


def test_duplicate_grouping_matches_the_raw_findings():
    state, run = _payload(VULNERABLE, "vulnerable.py")
    health = run["health"]
    raw = len(state.merged_findings)
    assert health["scored_finding_count"] + health["duplicates_ignored"] == raw
    assert health["duplicates_ignored"] == len(health["duplicate_details"])
    # Grouped duplicates must name real rules and a real location.
    for detail in health["duplicate_details"]:
        assert detail["rule_id"] and detail["duplicate_of"]
        assert detail["line_start"]


def test_pr_summary_severity_counts_are_the_raw_findings():
    state, run = _payload(VULNERABLE, "vulnerable.py")
    summary = pr_summary_agent.build_pr_summary(run, state.merged_findings)
    raw_counts = Counter(f.severity for f in state.merged_findings)
    for severity in ("critical", "high", "medium", "low", "info"):
        assert summary["severity_counts"][severity] == raw_counts.get(severity, 0)
        assert run["severity_counts"][severity] == raw_counts.get(severity, 0)
    assert summary["finding_count"] == len(state.merged_findings)
    # Unique (scored) counts differ from raw counts only by grouped duplicates.
    unique_total = sum(health_count for health_count in run["health"]["counts"].values())
    assert unique_total + run["health"]["duplicates_ignored"] == summary["finding_count"]


def test_perfect_score_is_never_described_as_secure():
    state, run = _payload(CLEAN, "clean.py")
    assert state.status == "COMPLETED"
    health = run["health"]
    if not state.merged_findings:
        assert health["score"] == 100
        assert "not a security guarantee" in health["caveat"]

    summary = pr_summary_agent.build_pr_summary(run, state.merged_findings)
    assert "secure" not in (summary["health"].get("label") or "").lower()
    caveat_text = " ".join(summary["caveats"]).lower()
    assert "not" in caveat_text


def test_partial_and_failed_scores_are_withheld():
    for status in ("PARTIAL", "FAILED"):
        health = compute_health(status, [])
        assert health["available"] is False
        assert health["score"] is None and health["label"] is None
        assert "withholding" in health["reason"]
        assert health["caveat"]


def test_frontend_does_not_recompute_the_score():
    source = Path(
        "code-submission-ui/src/components/analysis/HealthScoreCard.jsx"
    ).read_text(encoding="utf-8")
    # It renders the backend payload (score, penalty, deduction breakdown) ...
    assert "health" in source and "penalty" in source and "components" in source
    # ... and carries no copy of the weights or the formula arithmetic.
    assert "critical: 25" not in source
    assert "* 25" not in source
