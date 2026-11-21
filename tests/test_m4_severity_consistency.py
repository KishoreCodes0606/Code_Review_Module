"""M4 Phase 5: severity-scoring consistency across every component.

Checks that the same finding keeps one severity from the detector through the
merge, the health payload, the PR summary, the report and the prioritized fix
list, and that PARTIAL/FAILED runs never present a numeric score.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from agents import pr_summary_agent
from analysis.severity import SEVERITY_WEIGHTS, score_band
from m3 import report, store
from m3.health import SEVERITY_ORDER, compute_health
from m3.service import build_report, generate_remediation, generate_summary, run_payload
from orchestrator import pipeline

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "tests" / "fixtures" / "m4" / "sample3_complex_backend.py"


@pytest.fixture(scope="module")
def run_id():
    store.reset()
    source = SAMPLE.read_text(encoding="utf-8")
    rid = pipeline.analyze_code(source, "python", SAMPLE.name)
    yield rid
    store.reset()


def test_every_finding_severity_matches_its_score_band(run_id):
    state = pipeline.get_run(run_id)
    assert state.merged_findings
    for finding in state.merged_findings:
        expected = score_band(finding.severity_score)["label"]
        assert finding.severity == expected, (
            f"{finding.rule_id}: severity {finding.severity} but score "
            f"{finding.severity_score} bands as {expected}"
        )
        assert finding.severity in SEVERITY_ORDER


def test_health_counts_and_deductions_are_internally_consistent(run_id):
    state = pipeline.get_run(run_id)
    health = compute_health(state.status, state.merged_findings)

    assert [c["severity"] for c in health["components"]] == list(SEVERITY_ORDER)
    for component in health["components"]:
        assert component["weight_each"] == SEVERITY_WEIGHTS[component["severity"]]
        assert component["deduction"] == component["count"] * component["weight_each"]
    assert health["penalty"] == sum(c["deduction"] for c in health["components"])
    assert health["score"] == max(0, 100 - min(100, health["penalty"]))
    # Grouped findings are never scored twice.
    assert sum(health["counts"].values()) == health["scored_finding_count"]
    assert health["scored_finding_count"] + health["duplicates_ignored"] == len(
        state.merged_findings
    )


def test_summary_report_and_priorities_share_one_severity_per_finding(run_id):
    state = pipeline.get_run(run_id)
    summary = generate_summary(run_id)
    remediation = generate_remediation(run_id)
    data = json.loads(build_report(run_id, "json")[0].decode("utf-8"))

    by_id = {f.id: f for f in state.merged_findings}

    for category in summary["categorized_findings"]:
        for item in category["findings"]:
            assert item["severity"] == by_id[item["id"]].severity
            assert item["category"] == by_id[item["id"]].category

    for priority in summary["prioritized_fixes"]:
        assert priority["severity"] == by_id[priority["finding_id"]].severity

    for item in remediation["findings"]:
        assert item["severity"] == by_id[item["finding_id"]].severity

    exported = {f["id"]: f["severity"] for f in data["findings"]}
    assert exported == {f.id: f.severity for f in state.merged_findings}

    reported = Counter(f.severity for f in state.merged_findings)
    assert summary["severity_counts"] == {s: reported.get(s, 0) for s in SEVERITY_ORDER}
    assert data["health"]["score"] == summary["health"]["score"]


def test_pr_summary_priorities_follow_severity_and_urgency(run_id):
    state = pipeline.get_run(run_id)
    summary = generate_summary(run_id)
    order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}

    ranks = [order[p["severity"]] for p in summary["prioritized_fixes"]]
    assert ranks == sorted(ranks)
    assert summary["review_status"]["code"] == "CHANGES_REQUESTED"
    assert "critical/high" in summary["review_status"]["rationale"]


def test_partial_run_never_presents_a_score():
    findings = [
        {"id": "a", "rule_id": "S-PY-SQLI", "title": "SQL injection",
         "severity": "critical", "category": "security", "file_path": "x.py",
         "line_start": 2, "line_end": 2, "description": "dynamic"},
    ]
    run = {
        "run_id": "run-partial", "status": "PARTIAL", "language": "python",
        "filename": "x.py", "finding_count": 1, "metrics": {"parsed": True},
        "agent_results": [
            {"agent": "code_analysis_agent", "status": "succeeded", "error": None},
            {"agent": "security_agent", "status": "failed", "error": "boom"},
        ],
    }
    health = compute_health("PARTIAL", findings)
    assert health["available"] is False and health["score"] is None
    assert "PARTIAL" in health["reason"]

    summary = pr_summary_agent.build_pr_summary(run, findings, None)
    assert summary["review_status"]["code"] == "INCOMPLETE_REVIEW"
    assert summary["health"]["score"] is None
    assert any("withheld" in caveat.lower() for caveat in summary["caveats"])

    data = report.build_json_report(run, findings, None, summary)
    assert data["health"]["available"] is False
    assert data["health"]["score"] is None


def test_failed_run_has_no_score_and_no_approval():
    run = {
        "run_id": "run-failed", "status": "FAILED", "language": "java",
        "filename": "Broken.java", "finding_count": 0, "metrics": {"parsed": False},
        "agent_results": [
            {"agent": "code_analysis_agent", "status": "failed", "error": "parse"},
            {"agent": "security_agent", "status": "failed", "error": "parse"},
        ],
    }
    summary = pr_summary_agent.build_pr_summary(run, [], None)
    assert summary["review_status"]["code"] == "INCOMPLETE_REVIEW"
    assert summary["health"]["available"] is False
    assert "empty result is not a" in " ".join(summary["caveats"])


def test_duplicate_reports_are_charged_at_the_higher_severity():
    critical = {
        "id": "c1", "rule_id": "S-PY-SQLI", "severity": "critical",
        "category": "security", "file_path": "x.py", "line_start": 10,
    }
    duplicate = {
        "id": "c2", "rule_id": "bandit-B608", "severity": "high",
        "category": "security", "file_path": "x.py", "line_start": 10,
    }
    health = compute_health("COMPLETED", [critical, duplicate])
    assert health["duplicates_ignored"] == 1
    assert health["counts"]["critical"] == 1
    assert health["counts"]["high"] == 0
    assert health["penalty"] == SEVERITY_WEIGHTS["critical"]

    reversed_health = compute_health("COMPLETED", [duplicate, critical])
    assert reversed_health["score"] == health["score"]
