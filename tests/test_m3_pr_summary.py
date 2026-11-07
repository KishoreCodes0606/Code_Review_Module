"""M3 PR summary tests: real pipeline runs + explicit PARTIAL/FAILED honesty."""
import pytest

from agents import pr_summary_agent, remediation_agent
from orchestrator import pipeline
from tests.fixtures import JAVA_VULNERABLE, PY_CLEAN, PY_VULNERABLE


def _run_payload(state):
    payload = pipeline.run_summary(state)
    return payload


@pytest.fixture(scope="module")
def py_state():
    run_id = pipeline.analyze_code(PY_VULNERABLE, "python", "vulnerable.py")
    return pipeline.get_run(run_id)


@pytest.fixture(scope="module")
def py_summary(py_state):
    remediation = remediation_agent.generate_remediation(
        py_state.merged_findings, "python", run_id=py_state.run_id,
        analysis_status=py_state.status,
    )
    return pr_summary_agent.build_pr_summary(
        _run_payload(py_state), py_state.merged_findings, remediation
    )


def test_summary_uses_real_findings(py_state, py_summary):
    assert py_summary["run_id"] == py_state.run_id
    assert py_summary["finding_count"] == len(py_state.merged_findings)
    assert sum(py_summary["severity_counts"].values()) == py_summary["finding_count"]
    assert py_summary["consistency"]["severity_total_matches_finding_count"] is True
    assert py_summary["consistency"]["category_total_matches_finding_count"] is True


def test_critical_findings_request_changes(py_summary):
    assert py_summary["severity_counts"]["critical"] > 0
    assert py_summary["review_status"]["code"] == "CHANGES_REQUESTED"
    assert py_summary["review_status"]["label"] == "Changes Requested"
    assert py_summary["review_status"]["rationale"]


def test_prioritized_fixes_are_ordered_by_severity(py_summary):
    priorities = py_summary["prioritized_fixes"]
    assert priorities
    order = ["critical", "high", "medium", "low", "info"]
    ranks = [order.index(p["severity"]) for p in priorities]
    assert ranks == sorted(ranks)
    assert [p["priority"] for p in priorities] == list(range(1, len(priorities) + 1))


def test_byte_size_caveats_are_present(py_summary):
    joined = " ".join(py_summary["caveats"]).lower()
    assert "static analysis only" in joined
    assert "not a security guarantee" in joined


def test_clean_source_is_not_an_approval():
    run_id = pipeline.analyze_code(PY_CLEAN, "python", "clean.py")
    state = pipeline.get_run(run_id)
    summary = pr_summary_agent.build_pr_summary(_run_payload(state), state.merged_findings)
    # Never "Approved": a static scan with no findings is not an approval.
    assert summary["review_status"]["code"] in ("APPROVED_WITH_SUGGESTIONS", "CHANGES_REQUESTED")
    assert "no auto-approve" in summary["review_status"]["rationale"].lower() or \
        "cannot prove" in summary["final_recommendation"].lower()


def test_java_summary_is_consistent():
    run_id = pipeline.analyze_code(JAVA_VULNERABLE, "java", "Vulnerable.java")
    state = pipeline.get_run(run_id)
    summary = pr_summary_agent.build_pr_summary(_run_payload(state), state.merged_findings)
    assert summary["language"] == "java"
    assert summary["filename"] == "Vulnerable.java"
    assert sum(summary["severity_counts"].values()) == summary["finding_count"]
    assert summary["final_recommendation"]


@pytest.mark.parametrize("status", ["PARTIAL", "FAILED"])
def test_incomplete_runs_never_read_as_success(status):
    findings = [
        {
            "id": "f1", "rule_id": "S-PY-SQLI", "title": "SQL injection",
            "severity": "critical", "category": "security", "file_path": "a.py",
            "line_start": 2, "line_end": 2, "severity_score": 9.4,
        }
    ]
    run = {
        "run_id": "run-partial",
        "status": status,
        "language": "python",
        "filename": "a.py",
        "agent_results": [
            {"agent": "security", "status": "succeeded", "duration_seconds": 0.1},
            {"agent": "code_analysis", "status": "failed", "error": "boom",
             "duration_seconds": 0.0},
        ],
        "metrics": {"parsed": False, "pmd_status": "unavailable"},
    }
    summary = pr_summary_agent.build_pr_summary(run, findings)

    assert summary["review_status"]["code"] == "INCOMPLETE_REVIEW"
    assert summary["health"]["available"] is False
    assert summary["health"]["score"] is None
    assert "withheld" in " ".join(summary["caveats"]).lower()
    assert "not merge" in summary["final_recommendation"].lower()
    # The single real finding is still reported, just never as a pass.
    assert summary["severity_counts"]["critical"] == 1


def test_missing_remediation_is_stated_not_invented():
    run = {
        "run_id": "run-x", "status": "COMPLETED", "language": "python",
        "filename": "a.py", "agent_results": [], "metrics": {},
    }
    summary = pr_summary_agent.build_pr_summary(run, [])
    assert summary["remediation_summary"]["available"] is False
    assert summary["remediation_summary"]["message"]
    assert "No remediation bundle exists yet" in " ".join(summary["caveats"])
