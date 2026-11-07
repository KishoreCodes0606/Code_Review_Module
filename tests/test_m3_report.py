"""M3 report tests: JSON structure and real PDF bytes from actual run data."""
import json

import pytest

from m3 import report, store
from m3.service import build_report
from orchestrator import pipeline
from tests.fixtures import PY_VULNERABLE


@pytest.fixture(scope="module")
def run_id():
    store.reset()
    rid = pipeline.analyze_code(PY_VULNERABLE, "python", "vulnerable.py")
    yield rid
    store.reset()


def test_json_report_reflects_the_run(run_id):
    payload, content_type, filename = build_report(run_id, "json")
    assert content_type == "application/json"
    assert filename.endswith(".json")

    data = json.loads(payload.decode("utf-8"))
    assert data["schema_version"]
    assert data["run"]["run_id"] == run_id
    assert data["finding_count"] == len(data["findings"])
    assert data["findings"], "report must contain the real findings"
    assert data["remediation"]["finding_count"] == data["finding_count"]
    assert data["summary"]["run_id"] == run_id
    assert data["health"]["score"] is not None
    assert "not a security guarantee" in data["disclaimer"]


def test_json_report_findings_match_pipeline(run_id):
    state = pipeline.get_run(run_id)
    payload, _, _ = build_report(run_id, "json")
    data = json.loads(payload.decode("utf-8"))
    assert [f["rule_id"] for f in data["findings"]] == [f.rule_id for f in state.merged_findings]


def test_pdf_report_is_generated_from_the_same_data(run_id):
    payload, content_type, filename = build_report(run_id, "pdf")
    assert content_type == "application/pdf"
    assert filename.endswith(".pdf")
    assert payload[:5] == b"%PDF-"
    assert payload.rstrip().endswith(b"%%EOF")
    assert len(payload) > 5000


def test_unknown_format_is_rejected(run_id):
    with pytest.raises(ValueError):
        build_report(run_id, "docx")


def test_partial_run_report_says_score_is_withheld():
    findings = [
        {
            "id": "f1", "rule_id": "S-PY-SQLI", "title": "SQL injection",
            "severity": "critical", "category": "security", "file_path": "a.py",
            "line_start": 2, "line_end": 2, "description": "dynamic SQL",
        }
    ]
    run = {
        "run_id": "run-partial", "status": "PARTIAL", "language": "python",
        "filename": "a.py", "severity_counts": {"critical": 1}, "finding_count": 1,
        "agent_results": [{"agent": "security", "status": "failed", "error": "boom"}],
        "metrics": {"parsed": True},
    }
    data = report.build_json_report(run, findings, None, None)
    assert data["health"]["available"] is False
    assert data["health"]["score"] is None
    assert data["summary"] is None
    assert data["remediation"] is None

    pdf_bytes, content_type, filename = report.build_report_bytes("pdf", run, findings, None, None)
    assert content_type == "application/pdf"
    assert filename.endswith(".pdf")
    assert pdf_bytes[:5] == b"%PDF-"
    assert len(pdf_bytes) > 1000
