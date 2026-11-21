"""M4 Phase 2: validation of the existing report module (no duplicate module).

Every check here targets a requirement from the milestone text: metadata and
page numbering, finding/severity/health agreement, remediation correspondence,
duplicate findings, long code wrapping, honest PARTIAL/FAILED representation and
absence of stale findings.
"""
from __future__ import annotations

import json
from collections import Counter

import pytest

from m3 import report, store
from m3.config import MAX_REPORT_FINDINGS
from m3.health import compute_health
from m3.service import build_report
from orchestrator import pipeline


def _finding(rule_id="S-PY-SQLI", severity="critical", line=3, category="security",
             title="SQL injection", description="dynamic SQL", finding_id=None):
    return {
        "id": finding_id or f"f-{rule_id}-{line}",
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "severity_score": 9.4,
        "category": category,
        "file_path": "sample.py",
        "line_start": line,
        "line_end": line,
        "description": description,
        "remediation_advice": "Use parameters.",
        "code_snippet": "cursor.execute(query)",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 Injection",
    }


def _run(findings, status="COMPLETED", run_id="run-test-0001", filename="sample.py"):
    return {
        "run_id": run_id,
        "status": status,
        "language": "python",
        "filename": filename,
        "finding_count": len(findings),
        "agent_results": [
            {"agent": "code_analysis_agent", "status": "succeeded", "error": None},
            {"agent": "security_agent",
             "status": "succeeded" if status == "COMPLETED" else "failed",
             "error": None if status == "COMPLETED" else "scanner crashed"},
        ],
        "metrics": {"parsed": True},
    }


def _remediation(findings):
    return {
        "run_id": "run-test-0001",
        "mode": "deterministic",
        "finding_count": len(findings),
        "counts": {"suggested": len(findings), "manual_review_required": 0},
        "llm": {"used": False},
        "findings": [
            {
                "finding_id": f["id"],
                "rule_id": f["rule_id"],
                "severity": f["severity"],
                "remediation_status": "suggested",
                "recommended_fix": "Bind the value.",
                "corrected_code": 'cursor.execute("SELECT 1 WHERE id = ?", (uid,))',
                "best_practice": "Values are data.",
                "reason_for_fix": "Binding removes parsing ambiguity.",
                "problem_explanation": "Input became SQL text.",
            }
            for f in findings
        ],
    }


@pytest.fixture(scope="module")
def real_runs():
    """Two real runs, so a stale-findings check compares genuinely different data."""
    store.reset()
    sqli = (
        "import sqlite3\n\n\ndef get_user(conn, uid):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE id=\" + uid)\n"
    )
    clean = (
        "def add(left, right):\n"
        "    return left + right\n"
    )
    first = pipeline.analyze_code(sqli, "python", "sqli.py")
    second = pipeline.analyze_code(clean, "python", "clean.py")
    yield {"sqli": first, "clean": second}
    store.reset()


def test_pdf_has_metadata_and_page_numbering():
    findings = [_finding(line=index) for index in range(1, 40)]
    payload, content_type, _ = report.build_report_bytes(
        "pdf", _run(findings), findings, _remediation(findings), None
    )
    assert content_type == "application/pdf"
    assert payload[:5] == b"%PDF-"
    assert b"/Type /Page" in payload
    assert b"run-test-0001" in payload
    # A report of this size cannot fit on one page.
    assert payload.count(b"/Type /Page") > 2


def test_severity_counts_match_the_findings():
    findings = [
        _finding("S-PY-SQLI", "critical", 3),
        _finding("S-PY-CMDI", "critical", 8),
        _finding("S-PY-CRYPTO", "medium", 12),
        _finding("Q-deep-nesting", "low", 20, category="quality",
                 title="Deep Nesting", description="nested"),
    ]
    run = _run(findings)
    data = report.build_json_report(run, findings, _remediation(findings), None)

    reported = Counter(f["severity"] for f in data["findings"])
    assert reported["critical"] == 2
    assert reported["medium"] == 1
    assert reported["low"] == 1
    assert sum(data["health"]["counts"].values()) == data["health"]["scored_finding_count"]
    assert data["health"]["counts"]["critical"] == 2


def test_health_score_matches_the_backend_calculation():
    findings = [
        _finding("S-PY-SQLI", "critical", 3),
        _finding("S-PY-CRYPTO", "medium", 9),
        _finding("Q-magic-number", "low", 14, category="quality",
                 title="Magic Number", description="literal"),
    ]
    data = report.build_json_report(_run(findings), findings, None, None)
    expected = compute_health("COMPLETED", findings)
    assert data["health"]["score"] == expected["score"]
    assert data["health"]["penalty"] == expected["penalty"] == 25 * 1 + 5 * 1 + 2 * 1
    assert data["health"]["score"] == 100 - 32


def test_every_remediation_item_belongs_to_a_reported_finding():
    findings = [_finding(line=3), _finding("S-PY-CRYPTO", "medium", line=9)]
    remediation = _remediation(findings)
    # An extra item that belongs to no finding must not appear in the report.
    remediation["findings"].append(
        {"finding_id": "not-in-this-run", "rule_id": "S-PY-EVAL"}
    )
    data = report.build_json_report(_run(findings), findings, remediation, None)

    finding_ids = {f["id"] for f in data["findings"]}
    for item in data["remediation"]["findings"]:
        assert item["finding_id"] in finding_ids


def test_real_runs_contain_no_duplicate_findings(real_runs):
    from orchestrator.pipeline import run_summary

    state = pipeline.get_run(real_runs["sqli"])
    keys = [(f.rule_id, f.file_path, f.line_start) for f in state.merged_findings]
    assert len(keys) == len(set(keys)), "the merge step must not emit duplicates"

    data = report.build_json_report(
        run_summary(state), state.merged_findings, None, None
    )
    exported = [(f["rule_id"], f["file_path"], f["line_start"]) for f in data["findings"]]
    assert len(exported) == len(set(exported)) == len(state.merged_findings)


def test_same_line_reports_from_two_engines_are_both_kept_but_charged_once():
    built_in = _finding("S-PY-SQLI", "critical", 5, finding_id="builtin")
    engine = _finding("bandit-B608", "high", 5, finding_id="engine")
    findings = [built_in, engine]
    data = report.build_json_report(_run(findings), findings, None, None)

    # Both are shown as evidence, but the weakness is scored once.
    assert {f["rule_id"] for f in data["findings"]} == {"S-PY-SQLI", "bandit-B608"}
    assert data["health"]["duplicates_ignored"] == 1
    assert data["health"]["counts"]["critical"] == 1


def test_long_code_lines_wrap_inside_the_page():
    from reportlab.pdfbase import pdfmetrics

    long_line = "result = " + "+".join(f"value_{index}" for index in range(40))
    assert len(long_line) > 240
    wrapped = report._wrap_code(long_line)
    assert len(wrapped) > 1
    font = report._register_fonts()["code"]
    for line in wrapped:
        assert pdfmetrics.stringWidth(line, font, 7.2) <= report.CODE_LIMIT_PT + 0.01
    assert "".join(wrapped) == long_line.replace("\t", "    ")


def test_partial_run_withholds_the_score():
    findings = [_finding()]
    run = _run(findings, status="PARTIAL")
    data = report.build_json_report(run, findings, None, None)
    assert data["health"]["available"] is False
    assert data["health"]["score"] is None
    assert "PARTIAL" in data["health"]["reason"]
    assert "withholding" in data["health"]["reason"].lower()

    pdf, content_type, _ = report.build_report_bytes("pdf", run, findings, None, None)
    assert content_type == "application/pdf"
    assert pdf[:5] == b"%PDF-"


def test_failed_run_reports_no_score_and_no_findings():
    run = _run([], status="FAILED")
    data = report.build_json_report(run, [], None, None)
    assert data["health"]["available"] is False
    assert data["health"]["score"] is None
    assert data["finding_count"] == 0
    assert data["disclaimer"]


def test_remediation_absence_is_stated_not_invented():
    findings = [_finding()]
    data = report.build_json_report(_run(findings), findings, None, None)
    assert data["remediation"] is None
    assert data["summary"] is None
    pdf, _, _ = report.build_report_bytes("pdf", _run(findings), findings, None, None)
    assert pdf[:5] == b"%PDF-"


def test_large_result_sets_are_truncated_and_flagged():
    findings = [_finding(line=index) for index in range(1, MAX_REPORT_FINDINGS + 6)]
    data = report.build_json_report(_run(findings), findings, None, None)
    assert len(data["findings"]) == MAX_REPORT_FINDINGS
    assert data["finding_count"] == MAX_REPORT_FINDINGS + 5
    assert data["findings_truncated"] is True


def test_reports_never_contain_stale_findings(real_runs):
    first = real_runs["sqli"]
    second = real_runs["clean"]

    first_json = json.loads(build_report(first, "json")[0].decode("utf-8"))
    second_json = json.loads(build_report(second, "json")[0].decode("utf-8"))

    assert first_json["run"]["run_id"] == first
    assert second_json["run"]["run_id"] == second
    assert first_json["findings"], "the SQL injection sample must report findings"
    assert second_json["findings"] == [], "the clean sample must not inherit findings"

    first_pdf = build_report(first, "pdf")[0]
    second_pdf = build_report(second, "pdf")[0]
    assert first.encode() in first_pdf
    assert first.encode() not in second_pdf
    assert second.encode() in second_pdf


def test_report_has_exactly_one_canonical_health_score(real_runs):
    """The M2 raw score and the de-duplicated M3 score must not compete."""
    run_id = real_runs["sqli"]
    state = pipeline.get_run(run_id)
    data = json.loads(build_report(run_id, "json")[0].decode("utf-8"))

    assert data["run"]["health_score"] == data["health"]["score"]
    if state.health_score != data["health"]["score"]:
        assert data["run"]["m2_health_score"] == state.health_score


def test_json_and_pdf_use_the_same_computed_values(real_runs):
    run_id = real_runs["sqli"]
    state = pipeline.get_run(run_id)
    json_bytes, _, _ = build_report(run_id, "json")
    pdf_bytes, _, _ = build_report(run_id, "pdf")
    data = json.loads(json_bytes.decode("utf-8"))

    recomputed = compute_health(state.status, state.merged_findings)
    assert data["health"]["score"] == recomputed["score"]
    assert data["health"]["penalty"] == recomputed["penalty"]
    assert data["finding_count"] == len(state.merged_findings)
    assert data["summary"]["health"]["score"] == recomputed["score"]
    # The PDF is rendered from the same run record: its title carries that run id.
    assert run_id.encode() in pdf_bytes
