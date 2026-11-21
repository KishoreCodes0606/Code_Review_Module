"""Regression tests for the selected-finding assistant path.

Defect fixed here: ``agents/assistant_agent.py::_analysis_facts`` read the
selected finding with ``.get(...)`` although findings are ``Finding`` objects,
so every chat request that carried ``selected_finding_id`` failed with
``'Finding' object has no attribute 'get'``. The function now reads every field
through the shared ``_get`` helper, which supports both Finding objects (the
pipeline's shape) and dicts (dict-based callers).

These tests pin that behaviour and the contract around it: the answer still
carries real KB citations, the analysis facts still describe only this run's
real finding, and an unknown selection is still rejected.
"""
from __future__ import annotations

import pytest

from agents import assistant_agent, remediation_agent
from m3 import service
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

QUESTION = "How do I prevent SQL injection in Python?"


def _run():
    run_id = pipeline.analyze_code(VULNERABLE, "python", "selected_finding.py")
    state = pipeline.get_run(run_id)
    return run_id, state, service.run_payload(state)


def _sql_finding(state):
    return next(f for f in state.merged_findings if f.rule_id == "S-PY-SQLI")


def test_selected_finding_object_is_answered_not_raised():
    """The reported failure path: selected_finding_id over Finding objects."""
    run_id, state, _payload = _run()
    finding = _sql_finding(state)

    answer = service.chat(run_id, QUESTION, selected_finding_id=finding.id)

    assert answer["answer"]
    assert "object has no attribute" not in answer["answer"]
    # The selected finding is described from real run data, not invented.
    assert finding.rule_id in answer["answer"]
    assert f"line_start={finding.line_start}" not in answer["answer"]  # no raw repr leak
    reference = answer["analysis_references"][0]
    assert reference["finding_id"] == finding.id
    assert reference["rule_id"] == finding.rule_id
    assert reference["title"] == finding.title
    assert reference["location"] == {
        "file_path": finding.file_path,
        "line_start": finding.line_start,
    }


def test_selected_finding_supplied_as_dict_is_supported():
    """Dict-based callers keep working through the same accessor."""
    run_id, state, payload = _run()
    findings = [f.to_dict() for f in state.merged_findings]
    selected = next(f for f in findings if f["rule_id"] == "S-PY-SQLI")

    answer = assistant_agent.answer_question(
        QUESTION,
        run=payload,
        findings=findings,
        remediation=None,
        selected_finding_id=selected["id"],
    )

    assert answer["run_id"] == run_id
    assert selected["rule_id"] in answer["answer"]
    assert answer["analysis_references"][0]["finding_id"] == selected["id"]
    assert answer["analysis_references"][0]["location"] == {
        "file_path": selected["file_path"],
        "line_start": selected["line_start"],
    }


def test_selected_finding_answer_carries_real_citations_and_its_fix():
    """A valid response: grounded citations plus the real remediation, if any."""
    run_id, state, payload = _run()
    finding = _sql_finding(state)
    remediation = remediation_agent.generate_remediation(
        state.merged_findings, state.language, run_id=run_id
    )

    answer = assistant_agent.answer_question(
        QUESTION,
        run=payload,
        findings=state.merged_findings,
        remediation=remediation,
        selected_finding_id=finding.id,
    )

    assert answer["grounded"] is True
    assert answer["citations"], "a selected-finding answer keeps its KB sources"
    assert all(citation["index"] for citation in answer["citations"])
    assert all(citation["source"] for citation in answer["citations"])
    # Citations come from the real knowledge base, never invented file names.
    assert {c["source"] for c in answer["citations"]} <= {
        chunk.source for chunk in assistant_agent.get_knowledge_base().chunks
    }
    item = next(i for i in remediation["findings"] if i["finding_id"] == finding.id)
    assert f"Suggested fix: {item['recommended_fix']}" in answer["answer"]
    assert finding.severity in answer["answer"]


def test_selected_finding_from_foreign_run_is_rejected():
    """A selected id that is not in this run must not be silently accepted."""
    run_id, _state, _payload = _run()

    with pytest.raises(ValueError) as excinfo:
        service.chat(run_id, QUESTION, selected_finding_id="f-does-not-exist")

    assert "does not belong to this run" in str(excinfo.value)


def test_selected_finding_analysis_facts_stay_run_specific():
    """Facts describe this run only; a second run's findings never leak in."""
    first_id, first_state, first_payload = _run()
    second_id, second_state, second_payload = _run()
    first = _sql_finding(first_state)
    second = _sql_finding(second_state)

    assert first.id != second.id  # separate runs, separate finding ids

    answer = assistant_agent.answer_question(
        QUESTION,
        run=first_payload,
        findings=first_state.merged_findings,
        remediation=None,
        selected_finding_id=first.id,
    )

    assert answer["run_id"] == first_id
    assert first_id in answer["answer"]
    assert second_id not in answer["answer"]
    referenced = {ref["finding_id"] for ref in answer["analysis_references"]}
    assert first.id in referenced
    assert second.id not in referenced
    # Counts and severities come from this run's own findings.
    assert f"Findings in this run: {len(first_state.merged_findings)} total" in answer["answer"]


def test_plain_question_without_selection_is_unchanged():
    """The previously working path keeps working after the fix."""
    run_id, state, payload = _run()

    answer = assistant_agent.answer_question(
        QUESTION, run=payload, findings=state.merged_findings, remediation=None
    )

    assert answer["run_id"] == run_id
    assert answer["analysis_references"] == []
    assert answer["grounded"] is True
    assert "Selected finding" not in answer["answer"]
