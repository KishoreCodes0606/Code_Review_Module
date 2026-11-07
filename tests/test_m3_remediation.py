"""M3 remediation tests: real findings only, Bandit mapping, language fit.

Every test drives the real agent against findings produced by the real M2
pipeline (or a synthetic finding that mirrors one) — no fixture remediation text.
"""
import pytest

from agents import remediation_agent
from orchestrator import pipeline
from tests.fixtures import JAVA_VULNERABLE, PY_VULNERABLE

REQUIRED_FIELDS = (
    "finding_id",
    "rule_id",
    "title",
    "severity",
    "problem_explanation",
    "recommended_fix",
    "corrected_code",
    "best_practice",
    "reason_for_fix",
    "source_location",
    "remediation_status",
)


@pytest.fixture(scope="module")
def py_run():
    run_id = pipeline.analyze_code(PY_VULNERABLE, "python", "vulnerable.py")
    return pipeline.get_run(run_id)


@pytest.fixture(scope="module")
def py_remediation(py_run):
    return remediation_agent.generate_remediation(
        py_run.merged_findings,
        "python",
        run_id=py_run.run_id,
        analysis_status=py_run.status,
    )


@pytest.fixture(scope="module")
def java_run():
    run_id = pipeline.analyze_code(JAVA_VULNERABLE, "java", "Vulnerable.java")
    return pipeline.get_run(run_id)


def test_every_real_finding_gets_a_structured_entry(py_run, py_remediation):
    assert py_remediation["finding_count"] == len(py_run.merged_findings)
    returned_ids = {item["finding_id"] for item in py_remediation["findings"]}
    assert returned_ids == {f.id for f in py_run.merged_findings}
    for item in py_remediation["findings"]:
        for field in REQUIRED_FIELDS:
            assert field in item, f"missing {field} on {item['rule_id']}"
        assert item["source_location"]["file_path"]
        assert item["remediation_status"] in ("suggested", "manual_review_required")


def test_no_invented_rule_ids(py_run, py_remediation):
    real = {f.rule_id for f in py_run.merged_findings}
    assert {item["rule_id"] for item in py_remediation["findings"]} == real


def test_bandit_rules_are_mapped_to_remediation_families(py_run, py_remediation):
    bandit_items = [
        item for item in py_remediation["findings"] if item["rule_id"].startswith("bandit-")
    ]
    assert bandit_items, "expected Bandit findings in the vulnerable fixture"
    real = {f.id: f.rule_id for f in py_run.merged_findings}
    for item in bandit_items:
        # The original Bandit id is preserved, the family is recorded separately.
        assert real[item["finding_id"]] == item["rule_id"]
        assert item["remediation_family"], f"{item['rule_id']} was not family-mapped"
        assert item["remediation_family"] != item["rule_id"]


@pytest.mark.parametrize(
    "rule_id,family,code_marker",
    [
        ("bandit-B602", "S-PY-SHELL", "shell=False"),
        ("bandit-B608", "S-PY-SQLI", "?"),
        ("bandit-B301", "S-PY-DESER", "safe_load"),
    ],
)
def test_bandit_family_mapping_produces_corrected_code(rule_id, family, code_marker):
    finding = {
        "id": f"f-{rule_id}",
        "rule_id": rule_id,
        "title": "Bandit finding",
        "severity": "high",
        "category": "security",
        "description": "reported by bandit",
        "file_path": "app.py",
        "line_start": 12,
        "line_end": 12,
        "code_snippet": "value = input()\n",
        "finding_kind": "vulnerability",
    }
    item = remediation_agent.generate_remediation(
        [finding], "python", run_id="run-test"
    )["findings"][0]
    assert item["rule_id"] == rule_id                    # original id preserved
    assert item["remediation_family"] == family          # family recorded
    assert item["remediation_status"] == "suggested"
    assert code_marker in item["corrected_code"]
    assert "bandit" not in item["corrected_code"].lower()


def test_unknown_rule_falls_back_to_manual_review_without_fake_code():
    finding = {
        "id": "f-unknown",
        "rule_id": "S-PY-UNMAPPED-RULE",
        "title": "Something unusual",
        "severity": "medium",
        "category": "quality",
        "description": "no template exists",
        "file_path": "app.py",
        "line_start": 3,
        "line_end": 3,
        "code_snippet": "x = 1\n",
    }
    item = remediation_agent.generate_remediation(
        [finding], "python", run_id="run-test"
    )["findings"][0]
    assert item["rule_id"] == "S-PY-UNMAPPED-RULE"
    assert item["remediation_status"] == "manual_review_required"
    assert not item["corrected_code"]  # empty/None: no invented patch
    assert item["recommended_fix"]  # still explains what to do manually


def test_java_remediation_is_language_appropriate(java_run):
    payload = remediation_agent.generate_remediation(
        java_run.merged_findings, "java", run_id=java_run.run_id,
        analysis_status=java_run.status,
    )
    assert payload["language"] == "java"
    with_code = [item for item in payload["findings"] if item["corrected_code"]]
    assert with_code, "expected at least one Java corrected example"
    for item in with_code:
        assert item["language"] == "java"
        # A Python-isms leak would show up as these keywords in Java examples.
        assert "def " not in item["corrected_code"]
        assert "import os" not in item["corrected_code"]
    assert not any("shell=False" in item["corrected_code"] for item in with_code)


def test_remediation_is_illustrative_and_never_auto_applied(py_remediation):
    assert "not an automatically applied patch" in py_remediation["notice"]
    assert py_remediation["mode"] == "deterministic"
    # Nothing here claims the source was modified.
    assert all("applied" not in item["remediation_status"] for item in py_remediation["findings"])


def test_entries_are_grounded_in_kb_references(py_remediation):
    with_refs = [item for item in py_remediation["findings"] if item["references"]]
    assert with_refs, "expected KB references on real findings"
    for item in with_refs:
        for ref in item["references"]:
            assert ref["title"]
            assert ref["source"].endswith((".md", ".txt"))
            assert ref["excerpt"]
