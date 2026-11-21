"""M4 Phase 3: end-to-end grading of the three curated samples.

Each sample runs through the real pipeline (validation already happened in M1,
quality agent + security agent in parallel, merge, health, remediation, PR
summary, assistant, JSON/PDF report). The output is graded against
``tests/fixtures/m4/expected.json``, which was written by reading the sample
source.

The tests assert the invariants a reviewer should rely on:

* every expected detection is present, with the expected severity, category and
  a location on (or next to) the anchored line;
* no security finding lands inside a hand-written clean implementation
  (false-positive control);
* rules that cannot apply to the sample are never reported;
* duplicates from a second engine are grouped exactly once for scoring;
* remediation, summary, report and assistant all agree with the findings.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from m3 import store
from m3.health import SEVERITY_ORDER, compute_health
from m3.service import build_report, chat, generate_remediation, generate_summary, run_payload
from orchestrator import pipeline

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "m4"
EXPECTED = json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))
SAMPLES = EXPECTED["samples"]
SAMPLE_IDS = [sample["id"] for sample in SAMPLES]
BY_ID = {sample["id"]: sample for sample in SAMPLES}


def _line_of(source: str, anchor: str) -> int:
    for number, line in enumerate(source.splitlines(), start=1):
        if anchor in line:
            return number
    raise AssertionError(f"oracle anchor {anchor!r} is not in the sample source")


@pytest.fixture(scope="module")
def graded():
    """Run each sample once through the complete workflow."""
    store.reset()
    results = {}
    for sample in SAMPLES:
        source = (ROOT / sample["file"]).read_text(encoding="utf-8")
        run_id = pipeline.analyze_code(
            source, sample["language"], Path(sample["file"]).name
        )
        state = pipeline.get_run(run_id)
        payload = run_payload(state)
        remediation = generate_remediation(run_id)
        summary = generate_summary(run_id)
        json_bytes, json_type, json_name = build_report(run_id, "json")
        pdf_bytes, pdf_type, pdf_name = build_report(run_id, "pdf")
        results[sample["id"]] = {
            "sample": sample,
            "source": source,
            "run_id": run_id,
            "state": state,
            "payload": payload,
            "remediation": remediation,
            "summary": summary,
            "report_json": json.loads(json_bytes.decode("utf-8")),
            "json_meta": (json_type, json_name),
            "pdf": pdf_bytes,
            "pdf_meta": (pdf_type, pdf_name),
        }
    yield results
    store.reset()


def _grade(entry: dict) -> dict:
    sample = entry["sample"]
    source = entry["source"]
    findings = entry["state"].merged_findings
    expected = sample["expected_detections"]

    true_positives, false_negatives = [], []
    for spec in expected:
        hit = next((f for f in findings if f.rule_id in spec["rule_ids"]), None)
        (true_positives if hit is not None else false_negatives).append((spec, hit))

    accepted = {rule_id for spec in expected for rule_id in spec["rule_ids"]}
    accepted |= set(sample.get("expected_duplicate_families") or [])
    accepted |= set(sample.get("expected_additional_rules") or [])
    false_positives = [
        f for f in findings
        if f.category == "security" and f.rule_id not in accepted
    ]

    control_results = []
    for control in sample.get("security_controls") or []:
        start = _line_of(source, control["anchor"])
        end = start + control.get("span", 5)
        hits = [
            f for f in findings
            if f.category == "security"
            and f.line_start is not None
            and start <= f.line_start <= end
        ]
        control_results.append((control, start, end, hits))

    return {
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "controls": control_results,
        "true_negatives": [c for c in control_results if not c[3]],
    }


def _entry(graded, sample_id):
    return graded[sample_id]


def test_every_sample_completed_without_agent_failure(graded):
    for sample_id in SAMPLE_IDS:
        entry = _entry(graded, sample_id)
        state = entry["state"]
        assert state.status == "COMPLETED", (
            f"{sample_id}: status={state.status} "
            f"agents={[(a.agent, a.status, a.error) for a in state.agent_results]}"
        )
        assert all(result.status == "succeeded" for result in state.agent_results)
        assert state.merged_findings, f"{sample_id}: expected findings, got none"


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_expected_detections_are_present(graded, sample_id):
    entry = _entry(graded, sample_id)
    grade = _grade(entry)
    missing = [(spec["title"], spec["rule_ids"]) for spec, _ in grade["false_negatives"]]
    assert not missing, f"{sample_id}: false negatives {missing}"

    for spec, finding in grade["true_positives"]:
        assert finding.severity == spec["severity"], (
            f"{sample_id}: {finding.rule_id} severity {finding.severity} != {spec['severity']}"
        )
        assert finding.category == spec["category"]
        if spec.get("anchor"):
            anchor_line = _line_of(entry["source"], spec["anchor"])
            tolerance = spec.get("line_tolerance", 0)
            assert abs(finding.line_start - anchor_line) <= tolerance, (
                f"{sample_id}: {finding.rule_id} at line {finding.line_start}, "
                f"anchor {spec['anchor']!r} at {anchor_line}"
            )
        assert finding.file_path


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_no_unexpected_security_findings(graded, sample_id):
    grade = _grade(_entry(graded, sample_id))
    assert not grade["false_positives"], [
        (f.rule_id, f.line_start, f.description) for f in grade["false_positives"]
    ]


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_clean_implementations_are_not_flagged(graded, sample_id):
    grade = _grade(_entry(graded, sample_id))
    assert grade["controls"], f"{sample_id}: oracle defines no clean control"
    assert len(grade["true_negatives"]) == len(grade["controls"])
    for control, start, end, hits in grade["controls"]:
        assert not hits, (
            f"{sample_id}: false positive in clean control {control['why']} "
            f"(lines {start}-{end}): {[(h.rule_id, h.line_start) for h in hits]}"
        )


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_rules_that_cannot_apply_are_absent(graded, sample_id):
    entry = _entry(graded, sample_id)
    reported = {finding.rule_id for finding in entry["state"].merged_findings}
    for rule_id in entry["sample"]["expected_absent_rules"]:
        assert rule_id not in reported, f"{sample_id}: unexpected {rule_id}"


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_second_engine_duplicates_are_grouped_once_for_scoring(graded, sample_id):
    entry = _entry(graded, sample_id)
    health = entry["payload"]["health"]
    duplicate_families = set(entry["sample"].get("expected_duplicate_families") or [])
    reported_duplicates = [
        f for f in entry["state"].merged_findings if f.rule_id in duplicate_families
    ]
    assert health["duplicates_ignored"] == len(reported_duplicates), (
        f"{sample_id}: health grouped {health['duplicates_ignored']} duplicate(s), "
        f"report listed {len(reported_duplicates)}"
    )
    for detail in health["duplicate_details"]:
        # Either side of the pair may be the retained representative, so the
        # grouped pair must involve at least one expected duplicate rule.
        assert (
            detail["rule_id"] in duplicate_families
            or detail["duplicate_of"] in duplicate_families
        ), detail


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_health_score_matches_the_documented_formula(graded, sample_id):
    entry = _entry(graded, sample_id)
    health = entry["payload"]["health"]
    state = entry["state"]

    assert health["available"] is True
    assert health["weights"] == {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}

    manual_counts = Counter(f.severity for f in state.merged_findings)
    assert health["counts"]["critical"] + health["counts"]["high"] + \
        health["counts"]["medium"] + health["counts"]["low"] + \
        health["counts"]["info"] == health["scored_finding_count"]

    expected_penalty = sum(
        component["count"] * component["weight_each"] for component in health["components"]
    )
    assert health["penalty"] == expected_penalty
    assert health["score"] == max(0, 100 - min(100, expected_penalty))
    # Grouping can only reduce the count (never inflate it) versus raw findings.
    assert health["scored_finding_count"] <= len(state.merged_findings)
    assert manual_counts["critical"] >= health["counts"]["critical"]


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_remediation_covers_every_finding_and_keeps_identity(graded, sample_id):
    entry = _entry(graded, sample_id)
    state = entry["state"]
    remediation = entry["remediation"]

    findings_by_id = {f.id: f for f in state.merged_findings}
    items = remediation["findings"]
    assert len(items) == len(state.merged_findings)
    assert [item["finding_id"] for item in items] == [f.id for f in state.merged_findings]

    for item in items:
        finding = findings_by_id[item["finding_id"]]
        assert item["rule_id"] == finding.rule_id
        assert item["severity"] == finding.severity
        assert item["source_location"]["line_start"] == finding.line_start
        assert item["remediation_status"] in ("suggested", "manual_review_required")
        assert item["problem_explanation"]
        assert item["recommended_fix"]

    with_code = {
        item["rule_id"] for item in items if item.get("corrected_code")
    }
    for rule_id in entry["sample"]["expected_remediation_with_code"]:
        assert rule_id in with_code, f"{sample_id}: no corrected-code example for {rule_id}"

    for rule_id in entry["sample"].get("expected_manual_review_rules") or []:
        item = next(i for i in items if i["rule_id"] == rule_id)
        assert item["remediation_status"] == "manual_review_required"
        assert item["corrected_code"] in (None, "")


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_pr_summary_agrees_with_the_findings(graded, sample_id):
    entry = _entry(graded, sample_id)
    summary = entry["summary"]
    findings = entry["state"].merged_findings

    assert summary["run_id"] == entry["run_id"]
    assert summary["analysis_status"] == "COMPLETED"
    assert summary["review_status"]["code"] == entry["sample"]["expected_review_status"]
    assert summary["finding_count"] == len(findings)
    assert sum(summary["severity_counts"].values()) == len(findings)
    assert summary["consistency"]["severity_total_matches_finding_count"] is True

    order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    ranks = [order[p["severity"]] for p in summary["prioritized_fixes"]]
    assert ranks == sorted(ranks), "priorities must be ordered by severity"
    assert len(summary["prioritized_fixes"]) == min(10, len(findings))
    known_ids = {f.id for f in findings}
    assert all(p["finding_id"] in known_ids for p in summary["prioritized_fixes"])

    assert summary["health"]["score"] == entry["payload"]["health"]["score"]
    assert summary["executive_overview"]
    assert summary["final_recommendation"]
    assert summary["caveats"]


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_json_report_matches_the_run(graded, sample_id):
    entry = _entry(graded, sample_id)
    data = entry["report_json"]
    state = entry["state"]

    content_type, filename = entry["json_meta"]
    assert content_type == "application/json"
    assert filename == f"code-review-{entry['run_id']}.json"

    assert data["run"]["run_id"] == entry["run_id"]
    assert data["finding_count"] == len(state.merged_findings)
    assert [f["rule_id"] for f in data["findings"]] == [f.rule_id for f in state.merged_findings]
    assert data["health"]["score"] == entry["payload"]["health"]["score"]
    assert data["summary"]["run_id"] == entry["run_id"]
    assert data["remediation"]["finding_count"] == len(state.merged_findings)

    finding_ids = {f["id"] for f in data["findings"]}
    remediation_ids = {i["finding_id"] for i in data["remediation"]["findings"]}
    assert remediation_ids <= finding_ids
    assert data["disclaimer"]


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_pdf_report_is_generated_for_the_same_run(graded, sample_id):
    entry = _entry(graded, sample_id)
    pdf = entry["pdf"]
    content_type, filename = entry["pdf_meta"]

    assert content_type == "application/pdf"
    assert filename == f"code-review-{entry['run_id']}.pdf"
    assert pdf[:5] == b"%PDF-"
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 5000
    # The document title is written uncompressed into the PDF metadata.
    assert entry["run_id"].encode() in pdf
    assert pdf.count(b"/Type /Page") >= 1


@pytest.mark.parametrize("sample_id", SAMPLE_IDS)
def test_assistant_answers_are_grounded_and_cited(graded, sample_id):
    entry = _entry(graded, sample_id)
    payload = chat(entry["run_id"], "How do I fix SQL injection in this code?")

    assert payload["mode"] == "retrieval_only"
    assert payload["grounded"] is True
    assert payload["citations"], "a grounded answer must cite the knowledge base"
    known_sources = {
        citation["source"] for citation in payload["citations"]
    }
    assert known_sources
    for citation in payload["citations"]:
        assert citation["source"].endswith((".md", ".txt"))
        assert f"[{citation['index']}]" in payload["answer"]
    assert payload["analysis_references"]


def test_detection_totals_are_reported(graded):
    """Summarise the measured confusion matrix for the M4 test report."""
    lines = []
    totals = Counter()
    for sample_id in SAMPLE_IDS:
        grade = _grade(_entry(graded, sample_id))
        tp = len(grade["true_positives"])
        fn = len(grade["false_negatives"])
        fp = len(grade["false_positives"])
        tn = len(grade["true_negatives"])
        totals.update({"tp": tp, "fn": fn, "fp": fp, "tn": tn})
        lines.append(f"{sample_id}: TP={tp} FN={fn} FP={fp} clean_controls={tn}")
    assert totals["fn"] == 0, "\n".join(lines)
    assert totals["fp"] == 0, "\n".join(lines)
    assert totals["tp"] == sum(
        len(sample["expected_detections"]) for sample in SAMPLES
    ), "\n".join(lines)
