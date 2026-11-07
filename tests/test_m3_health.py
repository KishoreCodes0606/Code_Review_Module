"""M3 health-score tests: formula, de-duplication, caps, labels, withholding."""
import pytest

from m3.health import RULE_FAMILIES, compute_health


def finding(rule_id="S-PY-SQLI", severity="critical", file_path="a.py", line_start=6):
    return {
        "id": f"{rule_id}-{line_start}",
        "rule_id": rule_id,
        "severity": severity,
        "file_path": file_path,
        "line_start": line_start,
    }


def test_weights_and_formula_are_explicit():
    payload = compute_health("COMPLETED", [finding(severity="critical")])
    assert payload["weights"] == {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
    assert payload["formula"].startswith("score = max(0, 100 - min(100,")
    assert payload["penalty"] == 25
    assert payload["score"] == 75


def test_score_deducts_each_severity_once():
    findings = [
        finding("S-PY-SHELL", "critical", line_start=20),
        finding("S-PY-DESER", "critical", line_start=28),
        finding("S-PY-CRYPTO", "medium", line_start=3),
        finding("S-PY-QUALITY", "low", line_start=40),
        finding("S-PY-INFO", "info", line_start=41),
    ]
    payload = compute_health("COMPLETED", findings)
    # 25 + 25 + 5 + 2 + 0
    assert payload["penalty"] == 57
    assert payload["score"] == 43
    assert payload["counts"] == {"critical": 2, "high": 0, "medium": 1, "low": 1, "info": 1}
    assert payload["scored_finding_count"] == 5


def test_duplicate_rule_families_charged_once():
    """Bandit and the built-in engine report the same sink — charge it once."""
    findings = [
        finding("S-PY-SQLI", "critical", line_start=6),
        finding("bandit-B608", "critical", line_start=6),
    ]
    payload = compute_health("COMPLETED", findings)
    assert payload["duplicates_ignored"] == 1
    assert payload["scored_finding_count"] == 1
    assert payload["penalty"] == 25
    assert payload["score"] == 75
    assert payload["duplicate_details"][0]["rule_id"] == "bandit-B608"
    assert payload["duplicate_details"][0]["duplicate_of"] == "S-PY-SQLI"


def test_duplicates_on_different_lines_are_both_counted():
    findings = [
        finding("S-PY-SQLI", "critical", line_start=6),
        finding("bandit-B608", "critical", line_start=17),
    ]
    payload = compute_health("COMPLETED", findings)
    assert payload["duplicates_ignored"] == 0
    assert payload["penalty"] == 50


def test_duplicate_keeps_higher_severity_representative():
    findings = [
        finding("S-PY-SQLI", "low", line_start=6),
        finding("bandit-B608", "critical", line_start=6),
    ]
    payload = compute_health("COMPLETED", findings)
    # The grouped issue must not be understated by the lower-severity report.
    assert payload["counts"]["critical"] == 1
    assert payload["counts"]["low"] == 0
    assert payload["penalty"] == 25


@pytest.mark.parametrize(
    "rule_id,family",
    [
        ("bandit-B602", "S-PY-SHELL"),
        ("bandit-B608", "S-PY-SQLI"),
        ("bandit-B301", "S-PY-DESER"),
        ("bandit-B506", "S-PY-DESER"),
        ("bandit-B307", "S-PY-EVAL"),
        ("bandit-B324", "S-PY-CRYPTO"),
        ("bandit-B303", "S-PY-CRYPTO"),
        ("bandit-B105", "S-PY-SECRET"),
        ("bandit-B605", "S-PY-CMDI"),
    ],
)
def test_rule_family_aliases(rule_id, family):
    assert RULE_FAMILIES[rule_id] == family


def test_penalty_is_capped_and_reported():
    findings = [finding(f"R-{i}", "critical", line_start=i) for i in range(1, 10)]
    payload = compute_health("COMPLETED", findings)
    assert payload["penalty"] == 225
    assert payload["capped"] is True
    assert payload["score"] == 0


def test_label_bands():
    def label(items):
        return compute_health("COMPLETED", items)["label"]

    crit = lambda i: finding(f"R-{i}", "critical", line_start=i)
    high = lambda i: finding(f"H-{i}", "high", line_start=i)
    med = lambda i: finding(f"M-{i}", "medium", line_start=i)
    low = lambda i: finding(f"L-{i}", "low", line_start=i)

    clean = compute_health("COMPLETED", [])
    assert clean["score"] == 100 and clean["label"] == "excellent"

    assert label([low(1)]) == "excellent"                              # 98
    assert label([med(1), med(2)]) == "excellent"                     # 90 (band floor)
    assert label([high(1)]) == "good"                                 # 88
    assert label([crit(1)]) == "good"                                 # 75 (band floor)
    assert label([crit(1), high(2)]) == "fair"                        # 63
    assert label([crit(1), med(2), med(3), med(4)]) == "fair"         # 60 (band floor)
    assert label([crit(1), crit(2)]) == "poor"                        # 50
    assert label([crit(1), crit(2), med(3), med(4)]) == "poor"        # 40 (band floor)
    assert label([crit(1), crit(2), crit(3)]) == "critical"           # 25
    assert label([crit(i) for i in range(1, 5)]) == "critical"        # 0


def test_score_is_never_described_as_security_guarantee():
    payload = compute_health("COMPLETED", [])
    assert payload["score"] == 100
    assert "not a security guarantee" in payload["caveat"].lower()


@pytest.mark.parametrize("status", ["PARTIAL", "FAILED"])
def test_score_withheld_for_incomplete_runs(status):
    payload = compute_health(status, [finding()])
    assert payload["available"] is False
    assert payload["score"] is None
    assert payload["label"] is None
    assert status in payload["reason"]
    # The breakdown still exists so the UI can explain what was found.
    assert payload["components"]
