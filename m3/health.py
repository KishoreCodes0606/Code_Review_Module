"""Transparent, deterministic code-health scoring for M3.

Formula (identical weights to the M2 severity engine, imported so the two can
never drift):

    penalty   = sum(weight[severity] for each unique finding)
    health    = max(0, 100 - min(100, penalty))

weights: critical 25, high 12, medium 5, low 2, info 0.

Rules enforced here:
- findings are de-duplicated by remediation family + location before scoring,
  so the same underlying issue reported by the built-in engine and by Bandit
  (for example ``S-PY-SQLI`` and ``bandit-B608`` on the same line) is charged
  once;
- the penalty is capped at 100, and the response says so;
- a score is only *available* when every agent completed (status COMPLETED).
  For PARTIAL/FAILED the score is withheld instead of presenting a number
  computed from an incomplete scan as if it were meaningful;
- 100 means "no findings were reported by the implemented rules", never
  "secure".
"""
from __future__ import annotations

from analysis.severity import SEVERITY_WEIGHTS

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# Engines report the same sink under different ids. Scoring one underlying
# issue once keeps the score honest while leaving every finding visible in the
# findings table. Only aliases that describe the same weakness are grouped.
RULE_FAMILIES = {
    "bandit-B602": "S-PY-SHELL",
    "bandit-B608": "S-PY-SQLI",
    "bandit-B301": "S-PY-DESER",
    "bandit-B506": "S-PY-DESER",
    "bandit-B307": "S-PY-EVAL",
    "bandit-B324": "S-PY-CRYPTO",
    "bandit-B303": "S-PY-CRYPTO",
    "bandit-B105": "S-PY-SECRET",
    "bandit-B605": "S-PY-CMDI",
}

LABEL_BANDS = (
    (90, "excellent"),
    (75, "good"),
    (60, "fair"),
    (40, "poor"),
    (0, "critical"),
)

FORMULA = (
    "score = max(0, 100 - min(100, sum(severity_weight))) with weights "
    "critical=25, high=12, medium=5, low=2, info=0 over de-duplicated findings"
)


def _field(finding, name, default=None):
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _finding_key(finding) -> tuple:
    rule_id = _field(finding, "rule_id") or ""
    family = RULE_FAMILIES.get(rule_id, rule_id)
    return (family, _field(finding, "file_path") or "", _field(finding, "line_start"))


def _label(score: int) -> str:
    for threshold, label in LABEL_BANDS:
        if score >= threshold:
            return label
    return "critical"


def compute_health(status: str, findings: list) -> dict:
    """Return the M3 health payload for a run's merged findings."""
    unique_by_key: dict[tuple, object] = {}
    duplicates = 0
    duplicate_details = []
    for finding in findings or []:
        key = _finding_key(finding)
        existing = unique_by_key.get(key)
        severity = _field(finding, "severity")
        if existing is not None:
            duplicates += 1
            duplicate_details.append(
                {
                    "rule_id": _field(finding, "rule_id"),
                    "duplicate_of": _field(existing, "rule_id"),
                    "file_path": _field(finding, "file_path"),
                    "line_start": _field(finding, "line_start"),
                }
            )
            # Keep the higher-severity representative so grouping never
            # understates a real finding.
            if SEVERITY_WEIGHTS.get(severity, 0) > SEVERITY_WEIGHTS.get(
                _field(existing, "severity"), 0
            ):
                unique_by_key[key] = finding
            continue
        unique_by_key[key] = finding

    unique = list(unique_by_key.values())

    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in unique:
        severity = _field(finding, "severity")
        if severity in counts:
            counts[severity] += 1

    components = [
        {
            "severity": severity,
            "count": counts[severity],
            "weight_each": SEVERITY_WEIGHTS[severity],
            "deduction": counts[severity] * SEVERITY_WEIGHTS[severity],
        }
        for severity in SEVERITY_ORDER
    ]
    total_penalty = sum(component["deduction"] for component in components)
    capped = total_penalty >= 100

    payload = {
        "formula": FORMULA,
        "weights": dict(SEVERITY_WEIGHTS),
        "components": components,
        "counts": counts,
        "penalty": total_penalty,
        "capped": capped,
        "duplicates_ignored": duplicates,
        "duplicate_details": duplicate_details,
        "scored_finding_count": len(unique),
        "caveat": (
            "A score of 100 only means the implemented rules reported no findings; "
            "it is not a security guarantee. Heuristic warnings are included in the weighting."
        ),
    }

    if status != "COMPLETED":
        payload.update(
            {
                "available": False,
                "score": None,
                "label": None,
                "reason": (
                    f"The analysis run is {status}; withholding the score because it would be "
                    "computed from an incomplete set of findings."
                ),
            }
        )
        return payload

    score = max(0, 100 - min(100, total_penalty))
    payload.update(
        {
            "available": True,
            "score": score,
            "label": _label(score),
            "reason": None,
            "explanation": (
                f"{len(unique)} unique finding(s) deduct {min(100, total_penalty)} point(s)"
                + (f" after grouping {duplicates} duplicate report(s)" if duplicates else "")
                + (" (capped at 100)" if capped else "")
                + f", leaving {score}/100."
            ),
        }
    )
    return payload
