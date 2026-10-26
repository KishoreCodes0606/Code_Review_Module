"""Deterministic severity scoring engine (docs/severity_scoring.md).

formula (documented, reproducible, explainable to a mentor):

    severity_score = round(base_impact * exploitability_factor, 1)   (capped 10.0)

- base_impact: fixed per rule_id from analysis/rule_catalog.py (e.g. CWE-89 -> 9.4).
- exploitability_factor:
      1.00 if the sink demonstrably receives an untrusted value flowing into it
           (detectors mark this explicitly)
      0.85 if a dangerous pattern exists but data flow into the sink is
           pattern-level evidence only
      0.70 for heuristic warnings (smells/design concerns)
- confidence is SEPARATE and never multiplied into the score; it is a heuristic
  certainty tier (see rule catalog) so findings can be ordered/filterable.
- severity label bands: 9.0-10.0 critical, 7.0-8.9 high, 4.0-6.9 medium,
  0.1-3.9 low, 0 info.
- overall health score = 100 - min(100, sum of weighted penalties by severity).

The LLM is not involved; results are pure functions of inputs.
"""
from __future__ import annotations

from analysis.findings import Finding

EXPLOITABILITY_CONFIRMED = 1.00
EXPLOITABILITY_PATTERN = 0.85
EXPLOITABILITY_HEURISTIC = 0.70

SEVERITY_WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}


def score_band(score: float) -> dict:
    if score >= 9.0:
        return {"label": "critical", "from": 9.0, "to": 10.0}
    if score >= 7.0:
        return {"label": "high", "from": 7.0, "to": 8.9}
    if score >= 4.0:
        return {"label": "medium", "from": 4.0, "to": 6.9}
    if score > 0.0:
        return {"label": "low", "from": 0.1, "to": 3.9}
    return {"label": "info", "from": 0.0, "to": 0.0}



def compute_finding_score(finding: Finding, confirmed: bool | None = None) -> Finding:
    """Set severity/score fields on a Finding from its rule's base_impact.

    confirmed=True when the detector can trace an untrusted value into the
    sink; confirmed=False for a pattern-level detector hit; heuristic warnings
    always use the heuristic factor. Returns the same Finding for chaining.
    """
    spec = finding and _spec(finding.rule_id)
    base = spec.base_impact if spec else 7.0
    if finding.finding_kind == "heuristic_warning":
        factor = EXPLOITABILITY_HEURISTIC
    elif confirmed is None or confirmed:
        factor = EXPLOITABILITY_CONFIRMED
    else:
        factor = EXPLOITABILITY_PATTERN
    finding.severity_score = round(min(10.0, base * factor), 1)
    finding.severity = score_band(finding.severity_score)["label"]
    return finding


def health_score(findings: list[Finding]) -> int:
    """100 = clean; penalise by severity band weight (design doc 7.5)."""
    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return 100 - min(100, penalty)


def _spec(rule_id: str):
    from analysis.rule_catalog import ALL_RULES
    return ALL_RULES.get(rule_id)
