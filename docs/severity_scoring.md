# Severity Scoring — M2 (deterministic, documented)

## Formula

```
severity_score = round(base_impact * exploitability_factor, 1)   # capped at 10.0
```

- **base_impact** — a fixed weight per rule, defined once in
  `analysis/rule_catalog.py` (e.g. SQL injection / CWE-89 → 9.4, magic number → 1.5).
  No detector hardcodes an impact; both agents derive scores from this one table.
- **exploitability_factor** — exactly one of three constants (`analysis/severity.py`):
  | factor | when |
  |---|---|
  | 1.00 | sink demonstrably receives an untrusted value (detector traced it) |
  | 0.85 | dangerous pattern present, pattern-level evidence only |
  | 0.70 | heuristic warning (code smells, design concerns) — every quality finding |

- **Severity label bands** (no rung skipped): `critical` 9.0–10.0, `high` 7.0–8.9,
  `medium` 4.0–6.9, `low` 0.1–3.9, `info` 0.

## Confidence is NOT the score

`confidence` (0–1 per rule in the catalog) is kept as a **separate heuristic
certainty tier** used for ordering/filtering. It is never multiplied into
`severity_score` and is not treated as a measured probability.

## Finding kind

Every rule is either `finding_kind = "vulnerability"` (a concrete dangerous
sink matched by evidence) or `"heuristic_warning"` (smell/design concern).
The distinction is surfaced on every finding so heuristic warnings are never
presented as proven vulnerabilities.

## Health score (whole run)

```
health = 100 - min(100, sum(w_band for each finding))
w = critical 25, high 12, medium 5, low 2, info 0
```

## Reproduce

All scoring is a pure function of the run input — no LLM, no clock, no
environment dependence:

```python
from analysis.severity import compute_finding_score, health_score, score_band
from analysis.security_rules import analyze_python_security

findings = analyze_python_security(code, "x.py")
for f in findings:
    compute_finding_score(f)
print(score_band(f.severity_score), health_score(findings))
```

Bandit-sourced findings use a curated per-test-id base impact table
(`BASE_IMPACT_BY_TEST` in `analysis/bandit_client.py`, default 7.5) combined
with Bandit's own severity tier (high ×1.00, medium ×0.85, low ×0.70).
