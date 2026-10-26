# M2 Detection Accuracy Report

Generated: 2026-10-26T22:58:59

## Methodology

Precision, recall, and F1 below are computed from actual pipeline runs
of the golden fixtures in `tests/fixtures.py` on this exact machine and
environment; nothing is asserted. Ground truth is expressed as
vulnerability *categories* hand-labeled against each vulnerable fixture
({} for the Python sample, {} for the Java one); any security finding on
a fixture with no ground-truth category counts as a false positive,
including on the clean samples. Security findings only; quality findings
are validated by the unit tests instead.

| fixture | language | ground truth | detected | unexpected | TP | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|---|
| py_vulnerable | python | cmdi, deser, path, sqli | cmdi, deser, path, sqli | bandit-B403, bandit-B404 | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| py_clean | python | — | — | — | 0 | 0 | 0 | 0.00 | 0.00 | 0.00 |
| java_vulnerable | java | crypto, deser, sqli | crypto, deser, sqli | — | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| java_clean | java | — | — | — | 0 | 0 | 0 | 0.00 | 0.00 | 0.00 |

**Overall (micro):** TP=7, FP=0, FN=0 → precision=1.00, recall=1.00, F1=1.00

## Environment notes

- PMD status during runs: ok — PMD is download-on-demand; 'skipped'/'unavailable' means custom javalang detectors carried Java quality analysis (documented fallback).
- Bandit findings (rule ids `bandit-*`) merge into the same categories.
- Clean fixtures are required to produce zero security findings; any
  emission there is counted as a false positive above.
- These numbers reflect ONLY these samples; they are not a claim of
  general accuracy or OWASP coverage.
