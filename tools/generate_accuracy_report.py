"""Generate docs/accuracy_report.md from ACTUAL pipeline runs over the golden
fixtures. Precision/recall/F1 are computed, never asserted or fabricated.

Security-detection accuracy only (that is where we have ground truth);
quality detection is exercised by the unit tests and reported qualitatively.
"""
from __future__ import annotations

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import (PY_VULNERABLE, PY_CLEAN, JAVA_VULNERABLE,
                            JAVA_CLEAN, PY_GROUND_TRUTH, JAVA_GROUND_TRUTH)
from orchestrator.pipeline import analyze_code, get_run

# rule_id -> vulnerability category (union across custom rules + analyzers)
RULE_CATEGORY = {
    "S-PY-SQLI": "sqli", "S-JAVA-SQLI": "sqli", "bandit-B608": "sqli",
    "S-PY-SHELL": "cmdi", "S-PY-CMDI": "cmdi", "S-JAVA-CMDI": "cmdi",
    "bandit-B602": "cmdi", "bandit-B605": "cmdi",
    "S-PY-DESER": "deser", "S-JAVA-DESER": "deser", "bandit-B301": "deser",
    "bandit-B506": "deser",
    "S-PY-PATH": "path",
    "S-PY-CRYPTO": "crypto", "S-JAVA-CRYPTO": "crypto", "bandit-B324": "crypto",
    "S-PY-SECRETS": "secrets", "S-JAVA-SECRETS": "secrets",
    "bandit-B105": "secrets", "bandit-B106": "secrets", "bandit-B107": "secrets",
}


def run_case(name: str, code: str, lang: str):
    rid = analyze_code(code, lang, name)
    state = get_run(rid)
    detected: set[str] = set()
    unknown_rules: list[str] = []
    for f in state.merged_findings:
        if f.category != "security":
            continue
        cat = RULE_CATEGORY.get(f.rule_id)
        if cat is None:
            unknown_rules.append(f.rule_id)
        else:
            detected.add(cat)
    return state, detected, sorted(set(unknown_rules))


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    return p, r, f1


def main() -> str:
    cases = [
        ("py_vulnerable", PY_VULNERABLE, "python", PY_GROUND_TRUTH),
        ("py_clean", PY_CLEAN, "python", set()),
        ("java_vulnerable", JAVA_VULNERABLE, "java", JAVA_GROUND_TRUTH),
        ("java_clean", JAVA_CLEAN, "java", set()),
    ]
    rows, tp_total = [], 0
    fp_total, fn_total = 0, 0
    for name, code, lang, truth in cases:
        state, detected, unknown = run_case(name, code, lang)
        tp = len(truth & detected)
        fp = len(detected - truth)
        fn = len(truth - detected)
        p, r, f1 = prf(tp, fp, fn)
        tp_total += tp; fp_total += fp; fn_total += fn
        rows.append((name, lang, sorted(truth), sorted(detected), unknown,
                     tp, fp, fn, p, r, f1, state.status,
                     state.metrics.get("pmd_status")))
    p_all, r_all, f1_all = prf(tp_total, fp_total, fn_total)

    lines = [
        "# M2 Detection Accuracy Report",
        "",
        f"Generated: {datetime.datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Methodology",
        "",
        "Precision, recall, and F1 below are computed from actual pipeline runs",
        "of the golden fixtures in `tests/fixtures.py` on this exact machine and",
        "environment; nothing is asserted. Ground truth is expressed as",
        "vulnerability *categories* hand-labeled against each vulnerable fixture",
        "({} for the Python sample, {} for the Java one); any security finding on",
        "a fixture with no ground-truth category counts as a false positive,",
        "including on the clean samples. Security findings only; quality findings",
        "are validated by the unit tests instead.",
        "",
        "| fixture | language | ground truth | detected | unexpected | TP | FP | FN | precision | recall | F1 |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, lang, truth, detected, unknown, tp, fp, fn, p, r, f1, status, pmd in rows:
        lines.append(
            f"| {name} | {lang} | {', '.join(truth) or '—'} |"
            f" {', '.join(detected) or '—'} | {', '.join(unknown) or '—'} |"
            f" {tp} | {fp} | {fn} | {p:.2f} | {r:.2f} | {f1:.2f} |")
    lines += [
        "",
        f"**Overall (micro):** TP={tp_total}, FP={fp_total}, FN={fn_total} → "
        f"precision={p_all:.2f}, recall={r_all:.2f}, F1={f1_all:.2f}",
        "",
        "## Environment notes",
        "",
        f"- PMD status during runs: {rows[2][12] or 'n/a (python runs)'} — "
        "PMD is download-on-demand; 'skipped'/'unavailable' means custom "
        "javalang detectors carried Java quality analysis (documented fallback).",
        "- Bandit findings (rule ids `bandit-*`) merge into the same categories.",
        "- Clean fixtures are required to produce zero security findings; any",
        "  emission there is counted as a false positive above.",
        "- These numbers reflect ONLY these samples; they are not a claim of",
        "  general accuracy or OWASP coverage.",
        "",
    ]
    out_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "docs", "accuracy_report.md")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {out_path}")
    print(f"overall: precision={p_all:.2f} recall={r_all:.2f} F1={f1_all:.2f} "
          f"(TP={tp_total} FP={fp_total} FN={fn_total})")
    return out_path


if __name__ == "__main__":
    main()
