"""Bandit adapter for Python security scans.

Bandit runs as a static-analyzer subprocess over a temp file (never executes
the analysed code). Its official rule IDs (B-xxx), severity,
confidence and CWE tags are preserved; our severity engine recomputes the
final score from the curated base-impact table below, and Bandit's own
severity sets the exploitability factor (HIGH -> confirmed, MEDIUM -> pattern,
LOW/None -> heuristic).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

BASE_IMPACT_BY_TEST = {
    "B101": 3.0, "B102": 9.3, "B103": 9.3, "B104": 5.5, "B105": 8.4,
    "B106": 8.4, "B107": 8.4, "B108": 5.0, "B110": 2.5, "B112": 5.0,
    "B113": 5.9, "B201": 4.5, "B202": 6.0, "B203": 6.0, "B204": 6.0,
    "B205": 6.0, "B206": 6.0, "B301": 9.0, "B302": 8.0, "B303": 5.5,
    "B304": 5.5, "B305": 5.5, "B306": 5.5, "B307": 9.3, "B308": 5.0,
    "B310": 7.5, "B311": 3.0, "B312": 9.4, "B313": 9.0, "B314": 9.0,
    "B315": 9.0, "B316": 9.0, "B317": 9.0, "B318": 9.0, "B319": 9.0,
    "B320": 9.0, "B323": 5.9, "B324": 5.5, "B325": 4.0, "B326": 4.5,
    "B401": 3.0, "B402": 6.5, "B403": 4.5, "B404": 2.0, "B405": 2.0,
    "B406": 4.0, "B407": 4.0, "B408": 5.0, "B409": 2.0, "B410": 6.0,
    "B411": 6.0, "B412": 4.5, "B413": 5.5, "B415": 4.0, "B416": 7.5,
    "B417": 7.5, "B418": 4.0, "B419": 6.0, "B421": 4.0, "B424": 5.9,
    "B425": 4.0, "B426": 4.0, "B427": 4.5, "B601": 8.0, "B602": 9.6,
    "B603": 8.0, "B604": 9.5, "B605": 9.6, "B606": 9.6, "B607": 7.0,
    "B608": 9.4, "B609": 8.0, "B610": 7.0, "B611": 7.0, "B612": 6.5,
    "B613": 6.5, "B614": 5.0, "B615": 7.0, "B701": 5.5, "B702": 5.5,
    "B703": 5.5, "B704": 7.0, "B705": 7.0, "B706": 7.5, "B707": 5.5,
}
AGENT = "security_agent"
DETECTION = "analyzer:bandit"

LAST_ERROR: str | None = None
"""Last scanner failure message for honest diagnostics (scanner trouble is
never reported as a clean scan)."""


def bandit_available() -> bool:
    """True when bandit is importable by the interpreter that runs us."""
    try:
        import bandit  # noqa: F401
        return True
    except Exception:
        return False


def run_bandit(code: str, filename: str) -> list[dict]:
    """Returns normalized Bandit finding dicts. [] when bandit is missing —
    the caller records that as a scanner status, never as a clean scan."""
    if not bandit_available():
        return []
    tmp_dir = tempfile.mkdtemp(prefix="m2_bandit_")
    try:
        base = os.path.basename(filename or "submission.py")
        if not base.lower().endswith(".py"):
            base += ".py"
        target = os.path.join(tmp_dir, base)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(code)
        cmd = [*_bandit_exe(), "-q", "-f", "json", target]
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace")
        data = json.loads(completed.stdout or "{}")
        out = []
        for r in data.get("results", []):
            cwe_raw = r.get("issue_cwe")
            out.append({
                "test_id": r.get("test_id"),
                "title": (r.get("issue_text") or "").split("\n")[0],
                "line": int(r.get("line_number") or 1),
                "line_end": r.get("line_range") or [int(r.get("line_number") or 1)],
                "severity": (r.get("issue_severity") or "LOW").lower(),
                "confidence": (r.get("issue_confidence") or "LOW").lower(),
                "cwe": cwe_raw if cwe_raw else None,
                "code": r.get("code") or "",
            })
        return out
    except Exception as e:
        global LAST_ERROR
        LAST_ERROR = f"bandit run failed: {e!r}"
        return []
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _bandit_exe() -> list[str]:
    """Command prefix to launch bandit with the current interpreter.
    "python -m bandit" is portable (Store-Python installs Scripts off PATH)."""
    import sys
    return [sys.executable, "-m", "bandit"]


def to_findings(bandit_results: list[dict], file_path: str):
    """Convert Bandit dicts to Finding objects using the shared engine."""
    from analysis.findings import Finding
    from analysis.rule_catalog import SECURITY as _SEC
    findings = []
    for r in bandit_results:
        rule_id = f"bandit-{r['test_id']}"
        spec = _SEC.get("S-BANDIT-GENERIC")
        f = Finding.from_rule(
            rule_id, r["line"], _end_of(r), (r.get("code") or "").strip()[:200],
            file_path, r["title"], AGENT, DETECTION, spec,
            title_override=f"Bandit {r['test_id']}: {r['title']}"[:120])
        # deterministic score via curated table + bandit severity factor
        f.severity_score, f.severity = _score_from_bandit(r["test_id"], r["severity"])
        findings.append(f)
    return findings


def _end_of(r: dict) -> int:
    lr = r.get("line_end")
    if isinstance(lr, list) and lr:
        return int(lr[-1])
    if isinstance(lr, int):
        return int(lr)
    return int(r.get("line", 1) or 1)


def _score_from_bandit(test_id: str, severity: str) -> tuple[float, str]:
    from analysis.severity import score_band
    base = BASE_IMPACT_BY_TEST.get(test_id, 7.5)
    factor = {"high": 1.0, "medium": 0.85}.get((severity or "low").lower(), 0.70)
    score = round(min(10.0, base * factor), 1)
    return score, score_band(score)["label"]
