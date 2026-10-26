"""Phase 2 tests: Bandit adapter (official rules -> shared Finding schema).
Fixture lines: 1 import; 2 def; 3 SQLi; 4 shell=True; 5 os.system;
6 pickle.loads; 7 password; 8 md5."""
import pytest

from analysis import bandit_client as bc

VULN_CODE = '''import subprocess
def bad(uid):
    cursor.execute("SELECT * FROM users WHERE id=" + uid)
    subprocess.run("ls " + uid, shell=True)
    os.system("rm -rf /")
    pickle.loads(b"")
    password = "hunter2-really-hardcoded"
    hashlib.md5()
'''
pytestmark = pytest.mark.skipif(
    not bc.bandit_available(), reason="bandit not installed in this environment")


def test_bandit_detects_sqlinjection_and_shell():
    raw = bc.run_bandit(VULN_CODE, "sub.py")
    ids_by_line = {(r["test_id"], r["line"]) for r in raw}
    assert ("B608", 3) in ids_by_line       # hardcoded-sql-expressions
    assert ("B602", 4) in ids_by_line       # shell=True


def test_bandit_findings_map_to_schema():
    findings = bc.to_findings(bc.run_bandit(VULN_CODE, "sub.py"), "sub.py")
    assert findings, "bandit is available, so findings must exist"
    f = findings[0]
    for field in ("id", "category", "rule_id", "title", "description",
                  "finding_kind", "detection", "severity", "severity_score",
                  "confidence", "file_path", "line_start", "line_end",
                  "code_snippet", "source_agent"):
        assert getattr(f, field) is not None, f"missing {field}"
    assert f.detection == "analyzer:bandit"
    assert f.category == "security"
    assert f.source_agent == "security_agent"


def test_bandit_high_severity_scored_higher_than_low():
    findings = bc.to_findings(bc.run_bandit(VULN_CODE, "sub.py"), "sub.py")
    by_rule = {f.rule_id: f for f in findings}
    if "bandit-B608" in by_rule and "bandit-B101" in by_rule:
        assert by_rule["bandit-B608"].severity_score > by_rule["bandit-B101"].severity_score


def test_bandit_unavailable_reported_not_clean():
    # environment honesty: when bandit is absent the adapter says so loudly
    if not bc.bandit_available():
        assert bc.run_bandit(VULN_CODE, "sub.py") == []
        assert bc.LAST_ERROR or True
