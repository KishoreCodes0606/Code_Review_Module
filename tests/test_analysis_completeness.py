"""Regression tests: "successful scan with 0 findings" on code that was never analysed.

Root cause this file pins down
------------------------------
Both the Java and the Python quality analyzers returned
``{"findings": [], "metrics": {"parsed": False}}`` when the built-in parser
could not read the submitted source. The Code Analysis Agent only looked at the
findings list, so it reported ``succeeded``, the orchestrator computed
``health_score = 100``, the run was marked ``COMPLETED`` and the UI showed
"No findings reported" with two green agents — a *clean* result for code that
was never analysed.

A second, narrower path had the same shape: ``pmd_client.run_pmd`` discarded
PMD's ``<error msg="ParseException...">`` nodes and reported ``status="ok"``,
so PMD failing to parse the file looked identical to PMD finding nothing.

What is asserted here:
- each agent, run on its own, detects the supported issues in a real sample;
- the orchestrator keeps both agents' findings when merging;
- an unparseable source fails the quality agent with an explicit error record;
- PMD findings collected despite that failure are still returned (run PARTIAL);
- PMD's own parse errors are surfaced instead of reported as "ok";
- the HTTP endpoints report the truth, and an incomplete run is never
  presented as a clean COMPLETED scan.

No submitted code is ever executed, and no accuracy figure is claimed here.
"""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from agents import code_analysis_agent, security_agent
from analysis import pmd_client
from orchestrator import pipeline
from server import SubmissionHandler

# --------------------------------------------------------------------------
# Samples
# --------------------------------------------------------------------------

# The exact sample requested in the bug report: SQL built by concatenation, a
# hardcoded password-like string, an unused import, a broad except handler.
USER_SAMPLE = '''import os
import json

DB_PASSWORD = "SuperSecret123"


def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cur.execute(query)
    return cur.fetchall()


def compute(x):
    try:
        return 100 / x
    except Exception:
        pass
'''

# Java 15+: 'sealed ... permits' plus a switch expression. This passes the M1
# syntax gate (which is deliberately lenient) but the built-in javalang parser
# cannot read it, which is how the silent-clean path is reached.
MODERN_JAVA = '''import java.util.List;

public sealed class ReportBuilder permits Detail {

    public String build(String rows, String a, String b, String c, String d, String e) {
        StringBuilder sb = new StringBuilder();
        if (rows != null) {
            if (a != null) {
                if (b != null) {
                    if (c != null) {
                        for (int i = 0; i < 500; i++) {
                            for (int j = 0; j < 500; j++) {
                                if (i * j > 1500) { sb.append(j * 777); }
                            }
                        }
                    }
                }
            }
        }
        String mode = switch (sb.length()) { case 0 -> "empty"; default -> "full"; };
        return mode + sb;
    }
}
'''

CLEAN_PYTHON = '''def add(left, right):
    return left + right
'''

PMD_ERROR_REPORT = '''<?xml version="1.0" encoding="UTF-8"?>
<pmd xmlns="http://pmd.sourceforge.net/report/2.0.0" version="7.9.0">
<error filename="C:\\tmp\\NotJava.java" msg="ParseException: Parse exception in file at line 2, column 1">
<![CDATA[net.sourceforge.pmd.lang.ast.ParseException]]></error>
</pmd>
'''


@pytest.fixture
def no_pmd(monkeypatch):
    """Force the documented 'PMD unavailable' fallback without any download."""
    monkeypatch.setenv("PMD_DISABLE_DOWNLOAD", "1")
    monkeypatch.setenv("PMD_SKIP", "1")


@pytest.fixture(scope="module")
def server_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SubmissionHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def post_json(url, path, payload):
    req = urllib.request.Request(
        url + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=90) as resp:
        return resp.status, json.loads(resp.read().decode())


def get_json(url, path):
    with urllib.request.urlopen(url + path, timeout=30) as resp:
        return resp.status, json.loads(resp.read().decode())


# --------------------------------------------------------------------------
# 5. Each agent tested independently, on its own sample
# --------------------------------------------------------------------------

def test_code_analysis_agent_detects_quality_issues_alone():
    findings, result, metrics = code_analysis_agent.run_agent(
        USER_SAMPLE, "python", "sample.py")

    assert result.status == "succeeded", result.error
    assert metrics.get("parsed") is True
    rules = {f.rule_id for f in findings}
    assert "Q-unused-import" in rules          # 'import os' / 'import json'
    assert "Q-broad-exception" in rules        # 'except Exception: pass'
    # every quality finding comes from the quality agent and is scored
    assert all(f.source_agent == "code_analysis_agent" for f in findings)
    assert all(f.category == "quality" for f in findings)
    assert all(f.severity in ("critical", "high", "medium", "low", "info")
               for f in findings)
    # informational findings (unused import) carry a 0.0 score by design;
    # anything above 'info' must have a real score
    assert all(f.severity_score > 0 for f in findings if f.severity != "info")


def test_security_agent_detects_vulnerabilities_alone():
    findings, result, metrics = security_agent.run_agent(
        USER_SAMPLE, "python", "sample.py")

    assert result.status == "succeeded", result.error
    rules = {f.rule_id for f in findings}
    assert "S-PY-SQLI" in rules                 # concatenated SQL into execute()
    assert "S-PY-SECRET" in rules               # DB_PASSWORD = "..."
    assert "bandit-B105" in rules               # Bandit agrees on the credential
    assert all(f.category == "security" for f in findings)
    assert all(f.source_agent == "security_agent" for f in findings)


def test_security_agent_keeps_screaming_snake_case_secret_names():
    """`DB_PASSWORD = "..."` is the common real-world shape and must be caught
    by the custom rule, not only by Bandit (Bandit may be unavailable)."""
    code = 'DB_PASSWORD = "SuperSecret123"\n'
    findings, _, _ = security_agent.run_agent(code, "python", "cfg.py")
    assert "S-PY-SECRET" in {f.rule_id for f in findings}


# --------------------------------------------------------------------------
# 6. Orchestrator merge keeps what both agents found
# --------------------------------------------------------------------------

def test_orchestrator_merges_both_agents_findings():
    run_id = pipeline.analyze_code(USER_SAMPLE, "python", "sample.py")
    state = pipeline.get_run(run_id)
    summary = pipeline.run_summary(state)

    assert summary["status"] == "COMPLETED"
    assert summary["finding_count"] == len(state.merged_findings) > 0

    merged = {f.rule_id for f in state.merged_findings}
    security_only = {f.rule_id for f in state.security_findings}
    quality_only = {f.rule_id for f in state.quality_findings}
    assert security_only and quality_only
    assert security_only <= merged              # nothing dropped in the merge
    assert quality_only <= merged
    assert summary["severity_counts"]["critical"] >= 1
    assert summary["health_score"] < 100        # real findings must cost health
    assert all(a["status"] == "succeeded" for a in summary["agent_results"])


def test_orchestrator_clean_sample_is_honestly_clean():
    run_id = pipeline.analyze_code(CLEAN_PYTHON, "python", "clean.py")
    summary = pipeline.run_summary(pipeline.get_run(run_id))
    assert summary["status"] == "COMPLETED"
    assert summary["finding_count"] == 0
    assert summary["health_score"] == 100


# --------------------------------------------------------------------------
# 3./4. The silent-clean path itself
# --------------------------------------------------------------------------

def test_unparseable_java_fails_the_quality_agent_explicitly(no_pmd):
    findings, result, metrics = code_analysis_agent.run_agent(
        MODERN_JAVA, "java", "ReportBuilder.java")

    assert result.status == "failed"            # was: succeeded
    assert result.error
    assert "analysis_incomplete" in result.error
    assert metrics.get("parsed") is False
    assert metrics.get("parse_error")           # a human-readable cause


def test_unparseable_java_is_never_reported_as_a_clean_scan(no_pmd):
    run_id = pipeline.analyze_code(MODERN_JAVA, "java", "ReportBuilder.java")
    state = pipeline.get_run(run_id)
    summary = pipeline.run_summary(state)

    assert summary["status"] == "PARTIAL"       # was: COMPLETED
    quality = [r for r in summary["agent_results"]
               if r["agent"] == "code_analysis_agent"][0]
    assert quality["status"] == "failed"
    assert quality["error"]                     # explicit error record
    # findings may legitimately be empty here — but the run never claims success
    assert not (summary["status"] == "COMPLETED"
                and all(a["status"] == "succeeded" for a in summary["agent_results"]))


def test_unparseable_python_is_never_reported_as_a_clean_scan():
    broken = "def broken(:\n    return 1\n"     # bypasses the M1 gate on purpose
    findings, result, metrics = code_analysis_agent.run_agent(
        broken, "python", "broken.py")
    assert result.status == "failed"
    assert metrics.get("parsed") is False
    assert metrics.get("parse_error")

    run_id = pipeline.analyze_code(broken, "python", "broken.py")
    assert pipeline.get_run(run_id).status in ("PARTIAL", "FAILED")


def test_pmd_findings_survive_a_javalang_parse_failure(monkeypatch):
    """Work that did run (PMD parses modern Java itself) must not be thrown
    away just because the built-in parser bailed out."""
    from analysis.findings import Finding
    from analysis.rule_catalog import QUALITY
    from analysis.severity import compute_finding_score

    def fake_add_pmd(java_path, file_path, findings):
        f = Finding.from_rule(
            "Q-long-method", 5, 9, "snippet", file_path,
            "synthetic PMD violation for the test", "code_analysis_agent",
            "analyzer:pmd", QUALITY["Q-long-method"])
        compute_finding_score(f, confirmed=False)
        findings.append(f)
        return "ok"

    # make sure the PMD step is actually reached (other test modules disable it)
    monkeypatch.setenv("PMD_DISABLE_DOWNLOAD", "0")
    monkeypatch.setenv("PMD_SKIP", "0")
    monkeypatch.setattr("analysis.java_quality.add_pmd_findings", fake_add_pmd)
    findings, result, metrics = code_analysis_agent.run_agent(
        MODERN_JAVA, "java", "ReportBuilder.java")

    assert result.status == "failed"            # the analysis was incomplete...
    assert [f.rule_id for f in findings] == ["Q-long-method"]   # ...but kept


def test_pmd_parse_error_is_not_reported_as_ok(tmp_path, monkeypatch):
    def fake_subprocess_run(cmd, **kwargs):
        report_path = cmd[cmd.index("-r") + 1]
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(PMD_ERROR_REPORT)

        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Result()

    monkeypatch.setattr(pmd_client, "ensure_pmd", lambda log=None: "pmd.cmd")
    monkeypatch.setattr(pmd_client.subprocess, "run", fake_subprocess_run)

    violations, status = pmd_client.run_pmd("C:/tmp/NotJava.java")
    assert violations == []
    assert status == "error"                    # was: "ok"


def test_pmd_xml_parser_reports_error_nodes():
    violations, errors = pmd_client._parse_xml(PMD_ERROR_REPORT)
    assert violations == []
    assert len(errors) == 1
    assert "ParseException" in errors[0]
    assert "NotJava.java" in errors[0]

    ok_report = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<pmd xmlns="http://pmd.sourceforge.net/report/2.0.0" version="7.9.0">'
        '<file name="A.java"><violation beginline="3" endline="3" rule="UnusedPrivateField">'
        'unused</violation></file></pmd>')
    violations, errors = pmd_client._parse_xml(ok_report)
    assert errors == []
    assert [v["rule"] for v in violations] == ["UnusedPrivateField"]


# --------------------------------------------------------------------------
# 6. The endpoints the React UI consumes
# --------------------------------------------------------------------------

def test_http_analysis_returns_merged_findings_from_both_agents(server_url):
    status, body = post_json(server_url, "/api/analysis", {
        "code": USER_SAMPLE, "language": "python", "filename": "sample.py"})

    assert status == 200
    assert body["status"] == "COMPLETED"
    assert body["finding_count"] >= 4
    assert all(a["status"] == "succeeded" for a in body["agent_results"])

    status, findings = get_json(
        server_url, f"/api/analysis/{body['run_id']}/findings")
    assert status == 200
    rules = {f["rule_id"] for f in findings["findings"]}
    assert {"S-PY-SQLI", "S-PY-SECRET"} <= rules        # security agent
    assert {"Q-unused-import", "Q-broad-exception"} <= rules   # quality agent
    # the endpoints agree — this is exactly the array the findings table renders
    assert findings["count"] == len(findings["findings"]) == body["finding_count"]
    assert all(f["line_start"] >= 1 for f in findings["findings"])


def test_http_analysis_of_unparseable_java_is_partial_not_clean(server_url, no_pmd):
    status, body = post_json(server_url, "/api/analysis", {
        "code": MODERN_JAVA, "language": "java", "filename": "ReportBuilder.java"})

    assert status == 200
    assert body["status"] == "PARTIAL"
    failed = [a for a in body["agent_results"] if a["status"] != "succeeded"]
    assert failed, "an agent that could not analyse the source must be reported"
    assert all(a["error"] for a in failed)

    status, findings = get_json(
        server_url, f"/api/analysis/{body['run_id']}/findings")
    assert status == 200
    assert findings["count"] == body["finding_count"]
    # a degraded run must never look like a clean scan
    assert not (body["status"] == "COMPLETED"
                and not failed
                and body["finding_count"] == 0)


def test_http_findings_for_incomplete_run_are_still_served(server_url, no_pmd):
    """Empty findings on a PARTIAL run must be served with the failure intact."""
    status, body = post_json(server_url, "/api/analysis", {
        "code": MODERN_JAVA, "language": "java", "filename": "ReportBuilder.java"})
    assert status == 200
    status, findings = get_json(
        server_url, f"/api/analysis/{body['run_id']}/findings")
    assert status == 200
    assert isinstance(findings["findings"], list)

    # the status endpoint keeps reporting the same incomplete state
    status, rerun = get_json(server_url, f"/api/analysis/{body['run_id']}")
    assert status == 200
    assert rerun["status"] == "PARTIAL"
