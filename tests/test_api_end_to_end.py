"""Phase 3/4 tests: live-server round trips for the M2 analysis endpoints
plus the M1 regression guarantees (original routes byte-identical behavior)."""
import json
import threading
import time
import urllib.request
import urllib.error

import pytest

from server import SubmissionHandler
from http.server import ThreadingHTTPServer

PY_SQLI = """import sqlite3


def get_user(conn, uid):
    cur = conn.cursor()
    q = "SELECT * FROM users WHERE id=" + uid
    cur.execute(q)
"""

PY_SYNTAX_ERROR = "def broken()\n    return 1\n"

REJECT_JS = "const express = require('express');\nconsole.log('hi');\n"


@pytest.fixture(scope="module")
def server_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SubmissionHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield url
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


# ---- M1 regression --------------------------------------------------------

def test_m1_health_unchanged(server_url):
    status, body = get_json(server_url, "/api/health")
    assert status == 200
    assert body["status"] == "healthy"
    assert "timestamp" in body


def test_m1_validate_python_sqli_valid_syntax(server_url):
    status, body = post_json(server_url, "/api/submissions/validate",
                             {"code": PY_SQLI, "language": "python"})
    assert status == 200
    assert body["valid"] is True
    assert body["rejected_code"] is False


def test_m1_rejects_javascript(server_url):
    with pytest.raises(urllib.error.HTTPError) as err:
        post_json(server_url, "/api/submissions/validate",
                  {"code": REJECT_JS, "language": "auto"})
    body = json.loads(err.value.read().decode())
    assert err.value.code == 422
    assert body["rejected_language"] is True


def test_m1_syntax_error_still_reported(server_url):
    status, body = post_json(server_url, "/api/submissions/validate",
                             {"code": PY_SYNTAX_ERROR, "language": "python"})
    assert status == 200
    assert body["valid"] is False


# ---- M2 analysis endpoints ------------------------------------------------

def test_m2_analysis_runs_pipeline(server_url):
    status, body = post_json(server_url, "/api/analysis",
                             {"code": PY_SQLI, "language": "python",
                              "filename": "repo.py"})
    assert status == 200
    assert body["run_id"].startswith("run-")
    assert body["status"] in ("COMPLETED", "PARTIAL")
    assert body["health_score"] is not None
    assert all(a["status"] in ("succeeded", "failed", "timeout")
               for a in body["agent_results"])


def test_m2_findings_endpoint_returns_sqli(server_url):
    _, body = post_json(server_url, "/api/analysis",
                        {"code": PY_SQLI, "language": "python", "filename": "repo.py"})
    status, findings = get_json(server_url, f"/api/analysis/{body['run_id']}/findings")
    assert status == 200
    rule_ids = {f["rule_id"] for f in findings["findings"]}
    assert "S-PY-SQLI" in rule_ids
    sqli = [f for f in findings["findings"] if f["rule_id"] == "S-PY-SQLI"][0]
    assert sqli["line_start"] == 6  # dynamic SQL construction line (rule convention)
    assert sqli["severity_score"] == 9.4
    assert sqli["cwe_id"] == "CWE-89"


def test_m2_findings_filter_by_category(server_url):
    _, body = post_json(server_url, "/api/analysis",
                        {"code": PY_SQLI, "language": "python", "filename": "repo.py"})
    _, security = get_json(server_url,
                           f"/api/analysis/{body['run_id']}/findings?category=security")
    assert all(f["category"] == "security" for f in security["findings"])


def test_m2_analysis_rejects_syntax_error_with_422(server_url):
    with pytest.raises(urllib.error.HTTPError) as err:
        post_json(server_url, "/api/analysis",
                  {"code": PY_SYNTAX_ERROR, "language": "python"})
    assert err.value.code == 422
    payload = json.loads(err.value.read().decode())
    assert payload["error"] == "syntax_error"


def test_m2_analysis_rejects_non_python_java(server_url):
    with pytest.raises(urllib.error.HTTPError) as err:
        post_json(server_url, "/api/analysis",
                  {"code": REJECT_JS, "language": "auto"})
    assert err.value.code == 422


def test_m2_analysis_rejects_oversized_payload(server_url):
    big = "x = 1\n" + ("# padding line\n" * 15000)  # > 200 KB
    with pytest.raises(urllib.error.HTTPError) as err:
        post_json(server_url, "/api/analysis",
                  {"code": big, "language": "python"})
    assert err.value.code == 413
    payload = json.loads(err.value.read().decode())
    assert payload["error"] == "payload_too_large"


def test_m2_unknown_run_is_404(server_url):
    with pytest.raises(urllib.error.HTTPError) as err:
        get_json(server_url, "/api/analysis/run-does-not-exist")
    assert err.value.code == 404
