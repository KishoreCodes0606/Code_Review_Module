"""M3 HTTP tests: every new route against a live threaded server, real pipeline."""
import json
import threading
import urllib.error
import urllib.request

import pytest

from http.server import ThreadingHTTPServer

from m3 import store
from server import SubmissionHandler
from tests.fixtures import PY_CLEAN, PY_VULNERABLE

PY_SQLI_ONLY = """import sqlite3


def get_user(conn, uid):
    cur = conn.cursor()
    q = "SELECT * FROM users WHERE id=" + uid
    cur.execute(q)
    return cur.fetchone()
"""


@pytest.fixture(scope="module")
def server_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SubmissionHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(scope="module", autouse=True)
def reset_artifacts():
    store.reset()
    yield
    store.reset()


def _request(url, path, payload=None, method=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url + path, data=data, method=method or ("POST" if data else "GET"),
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


@pytest.fixture(scope="module")
def run(server_url):
    status, _, body = _request(server_url, "/api/analysis",
                               {"code": PY_VULNERABLE, "language": "python",
                                "filename": "vulnerable.py"})
    assert status == 200
    payload = json.loads(body)
    assert payload["status"] in ("COMPLETED", "PARTIAL")
    return payload


# ---- status -----------------------------------------------------------------

def test_m3_status_reports_real_capabilities(server_url):
    status, headers, body = _request(server_url, "/api/m3/status")
    assert status == 200
    payload = json.loads(body)
    assert payload["m3"]["available"] is True
    caps = payload["m3"]["capabilities"]
    assert caps["remediation"]["auto_apply"] is False
    assert caps["assistant"]["citation_required"] is True
    assert caps["knowledge_base"]["available"] is True
    assert set(caps["report"]["formats"]) == {"json", "pdf"}
    assert headers.get("X-M3-Supported") == "true"


def test_analysis_response_carries_health(run):
    health = run["health"]
    assert health["available"] in (True, False)
    assert "formula" in health
    assert health["weights"]["critical"] == 25
    if run["status"] == "COMPLETED":
        assert isinstance(health["score"], int)
    else:
        assert health["score"] is None


# ---- remediation ------------------------------------------------------------

def test_remediation_route_returns_agent_output(server_url, run):
    status, _, body = _request(server_url, f"/api/analysis/{run['run_id']}/remediation")
    assert status == 200
    payload = json.loads(body)["remediation"]
    assert payload["finding_count"] == run["finding_count"]
    assert payload["mode"] in ("deterministic", "llm_assisted")
    assert payload["counts"]["suggested"] >= 1
    item = payload["findings"][0]
    for field in ("finding_id", "rule_id", "problem_explanation", "recommended_fix",
                  "corrected_code", "best_practice", "reason_for_fix",
                  "source_location", "remediation_status"):
        assert field in item


def test_remediation_is_cached_between_calls(server_url, run):
    _, _, first = _request(server_url, f"/api/analysis/{run['run_id']}/remediation")
    _, _, second = _request(server_url, f"/api/analysis/{run['run_id']}/remediation")
    assert json.loads(first)["remediation"]["generated_at"] == \
        json.loads(second)["remediation"]["generated_at"]


# ---- summary ----------------------------------------------------------------

def test_summary_route_returns_pr_summary(server_url, run):
    status, _, body = _request(server_url, f"/api/analysis/{run['run_id']}/summary")
    assert status == 200
    summary = json.loads(body)["summary"]
    assert summary["review_status"]["code"] in (
        "APPROVED_WITH_SUGGESTIONS", "CHANGES_REQUESTED", "INCOMPLETE_REVIEW",
    )
    assert summary["finding_count"] == run["finding_count"]
    assert summary["prioritized_fixes"]
    assert summary["final_recommendation"]
    assert summary["caveats"]


# ---- assistant --------------------------------------------------------------

def test_chat_route_answers_with_citations(server_url, run):
    status, _, body = _request(server_url, "/api/analysis/chat",
                               {"run_id": run["run_id"],
                                "question": "How do I prevent SQL injection in Python?"})
    assert status == 200
    payload = json.loads(body)
    assert payload["grounded"] is True
    assert payload["citations"]
    assert "sql" in payload["citations"][0]["source"].lower()


def test_chat_route_reports_missing_kb_content(server_url, run):
    _, _, body = _request(server_url, "/api/analysis/chat",
                          {"run_id": run["run_id"],
                           "question": "What is the capital of France?"})
    payload = json.loads(body)
    assert payload["grounded"] is False
    assert payload["citations"] == []


def test_chat_history_route(server_url, run):
    status, _, body = _request(server_url, f"/api/analysis/{run['run_id']}/chat/history")
    assert status == 200
    payload = json.loads(body)
    assert payload["count"] >= 2
    assert {m["role"] for m in payload["messages"]} == {"user", "assistant"}


def test_chat_missing_question_is_400(server_url, run):
    status, _, body = _request(server_url, "/api/analysis/chat", {"run_id": run["run_id"]})
    assert status == 400
    assert json.loads(body)["error"] == "Missing question"


def test_chat_unknown_run_is_404(server_url):
    status, _, body = _request(server_url, "/api/analysis/chat",
                               {"run_id": "run-nope", "question": "hello?"})
    assert status == 404
    assert json.loads(body)["error"] == "Run Not Found"


# ---- reports ----------------------------------------------------------------

def test_json_report_contains_real_data(server_url, run):
    status, headers, body = _request(server_url, f"/api/analysis/{run['run_id']}/report?format=json")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")
    envelope = json.loads(body)
    report = envelope["report"]
    assert report["run"]["run_id"] == run["run_id"]
    assert len(report["findings"]) == run["finding_count"]
    assert report["remediation"]["finding_count"] == run["finding_count"]
    assert report["summary"]["run_id"] == run["run_id"]


def test_pdf_report_is_a_real_pdf_download(server_url, run):
    status, headers, body = _request(server_url, f"/api/analysis/{run['run_id']}/report?format=pdf")
    assert status == 200
    assert headers.get("Content-Type") == "application/pdf"
    assert "attachment" in headers.get("Content-Disposition", "")
    assert ".pdf" in headers.get("Content-Disposition", "")
    assert body[:5] == b"%PDF-"
    assert len(body) > 3000


def test_invalid_report_format_is_400(server_url, run):
    status, _, body = _request(server_url, f"/api/analysis/{run['run_id']}/report?format=xml")
    assert status == 400
    assert json.loads(body)["error"] == "Invalid format"


@pytest.mark.parametrize("suffix", ["remediation", "summary", "report?format=json"])
def test_unknown_run_is_404_for_m3_routes(server_url, suffix):
    status, _, body = _request(server_url, f"/api/analysis/run-nope/{suffix}")
    assert status == 404
    assert json.loads(body)["error"] == "Run Not Found"


# ---- M1/M2 preservation -----------------------------------------------------

def test_m2_findings_route_still_works(server_url, run):
    status, _, body = _request(server_url, f"/api/analysis/{run['run_id']}/findings")
    assert status == 200
    payload = json.loads(body)
    assert payload["count"] == run["finding_count"]
    assert payload["findings"]


def test_m1_health_and_validation_unchanged(server_url):
    status, _, body = _request(server_url, "/api/health")
    assert status == 200 and json.loads(body)["status"] == "healthy"

    status, _, body = _request(server_url, "/api/submissions/validate",
                               {"code": PY_CLEAN, "language": "python"})
    assert status == 200 and json.loads(body)["valid"] is True


def test_partial_analysis_withholds_score_but_keeps_findings(server_url):
    """A failing M3 agent must never destroy M2 findings or inflate the score."""
    status, _, body = _request(server_url, "/api/analysis",
                               {"code": PY_SQLI_ONLY, "language": "python",
                                "filename": "repo.py"})
    assert status == 200
    payload = json.loads(body)
    assert payload["status"] in ("COMPLETED", "PARTIAL")
    if payload["status"] != "COMPLETED":
        assert payload["health"]["score"] is None

    findings_status, _, findings_body = _request(
        server_url, f"/api/analysis/{payload['run_id']}/findings"
    )
    assert findings_status == 200
    assert json.loads(findings_body)["count"] >= 1
