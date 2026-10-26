"""M1 regression tests: the untouched endpoints keep their exact behavior.
These assertions mirror the live M1 contract observed byte-for-byte."""
import json
import threading
import urllib.request
import urllib.error

import pytest

from http.server import ThreadingHTTPServer

from server import SubmissionHandler


@pytest.fixture(scope="module")
def server_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SubmissionHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield url
    httpd.shutdown()
    httpd.server_close()


def _post(url, path, payload):
    req = urllib.request.Request(
        url + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_health_contract(server_url):
    req = urllib.request.urlopen(server_url + "/api/health", timeout=30)
    body = json.loads(req.read().decode())
    assert req.status == 200
    assert set(body) == {"status", "service", "timestamp"}
    assert body["status"] == "healthy"
    assert body["service"] == "Code Submission & Syntax Validation API"


def test_validate_valid_python(server_url):
    status, body = _post(server_url, "/api/submissions/validate",
                         {"code": "def f():\n    return 1\n", "language": "python"})
    assert status == 200
    assert body["valid"] is True
    assert body["rejected_code"] is False
    assert body["errors"] == []
    assert body["language"] == "python"
    assert body["language_name"] == "Python"


def test_validate_syntax_error_line(server_url):
    code = "def ok():\n    pass\n\ndef bad(:\n    pass\n"
    status, body = _post(server_url, "/api/submissions/validate",
                         {"code": code, "language": "python"})
    assert status == 200
    assert body["valid"] is False
    assert body["rejected_code"] is True
    assert body["rejection_reason"] == "incorrect_code"
    assert body["errors"][0]["line"] == 4
    assert body["errors"][0]["rule"] == "syntax_error"


def test_validate_rejected_language_is_422(server_url):
    status, body = _post(server_url, "/api/submissions/validate",
                         {"code": "console.log(1);", "language": "javascript"})
    assert status == 422
    assert body["rejected_language"] is True
    assert body["rejected_code"] is True
    assert body["rejection_reason"] == "unsupported_language"
    assert body["language_name"] == "JavaScript"


def test_submission_round_trip(server_url):
    status, body = _post(server_url, "/api/submissions",
                         {"code": "x = 1\n", "language": "python"})
    assert status == 201
    assert set(body) == {
        "id", "source_type", "filename", "language", "code", "code_hash",
        "line_count", "size_bytes", "syntax_valid", "rejected_code",
        "rejection_reason", "has_missing_item", "syntax_errors", "created_at"}
    assert body["language"] == "python"
    assert body["line_count"] == 2
    assert body["size_bytes"] == 6
    assert body["syntax_valid"] is True
    assert body["rejected_code"] is False
    assert len(body["code_hash"]) == 64
