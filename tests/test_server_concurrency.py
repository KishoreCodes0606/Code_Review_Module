"""Regression tests for the live-server hang (health blocked during analysis).

Root cause reproduced: server.py's main() built a single-threaded HTTPServer,
and POST /api/analysis runs the multi-agent pipeline synchronously in the
request thread — so every queued request, including GET /api/health, waited
for the whole analysis (Bandit subprocess, PMD JVM run, first-run PMD
download with its long download timeout). The end-to-end fixtures did not
catch this because they built ThreadingHTTPServer directly instead of the
production server class.

These tests boot the *production* server class (server.build_analysis_server)
and use controlled fake agents — no real scanners, deterministic timing.
"""
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

import server as server_module
from analysis.findings import AgentRunResult


@pytest.fixture(scope="module")
def production_server():
    """The exact class real `python server.py` boots."""
    httpd = server_module.build_analysis_server(("127.0.0.1", 0))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _get(url, path, timeout=5.0):
    with urllib.request.urlopen(url + path, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode())


def _post(url, path, payload, timeout=30.0):
    req = urllib.request.Request(
        url + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode())


VALID_PY = "import hashlib\n\ndef h(s):\n    return hashlib.md5(s.encode()).hexdigest()\n"


def test_health_responds_while_analysis_is_running(production_server, monkeypatch):
    """A slow analysis must NOT block /api/health (the reported live hang)."""
    scan_duration = 2.0
    analysis_started = threading.Event()

    def slow_quality(code, language, file_path):
        analysis_started.set()
        time.sleep(scan_duration)  # stands in for a multi-second scan
        return ([], AgentRunResult("code_analysis_agent", "succeeded"), {})

    def fast_security(code, language, file_path):
        return ([], AgentRunResult("security_agent", "succeeded"), {})

    monkeypatch.setattr("agents.code_analysis_agent.run_agent", slow_quality)
    monkeypatch.setattr("agents.security_agent.run_agent", fast_security)

    result = {}

    def run_analysis():
        result["response"] = _post(production_server, "/api/analysis",
                                   {"code": VALID_PY, "language": "python",
                                    "filename": "slow.py"}, timeout=60.0)

    t = threading.Thread(target=run_analysis)
    t.start()
    assert analysis_started.wait(timeout=5)
    time.sleep(0.05)  # let the analysis POST start before probing health

    probes = []
    for _ in range(3):
        started = time.perf_counter()
        status, body = _get(production_server, "/api/health", timeout=1.5)
        elapsed = time.perf_counter() - started
        probes.append(elapsed)
        assert status == 200
        assert body["status"] == "healthy"
        assert elapsed < 1.0, (
            f"/api/health took {elapsed:.2f}s while an analysis was running; "
            "the single-threaded server blocks queued requests until the "
            "analysis finishes")
    t.join()
    assert result["response"][0] == 200
    assert result["response"][1]["status"] == "COMPLETED"
    assert max(probes) < scan_duration  # probes must not wait out the whole scan


def test_health_stays_responsive_under_concurrent_analyses(production_server, monkeypatch):
    """Two analyses in flight + repeated health probes all stay responsive."""
    def quality(code, language, file_path):
        time.sleep(0.8)
        return ([], AgentRunResult("code_analysis_agent", "succeeded"), {})

    def security(code, language, file_path):
        return ([], AgentRunResult("security_agent", "succeeded"), {})

    monkeypatch.setattr("agents.code_analysis_agent.run_agent", quality)
    monkeypatch.setattr("agents.security_agent.run_agent", security)

    def post_analysis():
        try:
            return _post(production_server, "/api/analysis",
                         {"code": VALID_PY, "language": "python",
                          "filename": "c.py"}, timeout=60.0)[0]
        except Exception as exc:  # pragma: no cover
            return exc

    workers = [threading.Thread(target=post_analysis) for _ in range(2)]
    for w in workers:
        w.start()
    time.sleep(0.2)  # both analyses now executing

    for n in range(4):
        started = time.perf_counter()
        status, _ = _get(production_server, "/api/health", timeout=1.5)
        elapsed = time.perf_counter() - started
        assert status == 200 and elapsed < 0.7, (
            f"health probe #{n} took {elapsed:.2f}s under concurrent analyses")
    for w in workers:
        w.join()


def test_client_disconnect_does_not_wedge_the_server(production_server):
    """Closing the socket mid-response (the WinError 10053 scenario) must not
    break or permanently block subsequent requests on the same server."""
    url = urllib.parse.urlsplit(production_server)
    host, port = url.hostname, url.port

    for _ in range(3):
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(b"GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n")
        # abort without reading the response — the client has "gone away"
        s.close()

    time.sleep(0.3)  # give the handler threads a chance to notice the abort

    for _ in range(3):
        started = time.perf_counter()
        status, body = _get(production_server, "/api/health", timeout=3.0)
        elapsed = time.perf_counter() - started
        assert status == 200
        assert body["status"] == "healthy"
        assert elapsed < 1.0, (
            f"health took {elapsed:.2f}s after a client disconnect; the "
            "server appears blocked")


def test_production_server_class_is_threaded():
    """Guards the fix: the live server must be the threaded class, matching
    what the end-to-end fixtures had already been assuming."""
    from http.server import ThreadingHTTPServer
    httpd = server_module.build_analysis_server(("127.0.0.1", 0))
    assert isinstance(httpd, ThreadingHTTPServer)
    httpd.server_close()
