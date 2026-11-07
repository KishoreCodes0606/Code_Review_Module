"""Optional LLM integration contract tests (Task 2).

No live provider credentials are configured in this project, so these tests
exercise the client against a local OpenAI-compatible HTTP server and the agents
against a mocked ``llm.chat``. They verify request formatting, auth header,
response parsing, HTTP/parse/empty-response errors and that every failure path
keeps the deterministic M3 output intact. Live-provider verification remains
pending until a key and model are configured (see README).
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agents import assistant_agent, remediation_agent
from m3 import llm, service
from orchestrator import pipeline

VULNERABLE = '''
import sqlite3
import subprocess


def get_user(conn, uid):
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + uid
    cur.execute(query)
    return cur.fetchone()


def run_tool(name):
    return subprocess.call("tool " + name, shell=True)
'''


class _FakeProvider(BaseHTTPRequestHandler):
    """Minimal OpenAI-compatible chat-completions endpoint."""

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.last_request = {
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": body,
        }
        mode = self.server.mode
        if mode == "http500":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "provider exploded"}')
            return
        if mode == "malformed":
            payload = b"<html>not json</html>"
        elif mode == "empty":
            payload = json.dumps({"choices": [{"message": {"content": "   "}}]}).encode()
        elif mode == "missing_choices":
            payload = json.dumps({"choices": []}).encode()
        else:
            payload = json.dumps(
                {"choices": [{"message": {"content": "Use parameterized queries."}}]}
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # keep test output clean
        return


@pytest.fixture()
def provider(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeProvider)
    server.mode = "ok"
    server.last_request = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_BASE_URL", f"http://127.0.0.1:{server.server_port}/v1")
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture()
def configured(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:1/v1")
    return monkeypatch


def test_configured_requires_key_and_model(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert llm.configured() is False
    with pytest.raises(llm.LLMError):
        llm.chat([{"role": "user", "content": "hi"}])


def test_request_format_auth_and_parsing(provider):
    answer = llm.chat([{"role": "user", "content": "How do I fix SQL injection?"}])

    assert answer == "Use parameterized queries."
    request = provider.last_request
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == "Bearer test-key-not-real"
    assert request["body"]["model"] == "test-model"
    assert request["body"]["messages"][0]["content"].startswith("How do I fix")
    assert 0 <= request["body"]["temperature"] <= 1


@pytest.mark.parametrize("mode", ["http500", "malformed", "empty", "missing_choices"])
def test_provider_failures_raise_llm_error(provider, mode):
    provider.mode = mode
    with pytest.raises(llm.LLMError):
        llm.chat([{"role": "user", "content": "hi"}])


def test_unreachable_provider_raises_llm_error(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9/v1")
    with pytest.raises(llm.LLMError) as excinfo:
        llm.chat([{"role": "user", "content": "hi"}])
    assert "LLM request failed" in str(excinfo.value)


# --- agent-level contracts -------------------------------------------------

def _run():
    run_id = pipeline.analyze_code(VULNERABLE, "python", "vulnerable.py")
    state = pipeline.get_run(run_id)
    return state, service.run_payload(state)


def test_remediation_enrichment_only_touches_allowed_fields(configured):
    state, _ = _run()
    baseline = remediation_agent.generate_remediation(
        state.merged_findings, "python", run_id=state.run_id
    )
    target = baseline["findings"][0]
    finding_id = target["finding_id"]
    original_rule = target["rule_id"]
    original_location = dict(target["source_location"])
    count = len(baseline["findings"])

    configured.setattr(
        llm,
        "chat",
        lambda messages, temperature=0.1: json.dumps(
            [
                {
                    "finding_id": finding_id,
                    "rule_id": "INVENTED-RULE",
                    "title": "INVENTED TITLE",
                    "problem_explanation": "LLM explanation.",
                    "recommended_fix": "LLM proposed fix.",
                    "corrected_code": "print('safe')",
                    "best_practice": "LLM best practice.",
                    "reason_for_fix": "LLM reason.",
                },
                {"finding_id": "does-not-exist", "recommended_fix": "ignore me"},
                "not-an-object",
            ]
        ),
    )

    enriched = remediation_agent.generate_remediation(
        state.merged_findings, "python", run_id=state.run_id, use_llm=True
    )
    item = next(i for i in enriched["findings"] if i["finding_id"] == finding_id)

    assert item["recommended_fix"] == "LLM proposed fix."
    assert item["problem_explanation"] == "LLM explanation."
    # Never invented: rule identity and location are authoritative from M2.
    assert item["rule_id"] == original_rule
    assert item["source_location"] == original_location
    assert len(enriched["findings"]) == count
    assert "INVENTED-RULE" not in {i["rule_id"] for i in enriched["findings"]}
    assert enriched["mode"] == "llm_assisted"
    assert enriched["llm"]["used"] is True


def test_remediation_falls_back_when_llm_returns_garbage(configured):
    state, _ = _run()
    baseline = remediation_agent.generate_remediation(
        state.merged_findings, "python", run_id=state.run_id
    )
    configured.setattr(llm, "chat", lambda messages, temperature=0.1: "I cannot help with that.")

    result = remediation_agent.generate_remediation(
        state.merged_findings, "python", run_id=state.run_id, use_llm=True
    )
    assert result["mode"] == "deterministic"
    assert result["llm"]["error"]
    assert [i["recommended_fix"] for i in result["findings"]] == [
        i["recommended_fix"] for i in baseline["findings"]
    ]


def test_assistant_llm_answer_keeps_only_retrieved_citations(configured):
    state, run = _run()
    configured.setattr(
        llm, "chat",
        lambda messages, temperature=0.1: "Use parameterized queries [1]. See also [9].",
    )
    payload = assistant_agent.answer_question(
        "How do I prevent SQL injection in Python?",
        run=run,
        findings=state.merged_findings,
        remediation=None,
        use_llm=True,
    )
    assert payload["mode"] == "llm"
    assert payload["citations"], "an LLM answer must still carry real sources"
    assert [c["index"] for c in payload["citations"]] == [1]
    assert "not present in the retrieved context were ignored" in payload["answer"]


def test_assistant_llm_failure_falls_back_to_retrieval(configured):
    state, run = _run()

    def boom(messages, temperature=0.1):
        raise llm.LLMError("provider down")

    configured.setattr(llm, "chat", boom)
    payload = assistant_agent.answer_question(
        "How do I prevent SQL injection in Python?",
        run=run,
        findings=state.merged_findings,
        remediation=None,
        use_llm=True,
    )
    assert payload["mode"] == "retrieval_only"
    assert payload["llm"]["used"] is False
    assert "provider down" in (payload["llm"]["error"] or "")
    assert payload["citations"][0]["source"] == "python-sql-injection.md"


def test_assistant_without_llm_still_works(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    state, run = _run()
    payload = assistant_agent.answer_question(
        "How do I prevent SQL injection in Python?",
        run=run,
        findings=state.merged_findings,
        remediation=None,
        use_llm=True,
    )
    assert payload["mode"] == "retrieval_only"
    assert payload["citations"]
    assert "not configured" in (payload["llm"]["error"] or "")
