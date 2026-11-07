"""M3 assistant tests: retrieval ranking, citations, no-KB honesty, history."""
import pytest

from m3 import store
from m3.kb import get_knowledge_base, retrieve
from m3.service import RunNotFound, chat, get_history
from orchestrator import pipeline


@pytest.fixture(scope="module")
def kb():
    return get_knowledge_base()


@pytest.fixture(scope="module")
def run_id():
    return pipeline.analyze_code(
        "import sqlite3\n\n\ndef q(conn, uid):\n    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE id=\" + uid)\n",
        "python",
        "repo.py",
    )


@pytest.fixture(autouse=True)
def clean_store():
    store.reset()
    yield
    store.reset()


def test_kb_is_loaded_from_real_documents(kb):
    assert kb.available is True
    assert len(kb.chunks) > 20
    sources = {chunk.source for chunk in kb.chunks}
    assert any(s.endswith(".md") for s in sources)


@pytest.mark.parametrize(
    "question,expected_source_fragment",
    [
        ("How do I prevent SQL injection in Python?", "sql-injection"),
        ("How should I prevent XSS in Java?", "xss"),
        ("How do I handle hardcoded secrets?", "secret"),
        ("How do I prevent path traversal?", "path-traversal"),
    ],
)
def test_retrieval_ranks_the_relevant_document_first(kb, question, expected_source_fragment):
    rows = kb.search(question, k=5)
    assert rows, f"no rows for {question!r}"
    top, score = rows[0]
    assert expected_source_fragment in top.source, f"{question!r} -> {top.source}"
    assert score > 0


def test_sql_injection_question_beats_evaluation_design_section(kb):
    """Regression: the evaluation-design doc used to outrank real SQLi guidance."""
    rows = kb.search("How do I prevent SQL injection in Python?", k=3)
    sources = [chunk.source for chunk, _ in rows]
    assert "sql-injection" in sources[0]
    assert all("evaluation" not in s for s in sources[:2])


def test_citations_refer_to_retrieved_documents(run_id):
    payload = chat(run_id, "How do I prevent SQL injection in Python?")
    assert payload["mode"] == "retrieval_only"
    assert payload["grounded"] is True
    assert payload["citations"], "a grounded answer must cite the KB"
    known_sources = {chunk.source for chunk in get_knowledge_base().chunks}
    for citation in payload["citations"]:
        assert citation["source"] in known_sources
        assert citation["title"]
        assert citation["excerpt"]
        assert f"[{citation['index']}]" in payload["answer"]


def test_no_knowledge_base_match_is_admitted(run_id):
    payload = chat(run_id, "What is the capital of France?")
    assert payload["grounded"] is False
    assert payload["citations"] == []
    assert "does not contain" in payload["answer"].lower()
    assert payload["knowledge_base"]["message"]


def test_chat_history_is_session_scoped(run_id):
    other_run = pipeline.analyze_code("x = 1\n", "python", "clean.py")
    chat(run_id, "How do I prevent SQL injection in Python?")
    chat(run_id, "How do I handle hardcoded secrets?")

    history = get_history(run_id)
    assert history["count"] == 4  # two questions + two answers
    assert [m["role"] for m in history["messages"]] == [
        "user", "assistant", "user", "assistant",
    ]
    assert history["messages"][0]["content"].startswith("How do I prevent SQL")

    # The other run's session is untouched.
    assert get_history(other_run)["count"] == 0


def test_unknown_run_is_rejected(run_id):
    with pytest.raises(RunNotFound):
        chat("run-does-not-exist", "How do I prevent SQL injection?")


def test_empty_question_is_handled_without_answering(run_id):
    payload = chat(run_id, "   ")
    assert payload["grounded"] is False
    assert payload["citations"] == []


def test_assistant_does_not_echo_secrets_from_source():
    secret = "sk-live-abcdef1234567890"
    code = f'API_KEY = "{secret}"\n\ndef f():\n    return API_KEY\n'
    secret_run = pipeline.analyze_code(code, "python", "leak.py")
    payload = chat(secret_run, "How do I handle hardcoded secrets?")
    assert secret not in payload["answer"]
    assert secret not in str(payload["citations"])


def test_retrieve_helper_is_language_filtered(kb):
    rows = retrieve("How should I prevent XSS?", k=3, language="java")
    assert rows
    # Language-filtered retrieval must not surface Python-only guidance.
    assert all((chunk.language or "general").lower() != "python" for chunk, _ in rows)
