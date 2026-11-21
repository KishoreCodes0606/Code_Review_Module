"""M4 Phase 6: measured retrieval relevance and assistant grounding.

The dataset in ``tests/fixtures/m4/rag_eval.json`` names, for each question, the
knowledge-base document the answer must come from and topic tokens the retrieved
text must contain. The tests assert regression floors and report the measured
hit counts; the numbers quoted in docs/milestone-4 come from this same run.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from m3 import store
from m3.kb import get_knowledge_base, retrieve
from m3.service import chat
from orchestrator import pipeline

ROOT = Path(__file__).resolve().parents[1]
DATASET = json.loads(
    (ROOT / "tests" / "fixtures" / "m4" / "rag_eval.json").read_text(encoding="utf-8")
)
QUESTIONS = DATASET["questions"]

# Regression floors, not accuracy claims: 12/12 is the measured value at M4.
TOP1_FLOOR = 0.75
TOP3_FLOOR = 0.90


@pytest.fixture(scope="module")
def kb():
    return get_knowledge_base()


@pytest.fixture(scope="module")
def run_id():
    store.reset()
    rid = pipeline.analyze_code(
        "import sqlite3\n\n\ndef q(conn, uid):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE id=\" + uid)\n",
        "python",
        "repo.py",
    )
    yield rid
    store.reset()


def _measure(kb, top_k: int):
    rows = []
    for case in QUESTIONS:
        results = kb.search(case["question"], k=top_k)
        sources = [chunk.source for chunk, _ in results]
        rows.append((case, sources))
    return rows


def test_top1_relevance_meets_the_regression_floor(kb):
    rows = _measure(kb, 1)
    hits = [case["id"] for case, sources in rows
            if sources and sources[0] == case["expected_source"]]
    misses = [
        (case["question"], case["expected_source"], sources)
        for case, sources in rows
        if not (sources and sources[0] == case["expected_source"])
    ]
    assert len(hits) / len(rows) >= TOP1_FLOOR, f"top-1 misses: {misses}"


def test_top3_relevance_meets_the_regression_floor(kb):
    rows = _measure(kb, 3)
    hits = [case["id"] for case, sources in rows if case["expected_source"] in sources]
    misses = [
        (case["question"], case["expected_source"], sources)
        for case, sources in rows
        if case["expected_source"] not in sources
    ]
    assert len(hits) / len(rows) >= TOP3_FLOOR, f"top-3 misses: {misses}"


def test_retrieved_text_actually_contains_the_expected_topics(kb):
    """A citation must carry the guidance, not just the right document name.

    The answer cites up to three chunks, and a chunker can split a section in
    the middle, so the topic tokens are checked against the union of the cited
    chunks (heading included).
    """
    for case in QUESTIONS:
        rows = kb.search(case["question"], k=3)
        assert rows, f"no result for {case['id']}"
        top_chunk, score = rows[0]
        assert top_chunk.source == case["expected_source"]
        assert score > 0
        text = " ".join(
            f"{chunk.title} {chunk.section} {chunk.text}" for chunk, _ in rows
        ).lower()
        for topic in case["expected_topics"]:
            assert topic.lower() in text, (
                f"{case['id']}: topic {topic!r} missing from the cited chunks"
            )


def test_one_document_cannot_fill_every_citation_slot(kb):
    """Duplicate chunks from the same document must not crowd out other sources."""
    for case in QUESTIONS:
        rows = kb.search(case["question"], k=3)
        assert rows
        per_source = {}
        for chunk, _score in rows:
            per_source[chunk.source] = per_source.get(chunk.source, 0) + 1
        assert max(per_source.values()) <= 2, (case["id"], per_source)
        # The list is never shortened by the diversity step.
        assert len(rows) == min(3, len(kb.chunks))


def test_every_citation_points_at_a_real_chunk(run_id):
    known = {(chunk.chunk_id, chunk.source, chunk.title) for chunk in get_knowledge_base().chunks}
    payload = chat(run_id, "How do I prevent SQL injection in Python?")

    assert payload["citations"]
    indexes = [citation["index"] for citation in payload["citations"]]
    assert indexes == list(range(1, len(indexes) + 1))
    for citation in payload["citations"]:
        assert (citation["chunk_id"], citation["source"], citation["title"]) in known
        assert citation["excerpt"]
        assert f"[{citation['index']}]" in payload["answer"]
    # No repeated (source, section) pair under two citation numbers.
    keys = {(c["source"], c["section"]) for c in payload["citations"]}
    assert len(keys) == len(payload["citations"])


@pytest.mark.parametrize("case", DATASET["off_topic"], ids=lambda c: c["id"])
def test_off_topic_questions_are_refused_without_inventing_sources(run_id, case):
    payload = chat(run_id, case["question"])
    assert payload["citations"] == []
    assert payload["grounded"] is False
    assert "does not contain" in payload["answer"].lower()
    assert payload["knowledge_base"]["message"]


def test_follow_up_question_keeps_the_topic(run_id):
    follow = DATASET["follow_up"]
    first = chat(run_id, follow["first"])
    assert first["citations"], "the first question must retrieve guidance"

    second = chat(run_id, follow["follow"])
    assert second["citations"], "a pronoun follow-up must still retrieve context"
    assert second["citations"][0]["source"] == follow["expected_source"]


def test_language_filter_never_returns_the_other_language(kb):
    rows = retrieve("How should I fix SQL injection?", k=3, language="java")
    assert rows
    for chunk, _score in rows:
        assert (chunk.language or "general").lower() != "python"


def test_answer_uses_only_retrieved_documents(run_id):
    payload = chat(run_id, "How should passwords be hashed?")
    kb = get_knowledge_base()
    known_sources = {chunk.source for chunk in kb.chunks}
    cited = {citation["source"] for citation in payload["citations"]}
    assert cited <= known_sources
    # Every bracketed number in the answer belongs to a returned citation.
    indexes = {citation["index"] for citation in payload["citations"]}
    import re

    for number in re.findall(r"\[(\d+)\]", payload["answer"]):
        assert int(number) in indexes
