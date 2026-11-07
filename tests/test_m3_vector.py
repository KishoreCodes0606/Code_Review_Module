"""Vector / hybrid retrieval tests (Task 1).

The knowledge base is the project's real one: documents are loaded with the
existing chunker/loader and one vector is generated per chunk. These tests
verify that a vector backend is genuinely active (not BM25 wearing a vector
label), that ranking is relevant across languages and topics, that citations
point at documents that exist on disk, and that an unavailable embedding
provider degrades to BM25 with an honest status instead of fabricating results.
"""
from __future__ import annotations

import pytest

from m3.config import KB_COMBINED_FILE, KB_CUSTOM_DIR, KB_RAW_DIR
from m3.embeddings import HashingEmbedding, VectorIndex, embedding_status
from m3.kb import KnowledgeBase, get_knowledge_base, tokenize

# (question, document that must rank first)
TOPICS = (
    ("How do I prevent SQL injection in Python?", "python-sql-injection.md"),
    ("How do I prevent SQL injection in Java with PreparedStatement?", "java-sql-injection.md"),
    ("How do I prevent cross-site scripting XSS?", "xss-output-encoding.md"),
    ("How should I manage hardcoded secrets and API keys?", "hardcoded-secrets.md"),
    ("How do I prevent command injection in subprocess?", "python-command-injection.md"),
    ("How do I prevent path traversal in file paths?", "path-traversal.md"),
)

STRATEGIES = ("bm25", "vector", "hybrid")


@pytest.fixture(scope="module")
def knowledge():
    return get_knowledge_base()


def _sources(rows):
    return [chunk.source for chunk, _score in rows]


def test_every_chunk_has_one_vector(knowledge):
    index = knowledge.vector_index()
    assert index.available, index.status()
    assert len(index.chunks) == len(knowledge.chunks)
    assert len(index.vectors) == len(knowledge.chunks)
    assert index.status()["dimensions"] > 0
    assert index.status()["provider"] == "hashing"
    # Honesty: hashing vectors are lexical, not neural.
    assert index.status()["semantic"] is False


def test_vectors_are_stored_on_disk_and_reloadable(knowledge):
    index = knowledge.vector_index()
    assert index.status()["persisted"] is True

    reloaded = VectorIndex(knowledge.chunks, provider=HashingEmbedding(512, tokenize))
    reloaded.build()
    assert reloaded.available
    assert reloaded.loaded_from_cache is True


@pytest.mark.parametrize("strategy", STRATEGIES)
@pytest.mark.parametrize("query,expected", TOPICS)
def test_expected_document_ranks_first(knowledge, strategy, query, expected):
    rows = knowledge.search(query, k=3, strategy=strategy)
    assert rows, f"{strategy} returned nothing for {query!r}"
    assert _sources(rows)[0] == expected


def test_retrieval_comparison_across_strategies(knowledge):
    """All three strategies must answer every labelled topic; record hit@1."""
    hits = {strategy: 0 for strategy in STRATEGIES}
    for query, expected in TOPICS:
        for strategy in STRATEGIES:
            rows = knowledge.search(query, k=1, strategy=strategy)
            if rows and rows[0][0].source == expected:
                hits[strategy] += 1
    assert hits["bm25"] == len(TOPICS)
    assert hits["vector"] == len(TOPICS)
    assert hits["hybrid"] == len(TOPICS)


def test_hybrid_keeps_the_lexical_top_document(knowledge):
    for query, _expected in TOPICS:
        lexical = knowledge.search(query, k=1, strategy="bm25")
        hybrid = knowledge.search(query, k=1, strategy="hybrid")
        # Same document at the top; the chunk may differ because fusion ranks
        # sibling chunks of one document independently.
        assert hybrid[0][0].source == lexical[0][0].source


def test_unrelated_question_scores_weakly(knowledge):
    query = "What is the best recipe for chocolate cake?"
    lexical = knowledge.search(query, k=1, strategy="bm25")
    vector = knowledge.search(query, k=1, strategy="vector")
    lexical_match = knowledge.search(
        "How do I prevent SQL injection in Python?", k=1, strategy="bm25"
    )
    vector_match = knowledge.search(
        "How do I prevent SQL injection in Python?", k=1, strategy="vector"
    )
    assert not vector or vector[0][1] < 0.2
    # Compare within each backend: OFF-topic scores are far below real matches.
    assert lexical[0][1] < 0.6 * lexical_match[0][1]
    assert vector[0][1] < 0.3 * vector_match[0][1]


def test_citations_reference_real_documents(knowledge):
    for strategy in STRATEGIES:
        for chunk, score in knowledge.search("prevent SQL injection parameterized query", k=3,
                                             strategy=strategy):
            assert chunk.chunk_id
            assert chunk.text.strip()
            assert chunk.title
            assert score > 0
            exists = (
                (KB_CUSTOM_DIR / chunk.source).exists()
                or (KB_RAW_DIR / chunk.source).exists()
                or chunk.source == KB_COMBINED_FILE.name
            )
            assert exists, f"citation source {chunk.source!r} is not a real document"

            citation = chunk.citation(1, score)
            assert citation["source"] == chunk.source
            assert citation["title"] == chunk.title
            assert citation["section"] == chunk.section


def test_unconfigured_embedding_provider_falls_back_to_bm25(knowledge, monkeypatch):
    monkeypatch.setenv("EMBEDDING_PROVIDER", "openai")
    monkeypatch.delenv("EMBEDDING_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("KB_RETRIEVAL_STRATEGY", "vector")

    kb = KnowledgeBase(list(knowledge.chunks), doc_count=knowledge.doc_count)
    index = kb.vector_index()
    assert index.available is False
    assert index.status()["error"], "an unavailable provider must explain itself"

    rows = kb.search("How do I prevent SQL injection in Python?", k=3)
    assert rows, "BM25 fallback must still answer"
    assert rows[0][0].source == "python-sql-injection.md"

    status = kb.status()
    assert status["vector"]["available"] is False
    assert status["backend"].startswith("bm25"), (
        "status must not claim vector retrieval is active"
    )
    assert "vector" not in status["backend"]


def test_embedding_status_is_secret_free(knowledge):
    status = embedding_status()
    assert "api_key" not in status
    assert status["active_provider"] in ("hashing", "openai", "sentence-transformers")
    assert status["note"]
