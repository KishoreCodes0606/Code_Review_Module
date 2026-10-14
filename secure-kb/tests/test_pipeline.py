"""End-to-end test with the offline hash embedder and a temp ChromaDB."""
import numpy as np
import pytest

from kb.config import Settings
from kb.embedder import HashEmbedder
from kb.ingest import run
from kb.retriever import Retriever, build_where, format_context
from kb.store import EmbeddingModelMismatch, VectorStore


@pytest.fixture()
def cfg(tmp_path):
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "sql.md").write_text(
        "---\nid: custom-sql\nlanguage: python\nowasp: A03\ncwe: [CWE-89]\n---\n# SQL\n\n## Fix\n\n"
        "Use parameterized queries with placeholders so user input is never concatenated into SQL.\n" * 3,
        encoding="utf-8")
    (custom / "xss.md").write_text(
        "---\nid: custom-xss\nlanguage: java\nowasp: A03\ncwe: [CWE-79]\n---\n# XSS\n\n## Fix\n\n"
        "Encode untrusted output for the HTML context to stop cross site scripting in templates.\n" * 3,
        encoding="utf-8")
    sources = tmp_path / "sources.yaml"
    sources.write_text("groups: []\n", encoding="utf-8")
    return Settings(
        sources_file=sources, raw_dir=tmp_path / "raw", custom_dir=custom,
        chroma_dir=tmp_path / "chroma", manifest_file=tmp_path / "manifest.json",
        collection="test_kb", embedding_backend="hash", chunk_min_tokens=1)


def test_ingest_is_incremental_and_idempotent(cfg):
    first = run(cfg=cfg)
    assert first["documents_updated"] == 2 and first["collection_size"] > 0
    size = first["collection_size"]
    second = run(cfg=cfg)
    assert second["documents_updated"] == 0 and second["documents_skipped"] == 2
    assert second["collection_size"] == size


def test_changed_document_replaces_old_chunks(cfg):
    run(cfg=cfg)
    path = cfg.custom_dir / "sql.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nExtra new sentence about ORMs.\n", encoding="utf-8")
    stats = run(cfg=cfg)
    assert stats["documents_updated"] == 1
    store = VectorStore(cfg.chroma_dir, cfg.collection, HashEmbedder(cfg.hash_dim).name)
    got = store.col.get(where={"doc_id": "custom-sql"})
    assert any("Extra new sentence" in d for d in got["documents"])


def test_removed_document_is_deleted(cfg):
    run(cfg=cfg)
    (cfg.custom_dir / "xss.md").unlink()
    run(cfg=cfg)
    store = VectorStore(cfg.chroma_dir, cfg.collection, HashEmbedder(cfg.hash_dim).name)
    assert store.doc_ids() == {"custom-sql"}


def test_retrieval_and_language_filter(cfg):
    run(cfg=cfg)
    r = Retriever(settings=cfg)
    hits = r.retrieve("how to stop SQL injection with parameterized queries", k=2, min_score=0.0)
    assert hits[0].metadata["doc_id"] == "custom-sql"
    only_java = r.retrieve("anything about queries", k=5, language="java", min_score=0.0)
    assert {h.metadata["language"] for h in only_java} <= {"java", "general"}
    assert "[1]" in format_context(hits)
    assert format_context([]).startswith("NO RELEVANT")


def test_model_mismatch_is_refused(cfg):
    run(cfg=cfg)
    with pytest.raises(EmbeddingModelMismatch):
        VectorStore(cfg.chroma_dir, cfg.collection, "some-other-model")


def test_build_where_shapes():
    assert build_where(None, None, None) is None
    assert build_where("python", None, None) == {"language": {"$in": ["python", "general"]}}
    assert "$and" in build_where("python", "A03", None)


def test_hash_embedder_properties():
    e = HashEmbedder(64)
    a = e.embed_query("sql injection prevention")
    assert a.shape == (64,) and abs(np.linalg.norm(a) - 1) < 1e-5
    assert np.allclose(a, e.embed_query("sql injection prevention"))
