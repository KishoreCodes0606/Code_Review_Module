"""Retrieval: filtered top-k similarity search with optional MMR diversification."""
from __future__ import annotations

import numpy as np

from .config import Settings, get_settings
from .embedder import Embedder, get_embedder
from .models import RetrievedChunk
from .store import VectorStore


def build_where(language: str | None, owasp_category: str | None, doc_type: str | None) -> dict | None:
    conds: list[dict] = []
    if language:
        # python-specific question -> python notes + language-agnostic guidance
        conds.append({"language": {"$in": [language, "general"]}})
    if owasp_category:
        conds.append({"owasp_category": owasp_category})
    if doc_type:
        conds.append({"doc_type": doc_type})
    if not conds:
        return None
    return conds[0] if len(conds) == 1 else {"$and": conds}


def _mmr(query: np.ndarray, cands: np.ndarray, k: int, lam: float) -> list[int]:
    """Maximal Marginal Relevance: balance relevance and diversity."""
    rel = cands @ query
    chosen: list[int] = []
    remaining = list(range(len(cands)))
    while remaining and len(chosen) < k:
        if not chosen:
            best = max(remaining, key=lambda i: rel[i])
        else:
            sel = cands[chosen]
            best = max(remaining, key=lambda i: lam * rel[i] - (1 - lam) * float(np.max(sel @ cands[i])))
        chosen.append(best)
        remaining.remove(best)
    return chosen


class Retriever:
    def __init__(self, settings: Settings | None = None, embedder: Embedder | None = None):
        self.cfg = settings or get_settings()
        self.embedder = embedder or get_embedder(
            self.cfg.embedding_backend, self.cfg.embedding_model, self.cfg.hash_dim, self.cfg.embed_batch_size
        )
        self.store = VectorStore(self.cfg.chroma_dir, self.cfg.collection, self.embedder.name)

    def retrieve(
        self,
        query: str,
        k: int | None = None,
        language: str | None = None,
        owasp_category: str | None = None,
        doc_type: str | None = None,
        min_score: float | None = None,
        mmr: bool = True,
    ) -> list[RetrievedChunk]:
        k = k or self.cfg.top_k
        min_score = self.cfg.min_score if min_score is None else min_score
        qv = self.embedder.embed_query(query)
        res = self.store.query(qv, self.cfg.fetch_k, build_where(language, owasp_category, doc_type))
        ids = res["ids"][0]
        if not ids:
            return []
        docs, metas, dists = res["documents"][0], res["metadatas"][0], res["distances"][0]
        embs = np.asarray(res["embeddings"][0], dtype=np.float32)
        scores = [1.0 - float(d) for d in dists]

        order = _mmr(qv, embs, k, self.cfg.mmr_lambda) if mmr else list(range(min(k, len(ids))))
        out = [
            RetrievedChunk(chunk_id=ids[i], text=docs[i], score=scores[i], metadata=metas[i])
            for i in order
            if scores[i] >= min_score
        ]
        return out


def format_context(chunks: list[RetrievedChunk]) -> str:
    """Numbered context blocks so an LLM answer can cite [1], [2] ... (design doc 8.3)."""
    if not chunks:
        return "NO RELEVANT KNOWLEDGE-BASE CONTEXT FOUND."
    blocks = []
    for i, c in enumerate(chunks, 1):
        blocks.append(f"[{i}] {c.source} ({c.url or 'no url'})\n{c.text}")
    return "\n\n---\n\n".join(blocks)
