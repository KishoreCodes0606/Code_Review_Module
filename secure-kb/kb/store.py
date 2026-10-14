"""ChromaDB wrapper: persistent cosine-similarity collection with safety checks."""
from __future__ import annotations

from pathlib import Path

import chromadb
import numpy as np

from .models import Chunk

_BATCH = 128


class EmbeddingModelMismatch(RuntimeError):
    pass


def _clean_meta(meta: dict) -> dict:
    """Chroma accepts only str / int / float / bool values."""
    out = {}
    for k, v in meta.items():
        if v is None:
            continue
        out[k] = v if isinstance(v, (str, int, float, bool)) else str(v)
    return out


class VectorStore:
    def __init__(self, path: Path, collection: str, embedding_name: str):
        Path(path).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(path))
        self._name = collection
        self.embedding_name = embedding_name
        self.col = self._open(embedding_name)

    def _open(self, embedding_name: str):
        col = self._client.get_or_create_collection(
            name=self._name,
            metadata={"hnsw:space": "cosine", "embedding_model": embedding_name},
        )
        stored = (col.metadata or {}).get("embedding_model")
        if stored and stored != embedding_name:
            raise EmbeddingModelMismatch(
                f"Collection '{self._name}' was built with '{stored}' but the current model is "
                f"'{embedding_name}'. Re-run ingestion with --rebuild."
            )
        return col

    # ---- write --------------------------------------------------------
    def reset(self) -> None:
        try:
            self._client.delete_collection(self._name)
        except Exception:  # collection did not exist yet
            pass
        self.col = self._open(self.embedding_name)

    def delete_doc(self, doc_id: str) -> None:
        self.col.delete(where={"doc_id": doc_id})

    def upsert(self, chunks: list[Chunk], embeddings: np.ndarray) -> None:
        assert len(chunks) == len(embeddings)
        for i in range(0, len(chunks), _BATCH):
            part = chunks[i : i + _BATCH]
            self.col.upsert(
                ids=[c.chunk_id for c in part],
                documents=[c.text for c in part],
                embeddings=embeddings[i : i + _BATCH].tolist(),
                metadatas=[_clean_meta(c.metadata) for c in part],
            )

    # ---- read ---------------------------------------------------------
    def count(self) -> int:
        return self.col.count()

    def doc_ids(self) -> set[str]:
        data = self.col.get(include=["metadatas"])
        return {m["doc_id"] for m in data["metadatas"] if m and "doc_id" in m}

    def query(self, embedding: np.ndarray, n: int, where: dict | None = None) -> dict:
        n = max(1, min(n, max(self.count(), 1)))
        return self.col.query(
            query_embeddings=[embedding.tolist()],
            n_results=n,
            where=where,
            include=["documents", "metadatas", "distances", "embeddings"],
        )
