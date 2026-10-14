"""Embedding backends.

* sentence-transformers  - the real model (default: all-MiniLM-L6-v2, 384 dims)
* hash                   - deterministic bag-of-words hashing; needs no download.
                           Use ONLY for unit tests / CI / offline demos.

The same backend + model must be used for indexing and querying. The vector
store records the model name and refuses to mix them (see store.py).
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

import numpy as np

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_\-\.]*|\d+")
_STOP = frozenset(
    "a an and are as at be by for from has have how i in is it of on or that the this to was what when where which why with you your do does can should".split()
)


class Embedder(Protocol):
    name: str
    dim: int

    def embed_documents(self, texts: list[str]) -> np.ndarray: ...
    def embed_query(self, text: str) -> np.ndarray: ...


class HashEmbedder:
    """Signed feature hashing of unigrams + bigrams, L2-normalised."""

    def __init__(self, dim: int = 384):
        self.dim = dim
        self.name = f"hash-{dim}"

    @staticmethod
    def _stem(tok: str) -> str:
        for suf in ("ing", "ed", "es", "s"):
            if tok.endswith(suf) and len(tok) - len(suf) >= 4:
                return tok[: -len(suf)]
        return tok

    def _vec(self, text: str) -> np.ndarray:
        toks = [self._stem(t.lower()) for t in _TOKEN.findall(text)]
        toks = [t for t in toks if t not in _STOP and len(t) > 1]
        feats = toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]
        v = np.zeros(self.dim, dtype=np.float32)
        for f in feats:
            h = int.from_bytes(hashlib.md5(f.encode()).digest()[:8], "little")
            sign = 1.0 if (h >> 63) & 1 else -1.0
            v[h % self.dim] += sign * (1.0 + math.log(1 + len(f)) * 0.1)
        n = np.linalg.norm(v)
        return v / n if n else v

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        return np.vstack([self._vec(t) for t in texts]) if texts else np.zeros((0, self.dim), np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self._vec(text)


class SentenceTransformerEmbedder:
    # BGE models are trained with an instruction prefix on the QUERY side only.
    _BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

    def __init__(self, model_name: str, batch_size: int = 32):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "sentence-transformers is not installed. Run `pip install -r requirements.txt` "
                "or set KB_EMBEDDING_BACKEND=hash for an offline test run."
            ) from exc
        self.name = model_name
        self.batch_size = batch_size
        self._model = SentenceTransformer(model_name)
        self.dim = int(self._model.get_sentence_embedding_dimension())
        self._query_prefix = self._BGE_QUERY_PREFIX if "bge" in model_name.lower() else ""

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        return np.asarray(
            self._model.encode(
                texts, batch_size=self.batch_size, normalize_embeddings=True, show_progress_bar=len(texts) > 64
            ),
            dtype=np.float32,
        )

    def embed_query(self, text: str) -> np.ndarray:
        vec = self._model.encode([self._query_prefix + text], normalize_embeddings=True)
        return np.asarray(vec[0], dtype=np.float32)


def get_embedder(backend: str, model_name: str, hash_dim: int = 384, batch_size: int = 32) -> Embedder:
    if backend == "hash":
        return HashEmbedder(hash_dim)
    if backend == "sentence-transformers":
        return SentenceTransformerEmbedder(model_name, batch_size)
    raise ValueError(f"Unknown embedding backend: {backend!r}")
