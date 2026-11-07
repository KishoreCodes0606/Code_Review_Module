"""Embedding providers and a persistent vector index for the M3 knowledge base.

Design
------
``EmbeddingProvider`` is the seam: it turns text into L2-normalised float
vectors. Three implementations ship here so the RAG pipeline has a real vector
path in every environment:

* ``hashing`` (default, zero dependencies) - feature hashing over the same
  tokenizer the BM25 index uses (with its synonym expansion). This is a genuine
  vector-space representation and cosine search, but the vectors encode
  *lexical* proximity, not neural semantics. The status payload says so; nothing
  claims otherwise.
* ``openai`` - OpenAI-compatible ``/embeddings`` endpoint, enabled only when
  ``EMBEDDING_API_KEY`` (or an LLM key) **and** ``EMBEDDING_MODEL`` are set.
  This is the semantic provider.
* ``sentence-transformers`` - local neural model, used only when the package is
  installed.

``VectorIndex`` builds one vector per KB chunk, persists them under
``m3/.cache/`` keyed by a signature (provider, model, dimensions, chunk ids),
and answers cosine-similarity queries. Persistence keeps startup instant while
staying inside the workspace and out of git.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import math
import re
import urllib.error
import urllib.request
from pathlib import Path

from m3.config import EMBEDDING_CACHE_DIR, embedding_settings

_TOKEN_SPLIT = re.compile(r"[A-Za-z][A-Za-z0-9_'-]*|\d+")


class EmbeddingError(RuntimeError):
    """Raised when an embedding provider cannot produce vectors."""


def _stable_hash(text: str) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest(), "big")


class EmbeddingProvider:
    """Interface implemented by every embedding backend."""

    name = "base"
    kind = "lexical"  # 'lexical' | 'neural'

    def __init__(self) -> None:
        self.error: str | None = None

    @property
    def available(self) -> bool:  # pragma: no cover - overridden
        return False

    @property
    def dimensions(self) -> int:  # pragma: no cover - overridden
        return 0

    def embed(self, texts: list[str]) -> list[list[float]]:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> dict:
        return {
            "provider": self.name,
            "kind": self.kind,
            "dimensions": self.dimensions,
            "available": self.available,
            "error": self.error,
        }


class HashingEmbedding(EmbeddingProvider):
    """Deterministic feature-hashing embedding (offline, no dependencies)."""

    name = "hashing"
    kind = "lexical-heading-weighted"

    def __init__(self, dimensions: int = 512, tokenizer=None) -> None:
        super().__init__()
        self._dimensions = max(64, int(dimensions))
        self._tokenizer = tokenizer

    @property
    def available(self) -> bool:
        return True

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def _tokens(self, text: str) -> list[str]:
        if callable(self._tokenizer):
            return self._tokenizer(text)
        return [t.lower() for t in _TOKEN_SPLIT.findall(text or "") if len(t) > 1]

    def _vector(self, text: str, heading: str = "") -> list[float]:
        vector = [0.0] * self._dimensions
        # Heading text is weighted like a repeated term so a document titled
        # "Preventing SQL Injection" lands near SQL-injection queries.
        for weight, source in ((1.0, text), (2.5, heading)):
            tokens = self._tokens(source or "")
            if not tokens:
                continue
            counts: dict[str, int] = {}
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
            for token, count in counts.items():
                index = _stable_hash(token) % self._dimensions
                sign = 1.0 if _stable_hash("s:" + token) % 2 == 0 else -1.0
                vector[index] += sign * weight * (1.0 + math.log(count))
        norm = math.sqrt(sum(value * value for value in vector))
        if norm:
            vector = [value / norm for value in vector]
        return vector

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    def embed_chunk(self, chunk) -> list[float]:
        return self._vector(chunk.text, f"{chunk.title} {chunk.section}")


class OpenAIEmbedding(EmbeddingProvider):
    """OpenAI-compatible embeddings endpoint (stdlib HTTP, no SDK)."""

    name = "openai"
    kind = "neural"

    def __init__(self, *, api_key: str, model: str, base_url: str, timeout: float) -> None:
        super().__init__()
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._dimensions = 0

    @property
    def available(self) -> bool:
        return bool(self._api_key and self._model)

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not self.available:
            raise EmbeddingError(
                "OpenAI embeddings need EMBEDDING_API_KEY (or LLM_API_KEY/OPENAI_API_KEY) "
                "and EMBEDDING_MODEL."
            )
        payload = json.dumps({"model": self._model, "input": texts}).encode("utf-8")
        request = urllib.request.Request(
            self._base_url + "/embeddings",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self._api_key,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read(8 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(300).decode("utf-8", "replace")
            except Exception:
                detail = ""
            raise EmbeddingError(
                f"Embedding provider returned HTTP {exc.code}"
                + (f": {detail}" if detail else "")
            ) from exc
        except Exception as exc:
            raise EmbeddingError(f"Embedding request failed: {type(exc).__name__}") from exc

        try:
            data = json.loads(raw.decode("utf-8"))
            rows = data["data"]
            vectors = [row["embedding"] for row in rows]
        except Exception as exc:
            raise EmbeddingError("Embedding provider returned an unusable response.") from exc
        if len(vectors) != len(texts):
            raise EmbeddingError("Embedding provider returned the wrong number of vectors.")
        normalised = []
        for vector in vectors:
            norm = math.sqrt(sum(float(v) * float(v) for v in vector))
            normalised.append([float(v) / norm for v in vector] if norm else [float(v) for v in vector])
        self._dimensions = len(normalised[0]) if normalised else 0
        return normalised


class SentenceTransformerEmbedding(EmbeddingProvider):
    """Local neural embeddings when ``sentence-transformers`` is installed."""

    name = "sentence-transformers"
    kind = "neural"

    def __init__(self, model: str) -> None:
        super().__init__()
        self._model_name = model
        self._model = None
        self._dimensions = 0
        try:  # pragma: no cover - depends on optional package
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(model)
            self._dimensions = int(self._model.get_sentence_embedding_dimension())
        except Exception as exc:  # pragma: no cover
            self.error = f"{type(exc).__name__}: {exc}"

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed(self, texts: list[str]) -> list[list[float]]:  # pragma: no cover
        if self._model is None:
            raise EmbeddingError(self.error or "sentence-transformers model unavailable")
        vectors = self._model.encode(list(texts), normalize_embeddings=True)
        return [list(map(float, row)) for row in vectors]


def build_provider(tokenizer=None) -> EmbeddingProvider:
    """Select a provider from configuration, falling back honestly."""
    settings = embedding_settings()
    choice = settings["provider"]

    if choice in ("openai", "auto"):
        if settings["api_key"] and settings["model"] and choice == "openai":
            return OpenAIEmbedding(
                api_key=settings["api_key"],
                model=settings["model"],
                base_url=settings["base_url"],
                timeout=settings["timeout"],
            )
        if choice == "auto" and settings["api_key"] and settings["model"]:
            return OpenAIEmbedding(
                api_key=settings["api_key"],
                model=settings["model"],
                base_url=settings["base_url"],
                timeout=settings["timeout"],
            )
        if choice == "openai":
            provider = OpenAIEmbedding(
                api_key=settings["api_key"],
                model=settings["model"],
                base_url=settings["base_url"],
                timeout=settings["timeout"],
            )
            provider.error = (
                "EMBEDDING_PROVIDER=openai requires EMBEDDING_API_KEY "
                "(or LLM_API_KEY/OPENAI_API_KEY) and EMBEDDING_MODEL."
            )
            return provider

    if choice in ("sentence-transformers", "st", "auto"):
        if importlib.util.find_spec("sentence_transformers") is not None:
            return SentenceTransformerEmbedding(settings["sentence_model"])
        if choice in ("sentence-transformers", "st"):
            provider = HashingEmbedding(settings["dimensions"], tokenizer)
            provider.error = (
                "sentence-transformers is not installed; the hashing provider is active instead."
            )
            return provider

    return HashingEmbedding(settings["dimensions"], tokenizer)


class VectorIndex:
    """Cosine-similarity index over the existing KB chunks."""

    def __init__(self, chunks: list, *, provider: EmbeddingProvider,
                 cache_dir: Path | None = None) -> None:
        self.chunks = list(chunks)
        self.provider = provider
        self.cache_dir = cache_dir or EMBEDDING_CACHE_DIR
        self.vectors: list[list[float]] = []
        self.dimensions = 0
        self.loaded_from_cache = False
        self.error: str | None = None
        self._built = False

    # -- persistence ------------------------------------------------------
    def _signature(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.provider.name.encode())
        digest.update(str(getattr(self.provider, "_model", "") or "").encode())
        digest.update(str(self.provider.dimensions).encode())
        for chunk in self.chunks:
            digest.update(str(chunk.chunk_id).encode())
        return digest.hexdigest()[:16]

    def _cache_path(self) -> Path:
        safe = re.sub(r"[^a-z0-9_-]+", "-", self.provider.name.lower())
        return self.cache_dir / f"vectors-{safe}-{self._signature()}.json.gz"

    def _load_cache(self) -> bool:
        path = self._cache_path()
        if not path.exists():
            return False
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                data = json.load(handle)
            if data.get("signature") != self._signature():
                return False
            vectors = data.get("vectors") or []
            if len(vectors) != len(self.chunks):
                return False
            self.vectors = [[float(v) for v in row] for row in vectors]
            self.dimensions = int(data.get("dimensions") or (len(self.vectors[0]) if self.vectors else 0))
            return bool(self.vectors)
        except Exception as exc:
            self.error = f"vector cache unreadable ({type(exc).__name__}); rebuilding"
            return False

    def _save_cache(self) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = self._cache_path().with_suffix(".tmp")
            with gzip.open(tmp, "wt", encoding="utf-8") as handle:
                json.dump(
                    {
                        "signature": self._signature(),
                        "provider": self.provider.name,
                        "dimensions": self.dimensions,
                        "chunk_ids": [chunk.chunk_id for chunk in self.chunks],
                        "vectors": self.vectors,
                    },
                    handle,
                )
            tmp.replace(self._cache_path())
        except Exception as exc:  # pragma: no cover - disk issues must not break RAG
            self.error = f"vector cache not written: {type(exc).__name__}: {exc}"

    def build(self, *, force: bool = False) -> "VectorIndex":
        if self._built and not force:
            return self
        self._built = True
        if not self.chunks or not self.provider.available:
            self.error = self.error or (
                "Embedding provider unavailable: "
                + (self.provider.error or "provider reports not configured")
            )
            return self
        if not force and self._load_cache():
            self.loaded_from_cache = True
            return self
        try:
            embed_chunk = getattr(self.provider, "embed_chunk", None)
            if callable(embed_chunk):
                vectors = [embed_chunk(chunk) for chunk in self.chunks]
            else:
                vectors = self.provider.embed(
                    [f"{chunk.title} {chunk.section}\n{chunk.text}" for chunk in self.chunks]
                )
        except Exception as exc:
            self.error = f"embedding failed: {type(exc).__name__}: {exc}"
            self.vectors = []
            return self
        self.vectors = vectors
        self.dimensions = len(vectors[0]) if vectors else 0
        self._save_cache()
        return self

    @property
    def available(self) -> bool:
        return bool(self.chunks) and bool(self.vectors) and not self.error

    # -- retrieval --------------------------------------------------------
    def search(self, query: str, *, k: int = 5, language: str | None = None,
               owasp: str | None = None) -> list[tuple]:
        if not self._built:
            self.build()
        if not self.vectors:
            return []
        try:
            embed_query = getattr(self.provider, "embed_chunk", None)
            if callable(embed_query):
                query_vector = self.provider._vector(query)  # noqa: SLF001 - same module
            else:
                query_vector = self.provider.embed([query])[0]
        except Exception as exc:
            self.error = f"query embedding failed: {type(exc).__name__}: {exc}"
            return []

        owasp_key = (owasp or "").upper()[:3]
        scored: list[tuple[int, float]] = []
        for index, vector in enumerate(self.vectors):
            chunk = self.chunks[index]
            if language and chunk.language and chunk.language not in (language, "general"):
                continue
            if owasp_key and (chunk.owasp or "").upper() and not (chunk.owasp or "").upper().startswith(owasp_key):
                continue
            score = sum(a * b for a, b in zip(query_vector, vector))
            if score > 0:
                scored.append((index, score))
        if not scored:
            return []
        scored.sort(key=lambda item: (-item[1], self.chunks[item[0]].chunk_id))
        return [(self.chunks[index], score) for index, score in scored[: max(1, k)]]

    def status(self) -> dict:
        return {
            "provider": self.provider.name,
            "kind": self.provider.kind,
            "dimensions": self.dimensions or self.provider.dimensions,
            "vectors": len(self.vectors),
            "available": self.available,
            "persisted": self._cache_path().exists(),
            "loaded_from_cache": self.loaded_from_cache,
            "error": self.error,
            "semantic": self.provider.kind == "neural",
        }


def embedding_status() -> dict:
    """Secret-free description of the configured embedding provider."""
    settings = embedding_settings()
    provider = build_provider()
    return {
        "configured_provider": settings["provider"],
        "active_provider": provider.name,
        "kind": provider.kind,
        "dimensions": provider.dimensions,
        "available": provider.available,
        "semantic": provider.kind == "neural",
        "model": settings["model"] or None,
        "error": provider.error,
        "note": (
            "Neural embeddings are active."
            if provider.kind == "neural"
            else "Hashing (lexical) vectors are active; set EMBEDDING_PROVIDER=openai with "
            "EMBEDDING_API_KEY/EMBEDDING_MODEL for semantic embeddings."
        ),
    }
