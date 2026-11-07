"""Knowledge-base retrieval for the M3 conversational assistant.

Reuse, not replacement: documents are chunked with the existing
``secure-kb/kb/chunker.py`` structure-aware chunker and loaded with the same
front-matter/metadata model used by the M1 ingestion pipeline.

The existing dense retriever needs ``chromadb`` + ``sentence-transformers`` and
a built index. Neither is guaranteed to be installed in this environment, so
M3 adds a deterministic BM25 lexical index over the *same* real documents. When
the vector stack and an index are present the status endpoint says so, but the
lexical backend remains the default because it needs no external service and is
fully reproducible in tests.

Citations always reference a real chunk: document title, section path and the
source file it came from. Nothing is synthesised.
"""
from __future__ import annotations

import importlib.util
import math
import re
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from m3.config import (
    KB_COMBINED_FILE,
    KB_CUSTOM_DIR,
    KB_RAW_DIR,
    KB_ROOT,
    retrieval_strategy,
)
from m3.embeddings import VectorIndex, embedding_status

# Reuse the project's own chunker/models instead of a second implementation.
# Append (never insert at 0): secure-kb also contains a top-level ``tests``
# package, and putting it first would shadow the project's real tests package.
if str(KB_ROOT) not in sys.path:
    sys.path.append(str(KB_ROOT))

try:  # pragma: no cover - exercised through the public API
    from kb.chunker import chunk_document
    from kb.loader import clean_markdown, first_heading, split_front_matter
    from kb.models import Document

    _CHUNKER_AVAILABLE = True
    _CHUNKER_ERROR = None
except Exception as exc:  # pragma: no cover
    chunk_document = None
    _CHUNKER_AVAILABLE = False
    _CHUNKER_ERROR = f"{type(exc).__name__}: {exc}"

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_'-]*|\d+")
_OWASP_RE = re.compile(r"\b(A\d{2})\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\b(CWE-\d+)\b", re.IGNORECASE)

_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "is",
    "are", "was", "were", "be", "been", "being", "it", "its", "this", "that",
    "these", "those", "as", "at", "by", "from", "into", "than", "then", "so",
    "if", "how", "what", "why", "when", "where", "which", "who", "can", "could",
    "should", "would", "do", "does", "did", "not", "no", "but", "about", "use",
    "using", "used", "code", "please", "explain", "tell", "me", "my", "we", "i",
}

_SYNONYMS = {
    "sqli": ["sql", "injection", "parameterized"],
    "sql": ["sql", "injection"],
    "xss": ["cross", "site", "scripting", "encoding"],
    "rce": ["command", "injection", "exec"],
    "cmdi": ["command", "injection"],
    "xxe": ["xml", "external", "entity"],
    "csrf": ["cross", "site", "request", "forgery"],
    "idor": ["broken", "access", "control"],
    "authn": ["authentication"],
    "authz": ["authorization"],
    "deserialization": ["deserialization", "pickle", "objectinputstream"],
    "secret": ["hardcoded", "secret", "environment"],
    "secrets": ["hardcoded", "secret", "environment"],
    "traversal": ["path", "traversal"],
    "sanitize": ["encoding", "escaping", "validation"],
    "sanitise": ["encoding", "escaping", "validation"],
    "password": ["password", "hashing", "bcrypt", "argon2"],
    "crypto": ["cryptography", "hash", "cipher"],
    "hash": ["hashing", "sha256"],
}

# Sections that document the knowledge base itself (test design, retrieval
# evaluation, inventories) are useful material but should not outrank actual
# secure-coding guidance for a developer question. They are demoted only when
# the question is not itself about evaluation.
_META_SECTION_MARKERS = (
    "evaluation",
    "test design",
    "retrieval quality",
    "how this knowledge base was built",
    "document inventory",
    "maintenance",
)
_META_QUERY_MARKERS = ("evaluation", "benchmark", "test", "measure", "hit@", "mrr", "retrieval")


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for match in _TOKEN_RE.findall(text or ""):
        lowered = match.lower()
        parts = [lowered]
        if "_" in lowered:
            parts.extend(p for p in lowered.split("_") if p)
        if "-" in lowered:
            parts.extend(p for p in lowered.split("-") if p)
        # camelCase / PascalCase -> camel + case (helps Java identifiers)
        parts.extend(p.lower() for p in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", match))
        for part in parts:
            if len(part) > 1 and part not in _STOPWORDS:
                tokens.append(part)
    for token in list(tokens):
        tokens.extend(_SYNONYMS.get(token, ()))
    return tokens


def _front_matter_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()] if str(value).strip() else []


class KBChunk:
    __slots__ = ("chunk_id", "doc_id", "title", "section", "text", "source", "url",
                 "doc_type", "owasp", "cwe", "language", "tokens")

    def __init__(self, **kwargs):
        for name in self.__slots__:
            setattr(self, name, kwargs.get(name))

    def citation(self, index: int, score: float | None = None) -> dict:
        return {
            "index": index,
            "chunk_id": self.chunk_id,
            "title": self.title,
            "section": self.section,
            "source": self.source,
            "url": self.url or None,
            "document_type": self.doc_type or None,
            "owasp": self.owasp or None,
            "cwe": self.cwe or [],
            "language": self.language or None,
            "score": round(score, 3) if score is not None else None,
        }


def _load_custom_documents(custom_dir: Path, errors: list[str]):
    Document = globals().get("Document")
    if Document is None:
        return []
    docs = []
    if not custom_dir.exists():
        return docs
    for path in sorted(custom_dir.glob("*.md")):
        try:
            raw = path.read_text(encoding="utf-8")
            meta, body = split_front_matter(raw)
            body = clean_markdown(body)
            title = str(meta.get("title") or first_heading(body, path.stem))
            doc_id = str(meta.get("id") or path.stem)
            docs.append(
                Document(
                    doc_id=doc_id,
                    title=title,
                    text=body,
                    metadata={
                        "source_doc": path.name,
                        "source_url": meta.get("source_url") or "",
                        "doc_type": meta.get("doc_type") or "custom",
                        "owasp": ",".join(_front_matter_list(meta.get("owasp"))),
                        "cwe": _front_matter_list(meta.get("cwe")),
                        "language": str(meta.get("language") or "").lower() or None,
                    },
                )
            )
        except Exception as exc:
            errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
    return docs


def _load_raw_documents(raw_dir: Path, errors: list[str]):
    Document = globals().get("Document")
    if Document is None:
        return []
    docs = []
    if not raw_dir.exists():
        return docs
    for path in sorted(list(raw_dir.glob("*.md")) + list(raw_dir.glob("*.txt"))):
        try:
            raw = path.read_text(encoding="utf-8")
            meta, body = split_front_matter(raw) if path.suffix == ".md" else ({}, raw)
            body = clean_markdown(body)
            title = str(meta.get("title") or first_heading(body, path.stem))
            docs.append(
                Document(
                    doc_id=str(meta.get("id") or path.stem),
                    title=title,
                    text=body,
                    metadata={
                        "source_doc": path.name,
                        "source_url": meta.get("source_url") or "",
                        "doc_type": meta.get("doc_type") or "raw",
                        "owasp": ",".join(_front_matter_list(meta.get("owasp"))),
                        "cwe": _front_matter_list(meta.get("cwe")),
                        "language": str(meta.get("language") or "").lower() or None,
                    },
                )
            )
        except Exception as exc:
            errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
    return docs


def _load_combined_document(combined_file: Path, errors: list[str]):
    Document = globals().get("Document")
    if Document is None or not combined_file.exists():
        return []
    try:
        body = clean_markdown(combined_file.read_text(encoding="utf-8"))
        return [
            Document(
                doc_id="secure-coding-reference",
                title="Secure Coding Knowledge Base",
                text=body,
                metadata={
                    "source_doc": combined_file.name,
                    "source_url": "",
                    "doc_type": "reference",
                    "language": None,
                },
            )
        ]
    except Exception as exc:
        errors.append(f"{combined_file.name}: {type(exc).__name__}: {exc}")
        return []


def _chunk_payload(chunk) -> KBChunk:
    metadata = chunk.metadata or {}
    section_path = str(chunk.section_path or "")
    parts = [part.strip() for part in section_path.split(" > ") if part.strip()]
    title = parts[0] if parts else metadata.get("source_doc") or "Knowledge base"
    section = " > ".join(parts[1:]) if len(parts) > 1 else ""
    haystack = section_path
    owasp = metadata.get("owasp") or ""
    cwe = metadata.get("cwe") or []
    if not owasp:
        match = _OWASP_RE.search(haystack)
        owasp = match.group(1).upper() if match else ""
    if not cwe:
        cwe = [m.upper() for m in _CWE_RE.findall(haystack)]
    if isinstance(cwe, str):
        cwe = [cwe]
    return KBChunk(
        chunk_id=chunk.chunk_id,
        doc_id=chunk.doc_id,
        title=title,
        section=section,
        text=chunk.text,
        source=metadata.get("source_doc") or "unknown",
        url=metadata.get("source_url") or "",
        doc_type=metadata.get("doc_type") or "",
        owasp=owasp,
        cwe=list(cwe),
        language=(metadata.get("language") or None),
        tokens=chunk.tokens,
    )


class KnowledgeBase:
    """Deterministic BM25 index over real project knowledge documents."""

    def __init__(self, chunks: list[KBChunk], *, errors: list[str] | None = None,
                 doc_count: int = 0):
        self.chunks = chunks
        self.errors = list(errors or [])
        self.doc_count = doc_count
        self.built_at = time.time()
        self._vector: VectorIndex | None = None
        self._vector_lock = threading.Lock()
        # BM25F-style heading weighting: the title and section path are
        # repeated so a document titled "Preventing SQL Injection" outranks a
        # generic chunk that merely mentions the phrase in a table.
        self._tokens: list[list[str]] = []
        self._heading_tokens: list[set[str]] = []
        for chunk in chunks:
            body_tokens = tokenize(chunk.text)
            heading = tokenize(f"{chunk.title} {chunk.section}")
            self._tokens.append(body_tokens + heading * 2)
            self._heading_tokens.append(set(heading))
        self._lengths = [len(t) for t in self._tokens]
        self._avg_len = (sum(self._lengths) / len(self._lengths)) if self._lengths else 0.0
        self._df: Counter = Counter()
        for tokens in self._tokens:
            self._df.update(set(tokens))
        self._n = len(chunks)
        self._idf = {
            term: math.log(1 + (self._n - df + 0.5) / (df + 0.5))
            for term, df in self._df.items()
        }

    @property
    def available(self) -> bool:
        return bool(self.chunks)

    def vocabulary(self) -> set[str]:
        """Terms the index can actually match (used to reject off-topic queries)."""
        return set(self._idf)

    # -- vector backend ---------------------------------------------------
    def vector_index(self) -> VectorIndex:
        """Lazily build (or load) the embedding index for these chunks."""
        with self._vector_lock:
            if self._vector is None:
                index = VectorIndex(self.chunks, provider=build_embedding_provider())
                index.build()
                self._vector = index
            return self._vector

    # -- retrieval strategies ---------------------------------------------
    def search(self, query: str, *, k: int = 5, language: str | None = None,
               owasp: str | None = None, strategy: str | None = None
               ) -> list[tuple[KBChunk, float]]:
        """Retrieve with the configured strategy, never failing to BM25."""
        chosen = (strategy or retrieval_strategy()).lower()
        if chosen == "auto":
            index = self.vector_index()
            chosen = "hybrid" if index.available else "bm25"
        if chosen == "bm25":
            return self._bm25_search(query, k=k, language=language, owasp=owasp)

        index = self.vector_index()
        dense = index.search(query, k=max(k * 4, 20), language=language, owasp=owasp)
        if chosen == "vector":
            if dense:
                return dense[: max(1, k)]
            # Honest fallback: the vector backend could not answer (provider or
            # query issue), so lexical retrieval keeps the assistant useful.
            self.errors.append("vector retrieval unavailable; fell back to BM25")
            return self._bm25_search(query, k=k, language=language, owasp=owasp)

        lexical = self._bm25_search(query, k=max(k * 4, 20), language=language, owasp=owasp)
        fused = _reciprocal_rank_fusion(lexical, dense)
        if fused:
            return fused[: max(1, k)]
        return lexical[: max(1, k)]

    def _bm25_search(self, query: str, *, k: int = 5, language: str | None = None,
                     owasp: str | None = None) -> list[tuple[KBChunk, float]]:
        terms = [t for t in tokenize(query) if t in self._idf]
        if not terms or not self.chunks:
            return []
        unique_terms = list(dict.fromkeys(terms))
        meta_query = any(marker in (query or "").lower() for marker in _META_QUERY_MARKERS)
        k1, b = 1.5, 0.75
        scored: list[tuple[int, float]] = []
        owasp_key = (owasp or "").upper()[:3]
        for idx, tokens in enumerate(self._tokens):
            tf = Counter(tokens)
            length = self._lengths[idx] or 1
            score = 0.0
            for term in unique_terms:
                freq = tf.get(term, 0)
                if not freq:
                    continue
                denom = freq + k1 * (1 - b + b * length / (self._avg_len or 1))
                score += self._idf[term] * (freq * (k1 + 1)) / denom
            if score <= 0:
                continue
            chunk = self.chunks[idx]
            matched = sum(1 for term in unique_terms if term in tf)
            if matched:
                # Reward chunks that cover more of the question instead of one
                # repeated rare token.
                score *= 1 + 0.40 * (matched / len(unique_terms))
                heading_hits = len(set(unique_terms) & self._heading_tokens[idx])
                if heading_hits:
                    score *= 1 + 0.20 * min(1.0, heading_hits / min(4, len(unique_terms)))
            title_terms = set(tokenize(chunk.title))
            title_hits = set(unique_terms) & title_terms
            if len(title_hits) >= 2:
                # A document whose title names the concept is more authoritative
                # than a long checklist that repeats the words somewhere.
                score *= 1 + min(1.0, len(title_hits) / min(4, len(unique_terms)))
            section_lower = (chunk.section or "").lower()
            if any(word in (query or "").lower() for word in ("prevent", "fix", "remediat", "mitigat")):
                if section_lower.startswith("fix") or "fix:" in section_lower:
                    score *= 1.15
            if language:
                if chunk.language == language:
                    score *= 1.20
                elif chunk.language:
                    score *= 0.55
            if owasp_key and (chunk.owasp or "").upper().startswith(owasp_key):
                score *= 1.15
            section = (chunk.section or "").lower()
            if not meta_query and any(marker in section for marker in _META_SECTION_MARKERS):
                score *= 0.55
            scored.append((idx, score))

        if not scored:
            return []
        scored.sort(key=lambda item: (-item[1], self.chunks[item[0]].chunk_id))
        return [(self.chunks[idx], score) for idx, score in scored[: max(1, k)]]

    def status(self) -> dict:
        sources = sorted({chunk.source for chunk in self.chunks})
        languages = sorted({chunk.language for chunk in self.chunks if chunk.language})
        # Report the backend that is actually serving queries: build/load the
        # index here (cheap, cached on disk) rather than assuming it exists.
        try:
            self.vector_index()
        except Exception:
            pass
        vector = self._vector.status() if self._vector is not None else None
        vector_ready = bool(vector and vector.get("available"))
        strategy = retrieval_strategy()
        active = strategy
        if strategy == "auto":
            active = "hybrid" if vector_ready else "bm25"
        elif strategy in ("vector", "hybrid") and not vector_ready:
            active = "bm25"
        return {
            "available": self.available,
            "backend": active if active != "bm25" else "bm25-lexical",
            "strategy": active,
            "description": (
                "Hybrid (BM25 + cosine vector) retrieval over the project knowledge base."
                if active in ("hybrid", "vector")
                else "Deterministic BM25 lexical retrieval over the project knowledge base."
            ),
            "documents": self.doc_count,
            "chunks": len(self.chunks),
            "sources": sources,
            "languages": languages,
            "errors": self.errors,
            "vector": vector,
            "embedding": embedding_status(),
            "vector_stack_installed": bool(
                importlib.util.find_spec("chromadb")
                and importlib.util.find_spec("sentence_transformers")
            ),
            "note": (
                "Vector search is active with the configured embedding provider; BM25 remains "
                "available and is used as the fallback."
                if active in ("hybrid", "vector")
                else "BM25 lexical retrieval is active; the vector index did not build."
            ),
        }


def _reciprocal_rank_fusion(lexical: list, dense: list, *, k0: int = 60) -> list:
    """Merge two ranked lists without needing comparable score scales."""
    fused: dict[str, float] = {}
    by_id: dict[str, KBChunk] = {}
    for rows in (lexical, dense):
        for rank, (chunk, _score) in enumerate(rows):
            by_id[chunk.chunk_id] = chunk
            fused[chunk.chunk_id] = fused.get(chunk.chunk_id, 0.0) + 1.0 / (k0 + rank + 1)
    ordered = sorted(fused.items(), key=lambda item: (-item[1], item[0]))
    return [(by_id[chunk_id], score) for chunk_id, score in ordered]


def build_embedding_provider(tokenizer=tokenize):
    """Kept here so the tokenizer used by BM25 and hashing vectors is identical."""
    from m3.embeddings import build_provider

    return build_provider(tokenizer)


_lock = threading.Lock()
_kb: KnowledgeBase | None = None


def build_knowledge_base() -> KnowledgeBase:
    errors: list[str] = []
    docs = []
    if not _CHUNKER_AVAILABLE:
        errors.append(f"Existing KB chunker unavailable: {_CHUNKER_ERROR}")
    else:
        docs.extend(_load_custom_documents(KB_CUSTOM_DIR, errors))
        docs.extend(_load_raw_documents(KB_RAW_DIR, errors))
        docs.extend(_load_combined_document(KB_COMBINED_FILE, errors))

    chunks: list[KBChunk] = []
    for doc in docs:
        try:
            for chunk in chunk_document(doc, max_tokens=420, min_tokens=60, overlap_tokens=60):
                chunks.append(_chunk_payload(chunk))
        except Exception as exc:
            errors.append(f"{doc.doc_id}: chunking failed: {type(exc).__name__}: {exc}")
    return KnowledgeBase(chunks, errors=errors, doc_count=len(docs))


def get_knowledge_base(reload: bool = False) -> KnowledgeBase:
    global _kb
    with _lock:
        if _kb is None or reload:
            _kb = build_knowledge_base()
        return _kb


def kb_status(reload: bool = False) -> dict:
    return get_knowledge_base(reload=reload).status()


def retrieve(query: str, *, k: int = 5, language: str | None = None,
             owasp: str | None = None, strategy: str | None = None
             ) -> list[tuple[KBChunk, float]]:
    return get_knowledge_base().search(
        query, k=k, language=language, owasp=owasp, strategy=strategy
    )
