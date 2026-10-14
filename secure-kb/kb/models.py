"""Plain data containers shared by the pipeline stages."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Document:
    doc_id: str
    title: str
    text: str
    metadata: dict = field(default_factory=dict)


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    text: str            # includes the "Title > Heading path" prefix
    tokens: int
    section_path: str
    has_code: bool
    metadata: dict = field(default_factory=dict)


@dataclass
class RetrievedChunk:
    chunk_id: str
    text: str
    score: float         # cosine similarity, 0..1 (higher = closer)
    metadata: dict = field(default_factory=dict)

    @property
    def source(self) -> str:
        return self.metadata.get("source_doc", "unknown")

    @property
    def url(self) -> str:
        return self.metadata.get("source_url", "")
