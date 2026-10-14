"""Central configuration for the knowledge-base pipeline.

Every value can be overridden with an environment variable so the same code
runs on a laptop, in CI, or in the final deployed platform.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    # --- paths -----------------------------------------------------------
    sources_file: Path = field(default_factory=lambda: ROOT / _env("KB_SOURCES", "sources.yaml"))
    raw_dir: Path = field(default_factory=lambda: ROOT / _env("KB_RAW_DIR", "knowledge_base/raw"))
    custom_dir: Path = field(default_factory=lambda: ROOT / _env("KB_CUSTOM_DIR", "knowledge_base/custom"))
    chroma_dir: Path = field(default_factory=lambda: ROOT / _env("KB_CHROMA_DIR", "data/chroma"))
    manifest_file: Path = field(default_factory=lambda: ROOT / _env("KB_MANIFEST", "data/manifest.json"))

    # --- vector store ----------------------------------------------------
    collection: str = _env("KB_COLLECTION", "secure_coding_kb")

    # --- embeddings ------------------------------------------------------
    # "sentence-transformers" (real model, recommended) or "hash" (offline,
    # deterministic, for unit tests / CI only - retrieval quality is lower).
    embedding_backend: str = _env("KB_EMBEDDING_BACKEND", "sentence-transformers")
    embedding_model: str = _env("KB_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    hash_dim: int = int(_env("KB_HASH_DIM", "384"))
    embed_batch_size: int = int(_env("KB_EMBED_BATCH", "32"))

    # --- chunking (approximate tokens) ----------------------------------
    chunk_max_tokens: int = int(_env("KB_CHUNK_MAX", "600"))
    chunk_min_tokens: int = int(_env("KB_CHUNK_MIN", "80"))
    chunk_overlap_tokens: int = int(_env("KB_CHUNK_OVERLAP", "80"))

    # --- retrieval defaults ---------------------------------------------
    top_k: int = int(_env("KB_TOP_K", "5"))
    fetch_k: int = int(_env("KB_FETCH_K", "20"))
    min_score: float = float(_env("KB_MIN_SCORE", "0.20"))
    mmr_lambda: float = float(_env("KB_MMR_LAMBDA", "0.7"))


def get_settings() -> Settings:
    return Settings()
