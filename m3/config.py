"""Environment-driven M3 configuration.

Rules followed here:
- no API key, model or vector-store credential is ever hardcoded;
- the LLM is optional and only considered configured when both a key and an
  explicit model name are present, so a stray ``OPENAI_API_KEY`` cannot silently
  start spending credits;
- the deterministic analysis never depends on any of these values.
"""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

KB_ROOT = PROJECT_ROOT / "secure-kb"
KB_CUSTOM_DIR = KB_ROOT / "knowledge_base" / "custom"
KB_RAW_DIR = KB_ROOT / "knowledge_base" / "raw"
KB_COMBINED_FILE = PROJECT_ROOT / "secure_coding_kb.txt"

EMBEDDING_CACHE_DIR = PROJECT_ROOT / "m3" / ".cache"
MAX_QUESTION_CHARS = 2000
MAX_CHAT_MESSAGES = 40
MAX_HISTORY_FOR_CONTEXT = 12
MAX_REMEDIATION_FINDINGS = 100
MAX_LLM_FINDINGS = 12
MAX_REPORT_FINDINGS = 200


def _env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return ""


def llm_settings() -> dict:
    """Return LLM settings including the secret. Never serialise this dict."""
    api_key = _env("LLM_API_KEY", "OPENAI_API_KEY")
    model = _env("LLM_MODEL")
    base_url = _env("LLM_BASE_URL", "OPENAI_BASE_URL") or "https://api.openai.com/v1"
    try:
        timeout = float(_env("LLM_TIMEOUT_SECONDS") or 45)
    except ValueError:
        timeout = 45.0
    timeout = max(5.0, min(timeout, 120.0))
    return {
        "api_key": api_key,
        "model": model,
        "base_url": base_url.rstrip("/"),
        "timeout": timeout,
        "configured": bool(api_key and model),
    }


def embedding_settings() -> dict:
    """Embedding/vector configuration. No key is ever hardcoded."""
    provider = (_env("EMBEDDING_PROVIDER") or "auto").lower()
    model = _env("EMBEDDING_MODEL", "OPENAI_EMBEDDING_MODEL")
    api_key = _env("EMBEDDING_API_KEY", "LLM_API_KEY", "OPENAI_API_KEY")
    base_url = _env("EMBEDDING_BASE_URL", "LLM_BASE_URL", "OPENAI_BASE_URL") or "https://api.openai.com/v1"
    try:
        dimensions = int(_env("EMBEDDING_DIMENSIONS") or 512)
    except ValueError:
        dimensions = 512
    dimensions = max(64, min(dimensions, 4096))
    try:
        timeout = float(_env("EMBEDDING_TIMEOUT_SECONDS") or 30)
    except ValueError:
        timeout = 30.0
    return {
        "provider": provider,
        "model": model,
        "api_key": api_key,
        "base_url": base_url.rstrip("/"),
        "dimensions": dimensions,
        "timeout": max(5.0, min(timeout, 120.0)),
        "sentence_model": _env("EMBEDDING_SENTENCE_MODEL") or "all-MiniLM-L6-v2",
        "strategy": (_env("KB_RETRIEVAL_STRATEGY") or "auto").lower(),
    }


def retrieval_strategy() -> str:
    """auto | bm25 | vector | hybrid (validated, defaulting to auto)."""
    strategy = embedding_settings()["strategy"]
    return strategy if strategy in ("auto", "bm25", "vector", "hybrid") else "auto"


def llm_public_status() -> dict:
    """Secret-free view of the LLM configuration for the UI/API."""
    settings = llm_settings()
    base_url = settings["base_url"]
    host = base_url.split("://", 1)[-1].split("/", 1)[0]
    reason = None
    if not settings["api_key"] and not settings["model"]:
        reason = "Set LLM_API_KEY (or OPENAI_API_KEY) and LLM_MODEL to enable optional LLM assistance."
    elif not settings["api_key"]:
        reason = "LLM_MODEL is set but no LLM_API_KEY/OPENAI_API_KEY is present."
    elif not settings["model"]:
        reason = "An API key is present but LLM_MODEL is not set; the LLM stays disabled."
    return {
        "configured": settings["configured"],
        "model": settings["model"] or None,
        "provider_host": host,
        "reason": reason,
        "used_for": "optional enrichment only; deterministic analysis and retrieval work without it",
    }
