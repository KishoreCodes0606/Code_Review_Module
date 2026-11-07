"""Minimal OpenAI-compatible chat client (stdlib only).

Used only for optional enrichment. Callers must always keep a deterministic
fallback: a missing key, timeout, HTTP error or malformed response must never
break remediation, summaries or chat.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from m3.config import llm_settings


class LLMError(RuntimeError):
    """Raised when the optional LLM call cannot produce usable text."""


def configured() -> bool:
    return bool(llm_settings()["configured"])


def chat(messages: list[dict], *, temperature: float = 0.1) -> str:
    settings = llm_settings()
    if not settings["configured"]:
        raise LLMError("LLM is not configured (LLM_API_KEY/OPENAI_API_KEY + LLM_MODEL required).")

    payload = json.dumps(
        {
            "model": settings["model"],
            "messages": messages,
            "temperature": temperature,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        settings["base_url"] + "/chat/completions",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + settings["api_key"],
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=settings["timeout"]) as response:
            raw = response.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(400).decode("utf-8", "replace")
        except Exception:
            detail = ""
        raise LLMError(f"LLM provider returned HTTP {exc.code}{(': ' + detail) if detail else ''}") from exc
    except Exception as exc:  # timeout, DNS, connection reset
        raise LLMError(f"LLM request failed: {type(exc).__name__}") from exc

    try:
        data = json.loads(raw.decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
    except Exception as exc:
        raise LLMError("LLM provider returned an unusable response.") from exc
    if not isinstance(content, str) or not content.strip():
        raise LLMError("LLM provider returned an empty answer.")
    return content.strip()
