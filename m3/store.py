"""In-memory, per-run M3 artifacts.

Pipeline runs already live in memory (M2), so M3 artifacts use the same
lifecycle: they disappear when the server restarts. Everything is guarded by a
lock because the HTTP server is threaded.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from m3.config import MAX_CHAT_MESSAGES

_MAX_RUNS = 200


@dataclass
class RunArtifacts:
    run_id: str
    lock: threading.RLock = field(default_factory=threading.RLock)
    remediation: dict | None = None
    summary: dict | None = None
    chat: list[dict] = field(default_factory=list)

    def append_chat(self, role: str, content: str, meta: dict | None = None) -> dict:
        message = {
            "role": role,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "meta": meta or {},
        }
        with self.lock:
            self.chat.append(message)
            if len(self.chat) > MAX_CHAT_MESSAGES:
                del self.chat[: len(self.chat) - MAX_CHAT_MESSAGES]
        return message

    def history(self, limit: int = 12) -> list[dict]:
        with self.lock:
            return [
                {"role": m["role"], "content": m["content"]}
                for m in self.chat[-limit:]
            ]


_registry: "OrderedDict[str, RunArtifacts]" = OrderedDict()
_registry_lock = threading.Lock()


def get_artifacts(run_id: str) -> RunArtifacts:
    with _registry_lock:
        artifacts = _registry.get(run_id)
        if artifacts is None:
            artifacts = RunArtifacts(run_id=run_id)
            _registry[run_id] = artifacts
            while len(_registry) > _MAX_RUNS:
                _registry.popitem(last=False)
        return artifacts


def peek_artifacts(run_id: str) -> RunArtifacts | None:
    with _registry_lock:
        return _registry.get(run_id)


def reset() -> None:
    """Test helper: drop every cached artifact."""
    with _registry_lock:
        _registry.clear()
