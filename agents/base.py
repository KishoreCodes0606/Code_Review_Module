"""Agent contract (design doc 5.7): one focused job per agent, deterministic
implementation in M2, and a shared error type so orchestrator handles failures
explicitly."""
from __future__ import annotations


class AgentError(Exception):
    """Raised internally when an agent cannot do its work (never a silent pass)."""


def optional_tool_status(tool: str) -> str:
    """Honest availability marker for optional analyzers ('pmd', 'semgrep')."""
    if tool == "pmd" and __import__("os").environ.get("PMD_DISABLE_DOWNLOAD") == "1":
        return "unavailable (download disabled)"
    return "available"
