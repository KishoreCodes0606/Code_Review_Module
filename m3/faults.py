"""Test-only failure simulation for browser PARTIAL/FAILED verification.

The mechanism is opt-in at **process start** with ``CODE_REVIEW_TEST_FAULTS``
set to ``partial`` or ``failed``. There is deliberately no HTTP route, query
parameter or request body that can enable it: a normal process (where the
variable is unset) can never be pushed into a simulated failure by a client,
so the production configuration exposes nothing to toggle.

``server.py`` calls :func:`apply` right after the real pipeline has produced a
run, and only then rewrites the terminal status using the same rules as
``orchestrator/pipeline.py``. Findings that belong to a simulated-failed agent
are dropped and the merge is re-run, so the UI never presents a failed agent's
output as if it had been produced successfully.
"""
from __future__ import annotations

import os

MODE_ENV = "CODE_REVIEW_TEST_FAULTS"
MODES = ("partial", "failed")


def configured_mode() -> str | None:
    """Return the active simulation mode, or None when the gate is closed."""
    value = (os.getenv(MODE_ENV) or "").strip().lower()
    return value if value in MODES else None


def enabled() -> bool:
    return configured_mode() is not None


def describe() -> dict:
    mode = configured_mode()
    return {
        "enabled": bool(mode),
        "mode": mode,
        "env_var": MODE_ENV,
        "scope": "process start only; no HTTP route or request parameter can enable it",
    }


def _terminal_status(state) -> str:
    """The orchestrator's own status rule, applied to the mutated records."""
    results = list(state.agent_results or [])
    if not results:
        return "FAILED"
    failed = [r for r in results if r.status in ("failed", "timeout")]
    if not failed:
        return "COMPLETED"
    if len(failed) == len(results) and not state.merged_findings:
        return "FAILED"
    return "PARTIAL"


def apply(state, mode: str | None = None) -> str | None:
    """Rewrite a finished run for UI testing. Returns the mode applied."""
    chosen = (mode or configured_mode())
    if state is None or chosen not in MODES:
        return None

    from analysis.findings import AgentRunResult
    from analysis.severity import health_score
    from orchestrator import pipeline

    detail = f"simulated scanner failure ({MODE_ENV}={chosen})"

    def failed_record(agent: str):
        return AgentRunResult(agent=agent, status="failed", error=detail)

    if chosen == "partial":
        # One agent fails: its findings are removed, the other agent's real
        # findings stay visible exactly as the pipeline would leave them.
        state.security_findings = []
        records = [r for r in state.agent_results if r.agent != "security_agent"]
        records.append(failed_record("security_agent"))
        state.agent_results = records
        state.merged_findings = pipeline.merge_findings([state.quality_findings])
    else:
        state.security_findings = []
        state.quality_findings = []
        state.merged_findings = []
        state.agent_results = [
            failed_record("code_analysis_agent"),
            failed_record("security_agent"),
        ]

    state.health_score = health_score(state.merged_findings)
    state.status = _terminal_status(state)
    return chosen
