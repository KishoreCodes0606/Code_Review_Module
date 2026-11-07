"""Application service for the M3 endpoints.

Keeps HTTP handlers thin and centralises run validation, artifact caching and
cross-agent consistency (for example: regenerating remediation invalidates the
cached PR summary so the summary can never describe stale fixes).
"""
from __future__ import annotations

import importlib.util

from agents import assistant_agent, pr_summary_agent, remediation_agent
from m3 import llm, report, store
from m3.config import llm_public_status
from m3.health import compute_health
from m3.kb import get_knowledge_base


class RunNotFound(LookupError):
    pass


def _state(run_id: str):
    from orchestrator import pipeline

    state = pipeline.get_run(run_id) if run_id else None
    if state is None:
        raise RunNotFound(run_id)
    return state


def run_payload(state) -> dict:
    """M2 run summary plus the additive M3 health detail."""
    from orchestrator import pipeline

    payload = pipeline.run_summary(state)
    payload["health"] = compute_health(state.status, state.merged_findings)
    return payload


def generate_remediation(run_id: str, *, use_llm: bool = False,
                         force: bool = False) -> dict:
    state = _state(run_id)
    artifacts = store.get_artifacts(run_id)
    if artifacts.remediation is not None and not force:
        return artifacts.remediation
    payload = remediation_agent.generate_remediation(
        state.merged_findings,
        state.language,
        run_id=run_id,
        use_llm=use_llm,
        analysis_status=state.status,
    )
    with artifacts.lock:
        artifacts.remediation = payload
        artifacts.summary = None  # summary embeds remediation state
    return payload


def get_remediation(run_id: str) -> dict | None:
    _state(run_id)
    artifacts = store.peek_artifacts(run_id)
    return artifacts.remediation if artifacts else None


def generate_summary(run_id: str, *, force: bool = False) -> dict:
    state = _state(run_id)
    artifacts = store.get_artifacts(run_id)
    with artifacts.lock:
        if artifacts.summary is not None and not force:
            return artifacts.summary
        remediation = artifacts.remediation
    payload = pr_summary_agent.build_pr_summary(
        run_payload(state), state.merged_findings, remediation
    )
    with artifacts.lock:
        artifacts.summary = payload
    return payload


def get_summary(run_id: str) -> dict | None:
    _state(run_id)
    artifacts = store.peek_artifacts(run_id)
    return artifacts.summary if artifacts else None


def chat(run_id: str, question: str, *, use_llm: bool = False,
         selected_finding_id: str | None = None) -> dict:
    state = _state(run_id)
    artifacts = store.get_artifacts(run_id)
    history = artifacts.history(limit=12)
    payload = assistant_agent.answer_question(
        question,
        run=run_payload(state),
        findings=state.merged_findings,
        remediation=artifacts.remediation,
        history=history,
        selected_finding_id=selected_finding_id,
        use_llm=use_llm,
    )
    artifacts.append_chat(
        "user",
        payload["question"],
        {"selected_finding_id": selected_finding_id, "use_llm": use_llm},
    )
    artifacts.append_chat(
        "assistant",
        payload["answer"],
        {
            "mode": payload["mode"],
            "grounded": payload["grounded"],
            "citation_count": len(payload["citations"]),
        },
    )
    payload["history"] = [
        {"role": m["role"], "content": m["content"], "created_at": m.get("created_at")}
        for m in artifacts.chat[-20:]
    ]
    return payload


def get_history(run_id: str) -> dict:
    _state(run_id)
    artifacts = store.peek_artifacts(run_id)
    messages = artifacts.chat[-40:] if artifacts else []
    return {
        "run_id": run_id,
        "count": len(messages),
        "messages": [
            {
                "role": m["role"],
                "content": m["content"],
                "created_at": m.get("created_at"),
                "meta": m.get("meta") or {},
            }
            for m in messages
        ],
    }


def build_report(run_id: str, fmt: str) -> tuple[bytes, str, str]:
    state = _state(run_id)
    if fmt not in ("json", "pdf"):
        raise ValueError("format must be 'json' or 'pdf'")
    remediation = generate_remediation(run_id)
    artifacts = store.get_artifacts(run_id)
    with artifacts.lock:
        summary = artifacts.summary
    if summary is None:
        summary = generate_summary(run_id)
    return report.build_report_bytes(
        fmt, run_payload(state), state.merged_findings, remediation, summary
    )


def capabilities() -> dict:
    kb = get_knowledge_base()
    # Build (or load) the vector index now so the reported retrieval backend is
    # the one actually serving queries, not an assumption.
    try:
        kb.vector_index()
    except Exception:
        pass
    kb_info = kb.status()
    reportlab_available = importlib.util.find_spec("reportlab") is not None
    return {
        "milestone": "M3",
        "remediation": {
            "deterministic": True,
            "llm_optional": True,
            "auto_apply": False,
        },
        "pr_summary": {"deterministic": True, "llm_optional": False},
        "assistant": {
            "retrieval_backend": kb_info.get("backend"),
            "retrieval_strategy": kb_info.get("strategy"),
            "vector": kb_info.get("vector"),
            "embedding": kb_info.get("embedding"),
            "citation_required": True,
            "llm_optional": True,
        },
        "llm": llm_public_status(),
        "knowledge_base": kb_info,
        "report": {
            "formats": ["json", "pdf"],
            "pdf_available": reportlab_available,
            "pdf_library": "reportlab" if reportlab_available else None,
        },
        "limits": {
            "question_chars": 2000,
            "chat_messages_per_run": 40,
            "report_findings": 200,
        },
    }
