"""Code Analysis Agent (design doc 5.2).

Deterministic step only in M2: metrics + smell detection for Python and Java.
Every finding carries a line range, smell name, measured evidence, and a
quality severity (from the deterministic scoring engine). This agent never
reports security issues; that is the security agent's job.
It returns (findings, AgentRunResult, metrics) — never raises; a scanner
failure is recorded on the AgentRunResult, never as a clean empty result.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
import uuid

from agents.base import AgentError
from analysis.findings import AgentRunResult


def run_agent(code: str, language: str, file_path: str) -> tuple[list, AgentRunResult, dict]:
    started = time.time()

    def finish(f, res: AgentRunResult, metrics: dict):
        res.duration_seconds = round(time.time() - started, 2)
        return f, res, metrics

    try:
        if language == "python":
            from analysis.python_metrics import analyze_python_quality
            res = analyze_python_quality(code, file_path)
        elif language == "java":
            res = _java_quality_with_pmd(code, file_path)
        else:
            raise AgentError(
                f"Unsupported language for quality analysis: {language!r}")
    except Exception as e:  # scanner failure is never a clean result
        return finish([], AgentRunResult(
            agent="code_analysis_agent", status="failed", error=str(e)), {})

    findings = res["findings"]
    return finish(findings, AgentRunResult(
        agent="code_analysis_agent", status="succeeded"), res.get("metrics", {}))


def _java_quality_with_pmd(code: str, file_path: str) -> dict:
    from analysis.java_quality import analyze_java_quality, add_pmd_findings
    res = analyze_java_quality(code, file_path)
    # PMD needs a real file on disk (it scans paths, not stdin)
    try:
        if os.environ.get("PMD_DISABLE_DOWNLOAD") == "1" or os.environ.get("PMD_SKIP") == "1":
            res["metrics"]["pmd_status"] = "skipped"
            return res
        tmp_dir = tempfile.mkdtemp(prefix="m2_java_")
        try:
            tmp_path = os.path.join(tmp_dir, _java_filename(file_path))
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(code)
            res["metrics"]["pmd_status"] = add_pmd_findings(tmp_path, file_path, res["findings"])
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        res["metrics"]["pmd_status"] = "error"
    return res


def _java_filename(file_path: str) -> str:
    base = os.path.basename(file_path or "")
    if base.lower().endswith(".java"):
        return base
    return f"Submission-{uuid.uuid4().hex[:6]}.java"
