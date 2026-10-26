"""Shared finding data models (single schema used by every agent + analyzer).

Mirrors design doc section 7.4, extended with an explicit `finding_kind`
(vulnerability vs heuristic_warning) and a `detection` provenance id, per the
approved plan's policy that heuristic findings are never presented as proven
vulnerabilities. Uses plain dataclasses so no JSON library is required by the
stdlib server.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

Severity = str  # critical|high|medium|low|info  (validated by severity.py)


@dataclass
class Finding:
    id: str
    category: str                  # security | quality
    rule_id: str
    title: str
    description: str
    finding_kind: str              # vulnerability | heuristic_warning
    detection: str                 # rule_based | analyzer:bandit | analyzer:pmd | ...
    severity: str                  # severity LABEL, derived separately (section 5)
    severity_score: float          # deterministic 0-10, section 5
    confidence: float              # heuristic tier 0-1, kept separate from score
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    source_agent: str
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    remediation_advice: Optional[str] = None

    @staticmethod
    def new_id() -> str:
        return "f-" + uuid.uuid4().hex[:12]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_rule(cls, rule_id: str, line_start: int, line_end: int,
                  snippet: str, file_path: str, description: str,
                  source_agent: str, detection: str, rule_spec,
                  title_override: str | None = None):
        return cls(
            id=cls.new_id(),
            category=rule_spec.category,
            rule_id=rule_id,
            title=title_override or rule_spec.title,
            description=description,
            finding_kind=rule_spec.finding_kind,
            detection=detection,
            severity="info",           # replaced by severity engine
            severity_score=0.0,        # replaced by severity engine
            confidence=rule_spec.confidence,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=snippet,
            source_agent=source_agent,
            owasp_category=rule_spec.owasp_category,
            cwe_id=rule_spec.cwe_id,
            remediation_advice=rule_spec.remediation,
        )


@dataclass
class AgentRunResult:
    """Outcome of one agent (or preprocessing stage) inside a run."""
    agent: str
    status: str                    # succeeded | failed | timeout
    error: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class PipelineState:
    run_id: str
    language: str                  # python | java
    source_code: str
    filename: str
    file_path: str
    status: str = "QUEUED"         # QUEUED|PARSING|ANALYZING|COMPLETED|PARTIAL|FAILED
    quality_findings: list[Finding] = field(default_factory=list)
    security_findings: list[Finding] = field(default_factory=list)
    merged_findings: list[Finding] = field(default_factory=list)
    agent_results: list[AgentRunResult] = field(default_factory=list)
    errors: list[AgentRunResult] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    health_score: Optional[int] = None
    started_at: float = 0.0
    finished_at: float = 0.0

    def all_agent_failures(self) -> list[AgentRunResult]:
        return [r for r in self.agent_results if r.status != "succeeded"]
