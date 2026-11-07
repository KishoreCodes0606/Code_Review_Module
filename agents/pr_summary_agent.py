"""PR Summary Agent (M3).

Produces a review-ready summary from the real run state, real merged findings,
the transparent health score and (when available) the generated remediation.
It is deterministic and does not call an LLM, so it cannot invent findings,
files, rules or fixes.

Review-status policy:
- PARTIAL / FAILED            -> INCOMPLETE_REVIEW (never reads as success)
- COMPLETED + critical/high   -> CHANGES_REQUESTED
- COMPLETED + only lower      -> APPROVED_WITH_SUGGESTIONS
- COMPLETED + no findings     -> APPROVED_WITH_SUGGESTIONS, with an explicit
  caveat that absence of findings is not proof of safety. The agent never
  returns a bare "Approved" from an automated static scan.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from analysis.severity import SEVERITY_WEIGHTS
from m3.config import MAX_REPORT_FINDINGS
from m3.health import compute_health

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
STATUS_LABELS = {
    "APPROVED": "Approved",
    "APPROVED_WITH_SUGGESTIONS": "Approved with Suggestions",
    "CHANGES_REQUESTED": "Changes Requested",
    "INCOMPLETE_REVIEW": "Incomplete Review",
}


def _get(finding, name, default=None):
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _finding_dict(finding) -> dict:
    return {
        "id": _get(finding, "id"),
        "rule_id": _get(finding, "rule_id"),
        "title": _get(finding, "title"),
        "severity": _get(finding, "severity"),
        "severity_score": _get(finding, "severity_score"),
        "category": _get(finding, "category"),
        "file_path": _get(finding, "file_path"),
        "line_start": _get(finding, "line_start"),
        "line_end": _get(finding, "line_end"),
        "description": _get(finding, "description"),
        "remediation_advice": _get(finding, "remediation_advice"),
        "cwe_id": _get(finding, "cwe_id"),
        "owasp_category": _get(finding, "owasp_category"),
    }


def _review_status(status: str, counts: dict) -> dict:
    blocking = counts.get("critical", 0) + counts.get("high", 0)
    if status in ("PARTIAL", "FAILED"):
        code = "INCOMPLETE_REVIEW"
        rationale = (
            f"The analysis run is {status}. One or more agents did not complete, so this review "
            "cannot approve the change."
        )
    elif status != "COMPLETED":
        code = "INCOMPLETE_REVIEW"
        rationale = f"The analysis run is not terminal ({status}); no review decision is possible."
    elif blocking:
        code = "CHANGES_REQUESTED"
        rationale = (
            f"{blocking} critical/high severity finding(s) must be addressed before this change "
            "can be approved."
        )
    elif any(counts.get(s, 0) for s in ("medium", "low", "info")):
        code = "APPROVED_WITH_SUGGESTIONS"
        rationale = (
            "No critical/high findings were reported, but lower-severity findings should be "
            "addressed in follow-up work."
        )
    else:
        code = "APPROVED_WITH_SUGGESTIONS"
        rationale = (
            "The implemented rules reported no findings. Automated approval is intentionally not "
            "granted from a static scan: absence of findings is not proof that the code is secure."
        )
    return {"code": code, "label": STATUS_LABELS[code], "rationale": rationale}


def _priorities(findings: list, remediation: dict | None) -> list[dict]:
    remediation_by_id = {}
    if remediation:
        for item in remediation.get("findings") or []:
            if item.get("finding_id"):
                remediation_by_id[item["finding_id"]] = item
    ordered = sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.index(_get(f, "severity")) if _get(f, "severity") in SEVERITY_ORDER else 99,
            -(_get(f, "severity_score") or 0),
            _get(f, "line_start") or 0,
        ),
    )
    priorities = []
    for index, finding in enumerate(ordered[:10], start=1):
        item = remediation_by_id.get(_get(finding, "id")) or {}
        action = item.get("recommended_fix") or _get(finding, "remediation_advice") or (
            "Review the rule guidance and fix the reported location."
        )
        priorities.append(
            {
                "priority": index,
                "finding_id": _get(finding, "id"),
                "rule_id": _get(finding, "rule_id"),
                "title": _get(finding, "title"),
                "severity": _get(finding, "severity"),
                "severity_score": _get(finding, "severity_score"),
                "location": {
                    "file_path": _get(finding, "file_path"),
                    "line_start": _get(finding, "line_start"),
                    "line_end": _get(finding, "line_end"),
                },
                "why": _get(finding, "description"),
                "action": action,
                "remediation_available": bool(item.get("corrected_code")),
            }
        )
    return priorities


def _categorized(findings: list) -> list[dict]:
    groups: dict[str, list] = defaultdict(list)
    for finding in findings:
        groups[_get(finding, "category") or "unknown"].append(finding)
    result = []
    for category in sorted(groups, key=lambda c: (c != "security", c)):
        items = groups[category]
        counts = Counter(_get(f, "severity") for f in items)
        result.append(
            {
                "category": category,
                "finding_count": len(items),
                "severity_counts": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
                "rule_ids": sorted({str(_get(f, "rule_id")) for f in items}),
                "findings": [_finding_dict(f) for f in items[:MAX_REPORT_FINDINGS]],
            }
        )
    return result


def _remediation_summary(remediation: dict | None) -> dict:
    if not remediation:
        return {
            "available": False,
            "message": (
                "Remediation was not generated for this run. The findings and review status above "
                "do not depend on it."
            ),
        }
    counts = remediation.get("counts") or {}
    items = remediation.get("findings") or []
    return {
        "available": True,
        "mode": remediation.get("mode"),
        "generated_at": remediation.get("generated_at"),
        "total": remediation.get("finding_count", len(items)),
        "suggested": counts.get("suggested", 0),
        "manual_review_required": counts.get("manual_review_required", 0),
        "llm_used": bool((remediation.get("llm") or {}).get("used")),
        "manual_ids": [
            item.get("finding_id") for item in items
            if item.get("remediation_status") == "manual_review_required"
        ],
        "notice": (
            "Remediation examples are suggestions only; no source file was modified and no fix "
            "has been applied or verified."
        ),
    }


def _caveats(run: dict, findings: list, health: dict, remediation: dict | None) -> list[str]:
    caveats = [
        "Static analysis only: submitted code is never executed and no runtime or integration "
        "test was performed by this review.",
        "Rule coverage is limited to the implemented Python/Java checks; an empty result is not a "
        "security guarantee.",
    ]
    status = run.get("status")
    if status in ("PARTIAL", "FAILED"):
        failed = [
            agent for agent in (run.get("agent_results") or [])
            if agent.get("status") != "succeeded"
        ]
        if failed:
            detail = "; ".join(
                f"{a.get('agent')}: {a.get('status')}" + (f" ({a.get('error')})" if a.get("error") else "")
                for a in failed
            )
            caveats.append(f"Incomplete coverage — {detail}.")
        caveats.append(
            "The health score is withheld for this run because it would be computed from an "
            "incomplete set of findings."
        )
    elif health.get("available"):
        caveats.append(
            f"The health score ({health['score']}/100) reflects severity-weighted findings only; "
            "it is not a security rating."
        )
    metrics = run.get("metrics") or {}
    if metrics.get("parsed") is False:
        caveats.append("The built-in rule engine could not parse the source; its detectors were skipped.")
    if metrics.get("pmd_status") in ("unavailable", "skipped", "error"):
        caveats.append(f"PMD coverage for this run was degraded (pmd_status={metrics.get('pmd_status')}).")
    if remediation is None:
        caveats.append("No remediation bundle exists yet for this run.")
    elif (remediation.get("llm") or {}).get("error"):
        caveats.append(f"Optional LLM enrichment note: {(remediation.get('llm') or {}).get('error')}")
    if not findings:
        caveats.append("No findings were reported; manual review is still required for design and business logic.")
    return caveats


def _overview(run: dict, findings: list, counts: dict, health: dict,
              review: dict, remediation: dict | None) -> str:
    language = run.get("language") or "unknown"
    filename = run.get("filename") or "the submitted source"
    total = len(findings)
    parts = [
        f"Automated review of {filename} ({language}) produced {total} finding(s) "
        f"across {len({_get(f, 'rule_id') for f in findings})} rule(s)."
    ]
    if total:
        top = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s)]
        parts.append("Severity mix: " + ", ".join(top) + ".")
    else:
        parts.append("No rule produced a finding for this source.")
    if health.get("available"):
        parts.append(
            f"Health score {health['score']}/100 ({health['label']}), computed as 100 minus "
            f"{health['penalty']} severity-weighted point(s)."
        )
    else:
        parts.append("Health score withheld because the run did not complete.")
    parts.append(f"Review status: {review['label']}.")
    if remediation:
        rem_counts = remediation.get("counts") or {}
        parts.append(
            f"Remediation examples were generated for {remediation.get('finding_count', 0)} finding(s) "
            f"({rem_counts.get('suggested', 0)} with illustrative code, "
            f"{rem_counts.get('manual_review_required', 0)} requiring manual review)."
        )
    else:
        parts.append("No remediation bundle was included when this summary was generated.")
    return " ".join(parts)


def _recommendation(review: dict, findings: list, run: dict) -> str:
    code = review["code"]
    if code == "INCOMPLETE_REVIEW":
        return (
            "Do not merge on the basis of this run. Resolve the agent failure, re-run the analysis "
            "and review the complete findings before making a decision."
        )
    if code == "CHANGES_REQUESTED":
        top_rules = []
        for finding in findings:
            if _get(finding, "severity") in ("critical", "high"):
                rule = _get(finding, "rule_id")
                if rule not in top_rules:
                    top_rules.append(rule)
        focus = f" Start with {', '.join(top_rules[:5])}." if top_rules else ""
        return (
            "Request changes: fix the critical/high findings, re-run the pipeline and confirm they "
            "no longer appear." + focus
        )
    if findings:
        return (
            "The change may proceed after the suggested findings are addressed or explicitly "
            "accepted as follow-up work; re-run the analysis after changes."
        )
    return (
        "No blocking findings were reported, but this static scan cannot prove the change is safe. "
        "Complete human review, especially for authorization, business logic and design."
    )


def build_pr_summary(run: dict, findings: list, remediation: dict | None = None) -> dict:
    findings = list(findings or [])
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = _get(finding, "severity")
        if severity in counts:
            counts[severity] += 1
    health = compute_health(run.get("status"), findings)
    review = _review_status(run.get("status"), counts)
    remediation_summary = _remediation_summary(remediation)

    severity_breakdown = [
        {
            "severity": severity,
            "count": counts[severity],
            "weight_each": SEVERITY_WEIGHTS[severity],
            "share": round(counts[severity] / len(findings), 3) if findings else 0.0,
        }
        for severity in SEVERITY_ORDER
    ]

    return {
        "run_id": run.get("run_id"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_status": run.get("status"),
        "language": run.get("language"),
        "filename": run.get("filename"),
        "review_status": review,
        "executive_overview": _overview(run, findings, counts, health, review, remediation),
        "finding_count": len(findings),
        "severity_breakdown": severity_breakdown,
        "severity_counts": counts,
        "category_counts": dict(Counter(_get(f, "category") or "unknown" for f in findings)),
        "categorized_findings": _categorized(findings),
        "prioritized_fixes": _priorities(findings, remediation),
        "remediation_summary": remediation_summary,
        "health": health,
        "final_recommendation": _recommendation(review, findings, run),
        "caveats": _caveats(run, findings, health, remediation),
        "agent_results": run.get("agent_results") or [],
        "metrics": run.get("metrics") or {},
        "consistency": {
            "severity_total_matches_finding_count": sum(counts.values()) == len(findings),
            "category_total_matches_finding_count": sum(
                value for value in Counter(_get(f, "category") or "unknown" for f in findings).values()
            ) == len(findings),
        },
    }
