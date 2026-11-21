# M4 Gap Analysis

Milestone 4 (Week 7–8) asks for four things: validate the Code Review Report
Generation Module, run end-to-end testing on varied Python and Java samples,
optimize prompts / severity consistency / retrieval / assistant accuracy, and
prepare the technical documentation, project report and final demonstration.

This document records what already existed, what was genuinely missing, and what
changed. Nothing was rebuilt: M1 (submission + language gate), M2 (parallel
quality/security agents + orchestrator) and M3 (remediation, PR summary, RAG
assistant, health, report) are unchanged in behaviour.

| # | M4 requirement | Existing implementation | Gap found | Change made | Files | Tests |
|---|---|---|---|---|---|---|
| 1 | Report module covers project info, executive summary, severity breakdown, finding details, rule ids/locations, remediation, corrected code, prioritized roadmap, health score, status/limitations, metadata, page numbers | `m3/report.py` already emitted all of these from run state + summary + remediation; footer carries `Page N` | (a) two competing health numbers in the JSON export (M2 raw vs M3 de-duplicated); (b) JSON could list a remediation item for a finding not in the report; (c) severity table counts reported findings while the health table counts unique ones, with nothing saying so; (d) no schema id in the header | Canonical `health_score` + preserved `m2_health_score`; remediation filtered to reported findings (`not_in_report` counter); explanatory line under the severity table; header shows `report schema m3.1` | `m3/report.py` | `tests/test_m4_report_validation.py` |
| 2 | Verify severity counts, health score, remediation, duplicates, wrapping, honesty, staleness, JSON/PDF consistency | Health formula and de-duplication existed in `m3/health.py` | No test asserted report ↔ findings ↔ health ↔ summary agreement, wrapping width, or stale-run isolation | Added a validation suite covering all nine properties | `tests/test_m4_report_validation.py` | 14 tests |
| 3 | Three distinct samples (Python low, Java medium, Python high) with expected findings, categories, severities, locations, remediation expectations | Only ad-hoc fixture strings in `tests/fixtures.py` | No organised dataset, no oracle, no end-to-end workflow test per sample | Added `tests/fixtures/m4/` (three sources + `expected.json`) and a grader that reports TP/FN/FP and clean-control results | `tests/fixtures/m4/*`, `tests/test_m4_samples.py` | 35 tests |
| 4 | Optimise prompts for the five agents | Only two prompts exist (optional remediation enrichment, optional assistant). Code Analysis and Security agents are rule engines with no prompt | Prompts were inline strings: no explicit answer structure, no rule against inventing CVE/OWASP ids or findings, no bounded history statement, no "the input already owns identity/location" clause | Prompts extracted to `REMEDIATION_SYSTEM_PROMPT` / `ASSISTANT_SYSTEM_PROMPT`, hardened, and asserted together with the exact request messages sent to the provider | `agents/remediation_agent.py`, `agents/assistant_agent.py` | `tests/test_m4_prompts.py` (6 tests) |
| 5 | Severity consistency across agents, summary, report, priorities | Severity computed once per finding by `analysis/severity.py`; health de-duplicates by rule family + location | No cross-component assertion; the JSON export carried a second score | Invariant tests (severity == score band everywhere, priorities ordered, PARTIAL/FAILED withhold) plus the canonical-score fix | `m3/report.py`, `tests/test_m4_severity_consistency.py` | 7 tests |
| 6 | Improve RAG retrieval relevance, ranking, citations, context selection, duplicate chunks, grounding, follow-ups | BM25 + hashing vectors + RRF hybrid; citations from real chunks; off-topic refusal | Retrieval returned three chunks from the same document for 4 of 12 evaluation questions, so one source filled every citation slot; citations could repeat a (source, section) pair under two numbers | Diversity step in `KnowledgeBase.search` (max 2 chunks per source, never shortens the list); `_citations` drops repeated (source, section) pairs | `m3/kb.py`, `agents/assistant_agent.py` | `tests/test_m4_rag_eval.py` (10 tests) |
| 7 | Browser verification of the complete workflow incl. PARTIAL/FAILED and responsive layouts | M3 UI verified previously | Changes touched assistant output, report JSON and retrieval, so the flows needed re-checking | Re-verified in the running app: sample load → validation accepted → analysis → 5 findings → health 50/100 with 2 grouped duplicates → PR summary → assistant answer with citations → JSON blob download (41.7 KB) → PDF download → PARTIAL and FAILED score withholding → 390 px layout with no page overflow | UI unchanged | manual, recorded in `M4_Test_Report.md` |
| 8 | Documentation set | README sections 1–9 | No M4 documents | Added the six M4 documents plus the project report, and a README pointer | `docs/milestone-4/*`, `README.md` | — |

## Deliberately not changed

* **Health formula** (`100 - min(100, Σ severity weight)`) — unchanged; only the
  duplicate grouping already documented in `m3/health.py` is applied, and the
  JSON export now reports that single value.
* **Detector rules** — no rule was added or tuned for M4. One observed false
  negative (`API_TOKEN = "…"` is not matched by the built-in `S-PY-SECRET`
  pattern, though Bandit's B105 reports it) is recorded in
  `M4_Known_Limitations.md` instead of being patched, because changing a
  detector after the M2 accuracy figures would invalidate those results.
* **M1/M2/M3 API contracts** — routes, payload shapes and the UI are untouched.
