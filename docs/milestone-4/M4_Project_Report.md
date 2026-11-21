# Project Report — AI Code Review & Security Analysis Agent (Milestone 4)

## Abstract

This report covers the final milestone of an AI-assisted code review platform
for Python and Java. Milestones 1–3 delivered the submission gate, a parallel
multi-agent static analysis pipeline, and a layer of review assistance
(remediation, PR summary, retrieval-grounded assistant, health score and
PDF/JSON reporting). Milestone 4 validates that layer end to end, optimises the
weak points found during validation, and documents the system for demonstration.
The work produced three curated samples graded against a written oracle (12/12
expected detections, 0 false positives, 9/9 clean controls unflagged), a
12-question retrieval evaluation (12/12 top-1), a report-consistency suite, and
78 new automated tests (275 total). Two real defects were found and fixed during
validation: the JSON report published two competing health scores, and it could
list a remediation item for a finding the report did not contain. A third defect
found in the pre-delivery review — the assistant crashing when a finding was
selected before the question (`'Finding' object has no attribute 'get'`) — is
fixed in the same delivery and covered by six regression tests.

## 1. Introduction

Static review tools are easy to demonstrate and hard to trust. A detector that
reports nothing may have found nothing, or may have failed to parse the file; a
"security score" can be computed from an incomplete scan and read as reassurance;
an assistant can produce a confident paragraph with an invented source. The
project's guiding principle across all milestones has been that the deterministic
analysis is the authority, and that every surface (UI, PR summary, PDF, JSON,
assistant) must state the same facts and admit what it does not know.

## 2. Problem statement

Engineering teams need a review aid that (a) analyses Python and Java sources
without executing them, (b) explains each finding with a rule id, severity, CWE
or OWASP reference and a fix, (c) summarises the review in a form a reviewer can
act on, (d) answers follow-up questions from a trustworthy knowledge base, and
(e) produces an exportable report whose numbers agree with the underlying
findings. It must also be honest when an analysis is incomplete and must not
depend on paid external services to function.

## 3. Objectives of Milestone 4

1. Validate the Code Review Report Generation Module against its required
   content and internal consistency.
2. Conduct end-to-end testing with at least three distinct samples of varying
   complexity across Python and Java, recording true positives, false positives
   and false negatives.
3. Optimise agent prompts, severity consistency, retrieval quality and assistant
   accuracy.
4. Produce technical documentation, a project report and a final demonstration
   covering the three samples.

## 4. Existing system (M1–M3)

| Milestone | Delivered |
|---|---|
| M1 | Language gate (Python/Java only), syntax validation, size limit, submission payload and hashing |
| M2 | Parallel Code Analysis and Security Vulnerability agents, merge/de-duplicate, deterministic severity engine, health score, failure semantics (PARTIAL/FAILED) |
| M3 | Remediation agent, PR summary agent, retrieval-grounded assistant (BM25 + vectors + RRF), health payload, PDF/JSON report, optional LLM/embedding providers |

M4 changed none of these behaviours; it validated them and fixed two report-level
inconsistencies.

## 5. Proposed system (what M4 contributes)

* An **oracle-based sample suite**: three sources of increasing complexity, each
  with expected rule ids, severities, anchored locations, clean controls and
  remediation expectations.
* A **report validation suite** covering metadata, page numbering, severity and
  health agreement, remediation correspondence, duplicate handling, code
  wrapping, PARTIAL/FAILED honesty and stale-run isolation.
* A **severity consistency suite** proving one severity per finding across
  detector, health, summary, report and priorities.
* A **retrieval evaluation set** with measured relevance, citation validity and
  refusal behaviour, plus a diversity step so one document cannot fill every
  citation slot.
* **Hardened prompts** for the two optional LLM paths, asserted together with the
  exact provider request.

## 6. Architecture

```
React UI ──HTTP──► Python threaded server
                     ├─ M1 gate: language + syntax + size
                     ├─ M2 pipeline: quality agent ∥ security agent → merge → severity → health
                     └─ M3 service: remediation → PR summary → assistant → report (JSON/PDF)
                                   └─ knowledge base: BM25 + hashing/neural vectors + RRF
```

Runs and artifacts are in memory; the analysis never executes submitted code.
See `M4_Technical_Documentation.md` for the component-level detail.

## 7. Technology stack

Python 3.13 (stdlib HTTP server), `ast`/`radon`, `javalang`, Bandit, optional PMD,
custom rule catalogue and severity engine, BM25 + feature-hashing vectors +
reciprocal rank fusion, `reportlab`; React 19 + Vite 8 + Tailwind 4 on the
frontend; pytest for 275 automated tests.

## 8. Methodology

1. **Inspect before changing** — read every M3 module and test, then write the gap
   analysis (`M4_Gap_Analysis.md`).
2. **Oracle before measurement** — samples were written first and the expected
   results derived from the source and rule catalogue; the detector output was
   only compared afterwards. Expected results were never edited to make a test
   pass.
3. **Measure, then fix** — retrieval was measured on 12 questions before any
   change; the duplicate-source problem was visible in the measurement, which
   justified the diversity change and its before/after numbers.
4. **One source of truth** — health and severity are computed in one place; a test
   now asserts every surface agrees with that computation.
5. **Verify the running product** — the browser was used for the workflow the
   changes touched (assistant, exports, PARTIAL/FAILED, narrow layout), not only
   for unit-level checks.

## 9. Implementation summary

| Area | Change |
|---|---|
| `m3/report.py` | canonical `health_score` (+ `m2_health_score` when it differs); remediation filtered to reported findings; explanatory line under the severity table; report schema id in the header |
| `m3/kb.py` | retrieval diversity (≤2 chunks per source, list length preserved, wider candidate pool) |
| `agents/assistant_agent.py` | `ASSISTANT_SYSTEM_PROMPT` constant with answer structure, verbatim-fact rule, refusal rule, bounded history; citation de-duplication by (source, section) |
| `agents/remediation_agent.py` | `REMEDIATION_SYSTEM_PROMPT` constant forbidding invented ids/locations/CVEs and unverified claims |
| tests | `test_m4_samples.py`, `test_m4_report_validation.py`, `test_m4_severity_consistency.py`, `test_m4_rag_eval.py`, `test_m4_prompts.py`, `test_m4_selected_finding_assistant.py`; fixtures `expected.json`, `rag_eval.json` and three sample sources |
| docs | this milestone-4 directory and a README section 10 |

## 10. Testing and results

| Check | Result |
|---|---|
| `python -m pytest tests -q` | **275 passed** (197 pre-existing + 72 M4 + 6 P1 regression), 20 warnings, 32–39 s |
| `npm run lint` | **0 errors**, 22 documented warnings |
| `npm run build` | success — JS 339.34 kB (gzip 100.25), CSS 32.35 kB (gzip 6.57) |
| Sample 1 (Python, low) | 4 findings, health 70/100, 3 PDF pages |
| Sample 2 (Java, medium) | 3 findings, health 45/100, 3 PDF pages |
| Sample 3 (Python, high) | 11 findings, health 29/100, 6 PDF pages |
| Detection accuracy on the oracle | 12/12 expected, 0 FN, 0 FP, 9/9 clean controls |
| Retrieval | 12/12 top-1, 12/12 top-3; no query limited to one source (was 4/12) |
| Assistant | every citation resolves to a real chunk; both off-topic questions refused; a selected finding is answered instead of raising |
| Reports | severity counts, health and remediation agree with the findings; PARTIAL/FAILED withhold the score |
| Browser | full workflow verified for a Python sample; JSON export 29.2 KB; PDF download served; PARTIAL and FAILED states honest; no page overflow at 390 / 768 / 1440 px |

## 11. Screenshots and visual evidence

* `docs/qa/ui-mobile-390.png` — narrow layout, findings table scrolling inside its
  container.
* `docs/qa/ui-mobile-health-390.png` — health card and deduction breakdown at
  390 px.
* `docs/qa/pdf-report-page1.png` — first page of a generated PDF report
  (title block, review status, run metadata, health table).

These artefacts predate M4 (they were captured during M3 QA); M4 added structural
assertions over the PDF rather than new raster captures.

## 12. Limitations

The full list is in `M4_Known_Limitations.md`. In brief: the optional LLM and
neural embedding providers are implemented and contract-tested but not
live-verified (no credentials); retrieval at runtime is lexical; detection is
heuristic and limited to implemented Python/Java rules, with one documented false
negative for an all-caps secret constant; runs are in memory; the application is
not deployed; and browser verification covered all three samples' workflows plus
the responsive and failure states, not every click path. The pre-delivery review
found one open defect in the "ask about the selected finding" path
(`M4_Known_Limitations.md` §8).

## 13. Future scope

* Wire a verified embedding provider and re-run the same evaluation set to
  compare lexical and neural retrieval on identical questions.
* Add interprocedural taint tracking for Python and Java to move beyond
  pattern-level detection.
* Persist runs and review history (the current store is in memory) and add a
  diff-aware mode that reviews only changed lines in a pull request.
* Add a browser E2E suite (Playwright) to convert the manual workflow checks into
  repeatable tests.
* Extend the oracle approach to a larger corpus so detection rates can be quoted
  with confidence intervals.

## 14. Conclusion

Milestone 4 turned a working M1–M3 prototype into a validated deliverable: the
report module is checked against its own required content and against the
findings it describes, three samples exercise the pipeline end to end with a
written oracle, retrieval and assistant behaviour are measured rather than
asserted, and every optimisation is backed by a before/after observation. The two
defects found during validation (competing health scores; a remediation item for
an absent finding) were fixed at the source and locked down with tests. What
remains unverified — live LLM/neural providers, at-scale accuracy, deployment — is
stated explicitly rather than implied, which is the condition for trusting the
parts that were verified.
