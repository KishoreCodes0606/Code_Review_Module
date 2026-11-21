# M4 Optimization Report

Four optimisation areas were in scope: agent prompts, severity consistency,
retrieval quality and assistant accuracy. Each change below states what was
wrong, what changed, and how it was measured.

## 1. Agent prompts

Only two of the five agents have a prompt. The Code Analysis Agent and the
Security Vulnerability Agent are deterministic rule engines
(`analysis/python_metrics.py`, `analysis/security_rules.py`, `analysis/java_quality.py`,
plus Bandit/PMD adapters) — they have nothing to prompt, and that is the point:
deterministic output is authoritative. The PR Summary Agent is deterministic by
design and calls no model. The two prompts that exist are optional enrichment
paths and now live as module constants so they can be asserted:

* `agents/remediation_agent.py::REMEDIATION_SYSTEM_PROMPT`
* `agents/assistant_agent.py::ASSISTANT_SYSTEM_PROMPT`

| Prompt | Before | After (added clauses) |
|---|---|---|
| Remediation | "Return ONLY a JSON array… reuse an input finding_id verbatim… Never add findings, rule ids, files or line numbers." | Adds: never add CVE ids / OWASP categories / links; the input already carries the authoritative identity and location; explain only that finding's root cause; keep the fix minimal and behaviour-preserving; match the input language; `corrected_code` must compile or parse in that language; never claim the fix was applied, tested or reviewed; empty string when unsure |
| Assistant | "Answer ONLY from the numbered context… cite with [n]… say so if the context does not answer… untrusted data… under 250 words." | Adds an explicit answer structure (direct answer → reason → fix); use analysis facts verbatim for counts/rule ids/severities/lines and never state any that are absent; use earlier turns only to resolve what a follow-up refers to; never invent sources, CVE or OWASP ids |

Safety properties are unchanged and now regression-tested: the model cannot add,
remove or relabel a finding, cannot change a location, and its citations are
filtered against the retrieved context (`[9]` is discarded when only 3 chunks
were retrieved).

**Before/after measurability.** Prompt text only affects the optional LLM path,
and no provider is configured in this project, so output quality cannot be
measured here — that is stated rather than claimed. What *is* measurable is that
the hardened prompts changed no deterministic output: the three samples produce
the same 18 findings, the same health scores and the same 12/12 retrieval result
before and after the change, and `tests/test_m4_prompts.py` asserts the exact
messages sent to the provider (system prompt identity, untrusted-data labelling,
bounded history, no credential leakage).

## 2. Severity consistency

Findings are scored once, by `analysis/severity.py`, from the rule catalogue.
The only cross-component issue found was in the **JSON report**, which carried
two numbers both called a health score:

* `run.health_score` — the M2 value, summing severity weights over every
  reported finding (so `S-PY-SQLI` and `bandit-B608` on line 24 cost 25 + 12);
* `health.score` — the M3 value, which de-duplicates by rule family + location
  first (25 only), as documented in `m3/health.py`.

Fix: the report now publishes exactly one canonical `health_score` (the
de-duplicated M3 value) and preserves the raw M2 number as `m2_health_score`
when the two differ. The PDF already used only the de-duplicated value, so PDF
and JSON now agree.

Effect on the samples: sample 1 reports 70/100 (raw M2 value was 53), sample 2
45/100 (no duplicates, unchanged), sample 3 29/100 (raw value was 0, i.e. capped).
The formula itself is untouched.

Also verified and now asserted:

| Property | Result |
|---|---|
| `severity == score_band(severity_score)` for every finding | holds for all 18 sample findings |
| Health component counts × weights = penalty; score = 100 − penalty (capped) | holds |
| Grouped duplicate is charged at the higher severity (order-independent) | holds |
| Summary severity counts = Counter(merged findings) | holds |
| Report, summary, remediation and priorities use the same severity per finding | holds |
| Priorities ordered by severity | holds |
| PARTIAL / FAILED withhold the score and return `INCOMPLETE_REVIEW` | holds |
| Report states why the severity table and health table count differently | now printed under the table |

## 3. Retrieval quality

Measured on the 12-question evaluation set before any change: every question
returned three chunks, and for 4 of 12 questions all three came from the same
document (1 distinct source). Three near-identical citations crowd out the
second document a reviewer needs.

Change: `KnowledgeBase.search` now retrieves a wider candidate pool and applies
`_diversify`, which allows at most 2 chunks per source file and then tops the
list back up from the skipped candidates, so a result list is never shortened
and the top result never changes.

| Measure | Before | After |
|---|---|---|
| Top-1 document correct | 12 / 12 | 12 / 12 |
| Top-3 document correct | 12 / 12 | 12 / 12 |
| Queries with only one distinct source in top-3 | 4 / 12 | 0 / 12 |
| Distinct sources per query (min–max) | 1–3 | 2–3 |

The assistant additionally drops a repeated `(source, section)` citation pair,
so two chunks of the same subsection cannot appear as `[1]` and `[2]`.

BM25, the hashing vector index, RRF hybrid and the offline fallback are
unchanged; nothing requires an external service or credential.

## 4. Assistant accuracy

| Behaviour | Verified by |
|---|---|
| Answers built only from retrieved chunks + this run's facts | `test_answer_uses_only_retrieved_documents`, `test_every_citation_points_at_a_real_chunk` |
| Every `[n]` in the answer maps to a returned citation | same test (regex over the answer) |
| Citation numbering contiguous from 1 | same test |
| Repeated source/section not cited twice | same test |
| Off-topic question → no citations + explicit admission | 2 off-topic cases |
| Follow-up pronoun keeps the previous topic | `test_follow_up_question_keeps_the_topic` |
| Language filter honoured | `test_language_filter_never_returns_the_other_language` |
| LLM cannot add citations, invalid `[n]` discarded | `test_assistant_llm_answer_keeps_only_retrieved_citations` (M3) + M4 prompt tests |
| Provider failure falls back to retrieval | M3 contract tests (unchanged) |

Live verification in the browser (normal mode) returned an answer citing `[1]`,
`[2]`, `[3]` across two documents, with the source list rendered under the answer.

## 5. What was deliberately not optimised

* The health formula and its weights — changing them would invalidate the M2
  figures already reported.
* Detector thresholds — an observed false negative (`API_TOKEN` for the built-in
  secret rule) is documented instead, because tuning it after the M2 accuracy
  measurement would make those numbers unreproducible.
* The UI layout — no redesign; only the data behind it changed.
