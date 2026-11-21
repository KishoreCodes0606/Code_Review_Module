# M4 Test Report

All numbers below come from runs on this machine during M4. No value is
estimated or copied from another milestone.

## 1. Methodology

* **Deterministic pipeline** — each sample is analysed by the real orchestrator
  (`orchestrator/pipeline.py`): validation (M1 gate) → Code Analysis Agent and
  Security Vulnerability Agent in parallel → merge → health → remediation → PR
  summary → assistant → JSON/PDF report.
* **Oracle first, measurement second** — `tests/fixtures/m4/expected.json` was
  written by reading each sample's source (the weakness, its expected severity
  from `analysis/rule_catalog.py`, and the line that contains it). The tests then
  compare detector output against that oracle. Nothing in the oracle was edited
  to make a test pass.
* **Location tolerance** — a detector may report the enclosing statement
  (`cursor.execute(query)`) or the line that built the unsafe value, so each
  expectation carries an anchor string and a tolerance of 0–2 lines.
* **Clean controls** — each sample contains hand-written safe implementations
  (parameterized query, canonicalised path, plain aggregation). A security
  finding inside one of those spans is counted as a false positive.

## 2. The three samples

| ID | File | Language | Complexity | Deliberate weaknesses | Clean controls |
|---|---|---|---|---|---|
| `sample1_basic_inventory` | `tests/fixtures/m4/sample1_basic_inventory.py` | Python | Low | string-built SQL query; MD5 used for a digest | input validation + formatting, aggregation, comparison, fixed DB path |
| `sample2_medium_accounts` | `tests/fixtures/m4/sample2_medium_accounts.java` | Java | Medium | `Statement` concatenation; `ObjectInputStream.readObject`; `AES/ECB` | `AuditLog` class (validation + list append) |
| `sample3_complex_backend` | `tests/fixtures/m4/sample3_complex_backend.py` | Python | High | hardcoded token; f-string SQL; MD5 password digest; unconfined path; `subprocess.call(shell=True)`; bare `except`; 4-level nesting | parameterized `load_user`, confined `read_upload`, `summarise_orders`, `get_connection` |

## 3. Expected versus actual

### Sample 1 — basic Python (measured: 4 findings, health 70/100, 3 PDF pages)

| Expected (oracle) | Severity | Actual | Location | Verdict |
|---|---|---|---|---|
| `S-PY-SQLI` string-built query | critical | `S-PY-SQLI` critical (score 9.4) | line 24 vs anchor 25 | TP |
| `S-PY-CRYPTO` MD5 digest | medium | `S-PY-CRYPTO` medium (5.5) | line 46 = anchor | TP |
| second engine on the same line | — | `bandit-B608` high (line 24), `bandit-B324` medium (line 46) | — | grouped for scoring (2 duplicates) |
| 4 clean controls | — | no security finding in any control span | — | 4 TN |

### Sample 2 — intermediate Java (measured: 3 findings, health 45/100, 3 PDF pages)

| Expected (oracle) | Severity | Actual | Location | Verdict |
|---|---|---|---|---|
| `S-JAVA-SQLI` concatenated statement | critical | `S-JAVA-SQLI` critical (9.4) | line 26 = anchor | TP |
| `S-JAVA-DESER` `readObject` | critical | `S-JAVA-DESER` critical (9.0) | line 35 vs anchor 36 | TP |
| `S-JAVA-CRYPTO` ECB mode | medium | `S-JAVA-CRYPTO` medium (5.5) | line 42 = anchor | TP |
| `AuditLog` clean component | — | no finding in the class body | — | 1 TN |

### Sample 3 — complex Python backend (measured: 11 findings, health 29/100, 6 PDF pages)

| Expected (oracle) | Severity | Actual | Location | Verdict |
|---|---|---|---|---|
| hardcoded token | medium (alias family) | `bandit-B105` medium (5.9) — built-in `S-PY-SECRET` did **not** fire | line 18 = anchor | TP (other engine) |
| f-string SQL | critical | `S-PY-SQLI` critical (9.4) | line 47 vs anchor 48 | TP |
| MD5 password digest | medium | `S-PY-CRYPTO` medium (5.5) | line 54 = anchor | TP |
| unconfined path | medium | `S-PY-PATH` medium (4.9) | line 74 = anchor | TP |
| `shell=True` command | critical | `S-PY-SHELL` critical (9.5) | line 90 = anchor | TP |
| bare `except` | low | `Q-broad-exception` low (1.8) | line 68 = anchor | TP |
| 4-level nesting | low | `Q-deep-nesting` low (2.1) | line 93 (function) | TP |
| second engine reports | — | `bandit-B602`, `bandit-B608`, `bandit-B324`, `bandit-B404` | — | 3 grouped, `B404` kept separately (import-only warning has no built-in family) |
| 4 clean controls | — | no security finding in any control span | — | 4 TN |

## 4. Detection accuracy (measured confusion matrix)

| Sample | True positives | False negatives | False positives | Clean controls with no finding |
|---|---|---|---|---|
| sample1 | 2 | 0 | 0 | 4 / 4 |
| sample2 | 3 | 0 | 0 | 1 / 1 |
| sample3 | 7 | 0 | 0 | 4 / 4 |
| **Total** | **12 / 12** | **0** | **0** | **9 / 9** |

* A false positive is a **security** finding outside the expected rule set. No
  such finding occurred in any sample.
* Quality findings are not counted as false positives: the M4 oracle only pins
  the two quality rules that are unambiguous in sample 3 (`Q-broad-exception`,
  `Q-deep-nesting`); other quality output is reported as observation, because
  PMD availability changes Java quality coverage per machine.
* **Known false negative (outside these samples' oracle):** the built-in
  `S-PY-SECRET` detector did not flag `API_TOKEN = "demo-token-…"` in sample 3,
  because its pattern does not cover all-caps token names; Bandit's `B105`
  reported the same line, so the weakness is still surfaced. This is recorded as
  a limitation rather than patched, to keep M2 accuracy figures reproducible.

## 5. Remediation quality

| Sample | Findings covered | With illustrative code | Manual review required |
|---|---|---|---|
| sample1 | 4 / 4 | 4 | 0 |
| sample2 | 3 / 3 | 3 | 0 |
| sample3 | 11 / 11 | 10 | 1 (`bandit-B404` — import-only warning, no generic rewrite) |

Every remediation item preserved the original `finding_id`, `rule_id`, severity
and line range; the tests assert this. Corrected code exists for every rule that
has a deterministic template (`S-PY-SQLI`, `S-PY-CRYPTO`, `S-PY-PATH`,
`S-PY-SHELL`, all `S-JAVA-*` security rules, and the quality rules with a safe
rewrite). Remediation never claims to have modified a file.

## 6. RAG relevance and assistant accuracy

Dataset: `tests/fixtures/m4/rag_eval.json` — 12 questions across SQL injection
(Python/Java), XSS, password hashing, hardcoded secrets, path traversal, command
injection, deserialization, XXE, access control, code smells, CWE/severity
reference, plus 2 off-topic questions and 1 follow-up.

| Measure | Result |
|---|---|
| Top-1 document correct | 12 / 12 |
| Top-3 document correct | 12 / 12 |
| Expected topic tokens present in the cited chunks | 12 / 12 |
| Queries where one document supplied all 3 citations (before M4) | 4 / 12 |
| Same measure after the diversity change | 0 / 12 (≥2 distinct sources per query) |
| Citations pointing at a real chunk (chunk id, source, title) | 100% — asserted |
| Repeated `(source, section)` pair under two citation numbers | 0 after the dedupe change |
| Off-topic questions refused without citations | 2 / 2 |
| Follow-up ("Why does that work?") keeps the topic | yes — same source retrieved |
| Language filter (Java question) returns no Python-only guidance | yes |

Assistant output was verified in the running app: the answer cited `[1]`–`[3]`
from two distinct documents, and the UI listed the sources under the answer.

**Defect found in the pre-delivery review (fixed before delivery):** when a
finding was selected first (`View Details` → ask the assistant), the chat
request returned `Failed to process chat: 'Finding' object has no attribute
'get'` because `agents/assistant_agent.py::_analysis_facts` read the selected
finding with `.get(...)` while findings are `Finding` objects. Every field now
go through the shared `_get` helper, and
`tests/test_m4_selected_finding_assistant.py` pins both finding shapes
(Finding object and dict), a valid citation-grounded answer, an unknown
selection and run-specific context. The plain question path was never
affected. See `M4_Known_Limitations.md` §8.

## 7. Report completeness

| Check | Result |
|---|---|
| JSON contains schema id, generated_at, run, health, findings, summary, remediation, disclaimer | yes |
| Severity counts equal the findings list | asserted |
| Health score equals `compute_health` and the PR summary score | asserted |
| Every remediation item belongs to a reported finding | asserted (filter added) |
| Duplicate findings in a report | none (merge dedupes; two engines on one line are kept as separate evidence but scored once) |
| Long code wrapping | 240+ character line splits inside `CODE_LIMIT_PT`, verified with `pdfmetrics.stringWidth` |
| PARTIAL / FAILED | score withheld in JSON, PDF and UI; review status `INCOMPLETE_REVIEW` |
| Stale findings | two consecutive runs produce reports containing only their own findings and run id |
| PDF structure | `%PDF-` header, page numbering, run id in metadata, 3 / 3 / 6 pages for the samples (page count read from the PDF `/Count` entry) |

## 8. Automated test result

```
python -m pytest tests -q
275 passed, 20 warnings in 39.14s
```

(Run time varies with machine load: 32.03 s on the first M4 run, 37.59 s on the
pre-delivery review run, 39.14 s with the six selected-finding regression tests.)

197 of those tests are the pre-existing M1/M2/M3 suite (unchanged); 72 are the M4
validation suites and 6 are the selected-finding assistant regression tests added
with the P1 fix (269 before those six). `npm run lint` → 0 errors, 22 warnings; `npm run build` → success
(JS 339.34 kB / gzip 100.25 kB, CSS 32.35 kB / gzip 6.57 kB).

## 9. Limitations of this test report

* The oracle encodes *expected* detections for three samples; it is not a
  benchmark of detection rate across arbitrary code.
* Java quality coverage depends on PMD being downloadable on the machine; the
  sample 2 assertions are security-only for that reason.
* The optional LLM and neural embedding paths are not exercised against a live
  provider (no credentials); their contract tests use a local OpenAI-compatible
  server.
* Report PDFs were validated structurally and by page count in M4; the last
  visual (raster) inspection was done in M3 (`docs/qa/pdf-report-page1.png`).
