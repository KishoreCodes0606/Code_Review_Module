# M4 Known Limitations

Honest scope statement for the final demonstration. Anything below was not
verified, or is verified only in a bounded way.

## 1. External integrations not verified live

| Integration | State |
|---|---|
| LLM (OpenAI-compatible chat) | Implemented and contract-tested against a local fake provider (request shape, auth header, parsing, HTTP/JSON/empty failures, deterministic fallback). **Never called against a real provider** — no key/model is configured in this project. |
| Neural embeddings (`EMBEDDING_PROVIDER=openai` or sentence-transformers) | Implemented with persistence and fallback. **Not active**: the running system reports `provider=hashing`, `semantic=false`. All reported retrieval numbers come from BM25 + hashing vectors + RRF, which are lexical, not neural. |
| PMD for Java quality | Optional, downloaded on demand. Java quality coverage depends on availability; sample 2 assertions are security-only for that reason. |
| ChromaDB / sentence-transformers stack | Not installed; the status endpoint reports `vector_stack_installed=false`. |

No accuracy claim in the M4 documents depends on any of the above.

## 2. Language support

* Python and Java only. JavaScript, C++, and markup are rejected by the M1
  language gate by design.
* Java analysis is text/AST-assisted (`javalang` + PMD when present) and does not
  build a full type model; interprocedural data-flow reasoning is limited to what
  the rule patterns encode.
* Python quality metrics come from `radon`/`ast` heuristics; framework-specific
  issues (Django ORM misuse, SQLAlchemy, Flask templates) are not modelled.

## 3. Detection limitations

* Rules are pattern/heuristic based. Detection depends on the sink expression
  being visible in the submitted file.
* **Known false negative:** the built-in `S-PY-SECRET` pattern does not match an
  all-caps constant such as `API_TOKEN = "…"`; Bandit's `B105` covers that line in
  the current environment. Whether the weakness is reported therefore depends on
  Bandit being installed.
* Python XSS is not a rule (only Java `S-JAVA-XSS` exists); Python template
  injection is not modelled.
* Duplicate reports across engines are grouped for scoring by rule family plus
  location; an engine reporting a genuinely different weakness on the same line is
  kept separately, which is why the findings table can show more rows than the
  health table counts.
* A clean result means "no implemented rule matched". It is never a security
  guarantee, and the UI, PR summary and PDF all say so.
* PMD rule ids are collapsed into `Q-pmd-generic`; the original rule name is in
  the finding description only.

## 4. RAG limitations

* Retrieval is lexical at runtime (BM25 + hashing vectors). Synonyms are handled
  by a fixed synonym table, not by a semantic model.
* 13 documents / 62 chunks cover the OWASP-style topics in the project knowledge
  base; anything outside that corpus is refused rather than answered.
* Evaluation is a 12-question curated set (12/12 top-1). That is a relevance
  regression suite, not a benchmark of answer correctness at scale.
* Assistant answers in `retrieval_only` mode quote retrieved passages; they are
  grounded but not synthesised. With no LLM configured, wording is template-based.
* Chat history is per run, capped at 40 messages and held in memory only.

## 5. Runtime and deployment

* Runs, artifacts and chat history are in memory: restarting `server.py` discards
  them. Nothing is persisted to a database.
* The application is not deployed. It runs locally (backend `127.0.0.1:8000`,
  frontend `:5174`); no container, CI pipeline or hosted environment is part of
  this milestone.
* The backend is a stdlib threaded server intended for local/demo use, with CORS
  limited to the local frontend; it is not hardened as an internet-facing service.
* Fault simulation for PARTIAL/FAILED is process-start-only
  (`CODE_REVIEW_TEST_FAULTS`), deliberately with no HTTP toggle.

## 6. Verification scope in M4

| Verified | Not verified |
|---|---|
| 275 automated tests (M1–M4), lint, production build | Browser automation across every control; no E2E framework is configured |
| Full workflow in the running UI for one Python sample (validation → analysis → findings → filters → details → remediation → health → PR summary → assistant → JSON/PDF download) | The same click-through for the Java and complex samples (those are covered by API-level tests) |
| PARTIAL and FAILED UI states (score withheld, Incomplete Review) | PARTIAL/FAILED while an LLM is configured |
| 390 px layout: no page overflow, table scrolls inside its container | Tablet/desktop pixel review was measurement-based, not visual |
| PDF structure, page counts (3/3/6) and content assertions | A fresh raster/visual inspection of the M4 PDFs — the last visual check is `docs/qa/pdf-report-page1.png` from M3 |

## 7. Data and privacy

* Submitted code is never executed and never written to disk by the analysis.
* The optional LLM path sends findings text, code snippets and retrieved KB
  passages to the configured provider; that is why it is opt-in and off by default.
* No credential is hardcoded; `.env` files are git-ignored and only
  `.env.example` (placeholders) is tracked.

## 8. Defect found in the pre-delivery review (fixed before delivery)

Selecting a finding and then asking the assistant failed:

| Step | Before the fix | After the fix |
|---|---|---|
| `POST /api/analysis/chat` with only `run_id` + `question` | normal answer with citations | unchanged |
| same request plus `selected_finding_id` | HTTP 200 body `{"status": "error", "message": "Failed to process chat: 'Finding' object has no attribute 'get'"}` | normal answer that describes the selected finding, keeps its KB citations and adds the real remediation |
| same in the UI (`View Details` on a finding, then ask) | the assistant panel showed the same error | the panel shows the answer |

Cause: `agents/assistant_agent.py::_analysis_facts` read the selected finding
with `.get(...)` although findings are `Finding` objects; the rest of the
function already used the `_get` helper. Fix: every field of the selected
finding is read through `_get`, so both shapes (a pipeline `Finding` and a dict,
which some callers pass) work, and the remediation lookup compares against the
same resolved id. No API field, response shape, citation, retrieval or prompt
behaviour changed.

Regression coverage: `tests/test_m4_selected_finding_assistant.py` (6 tests) — a
selected Finding object, a selected finding as a dict, a valid answer with real
KB citations and the run's remediation, an id from another/nonexistent run being
rejected, run-specific facts/citations, and the unselected question path. The
plain question path was never affected.
