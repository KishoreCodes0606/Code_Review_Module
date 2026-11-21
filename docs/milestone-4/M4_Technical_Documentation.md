# M4 Technical Documentation

Consolidated technical reference for the AI Code Review & Security Analysis
Agent after M4. It complements the README (setup, environment variables) with
the architecture and the mechanics of each stage.

## 1. Architecture

```
Browser (React 19 + Vite + Tailwind)
   │  fetch /api/submissions/validate, /api/analysis, /api/analysis/{id}/…, /api/m3/status
   ▼
Python stdlib HTTP server (server.py, ThreadingHTTPServer, CORS)
   │
   ├── M1 gate  : language detection, syntax validation, size limit (200 KB)
   ├── M2 pipeline (orchestrator/pipeline.py)
   │      fan-out  ──► Code Analysis Agent   (radon/ast for Python, javalang + PMD for Java)
   │              └─► Security Vulnerability Agent (custom rule engine + Bandit)
   │      fan-in   ──► merge + de-duplicate + severity scoring + health
   └── M3 service (m3/service.py)
          remediation → PR summary → RAG assistant → JSON/PDF report
```

Runs live in memory (`orchestrator/pipeline.py::_runs`, `m3/store.py`), guarded by
locks because the server is threaded. Artifacts expire with the process; there
is no database and nothing is written to disk except an optional embedding cache
under `m3/.cache/` (git-ignored).

## 2. Technology stack

| Layer | Choice | Why |
|---|---|---|
| Backend | Python 3.13 stdlib `http.server` | zero web-framework dependency; the project must run offline |
| Analysis | `ast`/`radon`, `javalang`, `bandit`, optional PMD, custom rule engine | deterministic, explainable findings |
| Scoring | `analysis/severity.py` (impact × exploitability, bands) | one source of truth for both agents |
| Reports | `reportlab` (PDF), `json` (canonical export) | PDF is a rendering of the same data |
| Retrieval | BM25 over the project chunker + hashing/neural vectors + RRF | offline-first, no external service required |
| Frontend | React 19, Vite 8, Tailwind 4, lucide-react, oxlint | existing M1/M2 stack, unchanged |
| Tests | pytest (275 tests) | one command, no network |

## 3. Agents and responsibilities

| Agent | File | Input | Output | Deterministic |
|---|---|---|---|---|
| Code Analysis Agent | `agents/code_analysis_agent.py` | source + language | quality findings, metrics (`parsed`, `pmd_status`) | yes |
| Security Vulnerability Agent | `agents/security_agent.py` | source + language | security findings with CWE/OWASP | yes |
| Remediation Agent | `agents/remediation_agent.py` | merged findings | per-finding problem / fix / code / best practice / reason / references | yes, with optional LLM wording |
| PR Summary Agent | `agents/pr_summary_agent.py` | run payload + findings + remediation | review status, overview, breakdown, priorities, caveats | yes (no LLM) |
| Assistant Agent | `agents/assistant_agent.py` | question + run facts + KB | answer, citations, grounding flag | yes, with optional LLM phrasing |

Every agent returns an explicit failure record instead of an empty "clean"
result; a scanner that could not parse the source marks the run PARTIAL.

## 4. Orchestration flow

1. `POST /api/analysis` → M1 gate validates language/syntax/size.
2. `pipeline.analyze_code` starts both agents in a 2-worker pool, each bounded by
   a 60 s deadline; a timeout becomes a `timeout` result, never silence.
3. `merge_findings` concatenates and drops exact `(rule_id, file, line_start)`
   duplicates, ordering security findings first by severity score.
4. Terminal status: all succeeded → `COMPLETED`; every agent failed with no
   findings → `FAILED`; otherwise `PARTIAL`.
5. M3 artifacts are generated lazily on first request and cached per run;
   regenerating remediation invalidates the cached summary so a summary can never
   describe stale fixes.

## 5. Knowledge base and retrieval

* 13 documents, 62 chunks, produced by the project's own structure-aware chunker
  (`secure-kb/kb/chunker.py`) — 12 curated markdown documents plus the combined
  reference text.
* BM25 with heading weighting, synonym expansion, language and OWASP filters, and
  demotion of meta sections (evaluation/test-design) unless the question is about
  evaluation itself.
* Vectors: hashing (default, offline) or OpenAI-compatible / sentence-transformers
  when configured. Persisted to `m3/.cache/vectors-*.json.gz` keyed by a signature.
* Hybrid = reciprocal rank fusion of lexical and dense lists.
* Diversity step: at most 2 chunks per source file, list length preserved.
* Citations always come from a real chunk (title, section, source, url, CWE,
  OWASP); the assistant refuses to answer when nothing relevant is retrieved.

## 6. Health score

```
penalty = Σ severity_weight(unique finding)      # critical 25, high 12, medium 5, low 2, info 0
score   = max(0, 100 - min(100, penalty))
```

Unique means keyed by (rule family, file, line): a Bandit report of the same
weakness as a built-in rule is charged once, while both remain visible in the
findings table. A score is only published for `COMPLETED` runs; PARTIAL/FAILED
withhold it. `100` means "no implemented rule matched", never "secure".

## 7. Report generation

`m3/report.py` builds one payload and renders it twice:

* **JSON** (`build_json_report`): schema `m3.1`, run, canonical `health`,
  findings, summary, remediation (filtered to findings in this report),
  disclaimer. `m2_health_score` preserves the raw M2 value when it differs.
* **PDF** (`build_pdf_report`, reportlab A4): title block with run id, language,
  generation time, report schema and the font actually embedded; review status;
  run metadata table; executive overview; health score with deduction table;
  severity breakdown (with a note explaining reported vs unique counts);
  prioritized actions; every finding with rule id, severity, location, snippet and
  its remediation; caveats; scope and disclaimer; footer with report id and
  `Page N`.
* Long code is wrapped by measured text width (`CODE_LIMIT_PT`), not by character
  count; characters the embedded font lacks are shown as `?` instead of silently
  disappearing.

## 8. API surface (M3/M4 relevant)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/m3/status` | capabilities, KB/retrieval/embedding status, LLM config, PDF support |
| POST | `/api/analysis` | run the M1 gate + M2 pipeline |
| GET | `/api/analysis/{run_id}` | run summary + M3 health payload |
| GET | `/api/analysis/{run_id}/findings` | findings (severity/category filters) |
| GET | `/api/analysis/{run_id}/remediation` | remediation bundle |
| GET | `/api/analysis/{run_id}/summary` | PR summary |
| POST | `/api/analysis/summary` | regenerate summary (`force`) |
| POST | `/api/analysis/chat` | assistant question (`run_id`, `question`, `use_llm`, `selected_finding_id`) |
| GET | `/api/analysis/{run_id}/chat/history` | session transcript |
| GET | `/api/analysis/{run_id}/report?format=json\|pdf` | report download |

## 9. Setup

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows (source .venv/bin/activate elsewhere)
pip install -r requirements.txt
python server.py                   # http://localhost:8000

cd code-submission-ui
npm install
npm run dev                        # http://localhost:5174
```

Optional (never required): copy `.env.example` to `.env` and set `LLM_API_KEY` +
`LLM_MODEL` for LLM wording, and/or `EMBEDDING_PROVIDER=openai` with
`EMBEDDING_API_KEY` + `EMBEDDING_MODEL` for neural vectors. With nothing
configured the system is fully functional in deterministic/BM25 mode.

## 10. Testing

```bash
python -m pytest tests -q           # 275 tests
cd code-submission-ui && npm run lint && npm run build
```

| Suite | What it covers |
|---|---|
| `test_m1_regression.py`, `test_api_end_to_end.py` | M1 gate, validation, end-to-end API |
| `test_python_quality.py`, `test_java_quality.py`, `test_security_rules.py`, `test_bandit_adapter.py`, `test_analysis_completeness.py` | M2 detectors and severity |
| `test_m3_*.py` | health, remediation, summary, RAG, report, faults, LLM contract, API |
| `test_m4_samples.py` | three curated samples graded against an oracle |
| `test_m4_report_validation.py` | report ↔ findings ↔ health consistency, wrapping, staleness |
| `test_m4_severity_consistency.py` | one severity per finding across components; PARTIAL/FAILED |
| `test_m4_rag_eval.py` | measured retrieval relevance, citation validity, refusals |
| `test_m4_prompts.py` | prompt content and the exact provider request |
