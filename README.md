================================================================================
PROJECT: AI Code Review & Security Analysis Agent
         (Infosys Springboard Internship - Smart Code Inspection Platform
          with Vulnerability Detection System)
================================================================================

--------------------------------------------------------------------------------
1. WHAT THE PROJECT IS
--------------------------------------------------------------------------------
You are building a multi-agent AI platform that automatically reviews source
code. A developer submits Python/Java code (paste or file upload), and a
pipeline of 5 specialized AI agents runs automatically:

  AGENT 1 - Code Analysis Agent
    Reviews code structure, detects code smells, design anti-patterns,
    complexity issues and poor practices.

  AGENT 2 - Security Vulnerability Agent
    Scans for OWASP-standard vulnerabilities: SQL Injection, XSS, CSRF,
    hardcoded secrets, insecure authentication, broken access controls.

  AGENT 3 - Remediation Agent
    Generates specific fix recommendations with corrected code examples and
    best practice explanations for each finding.

  AGENT 4 - PR Summary Agent
    Compiles all agent findings into a structured, human-readable
    pull-request style review summary.

  AGENT 5 - Conversational Code Assistant
    RAG-powered Q&A grounded in a secure coding knowledge base, for follow-up
    queries, deeper explanations and best practice guidance.

SIX MODULES:
  1. Code Submission Module - paste / file upload, Python + Java, syntax
     validation
  2. Secure Coding Knowledge Base and RAG Pipeline Module
  3. Multi-Agent Orchestration and Analysis Pipeline
  4. Findings Display and Severity Scoring Module
  5. Conversational Code Assistant Interface
  6. Code Review Report Generation and Export Module

CORE IDEA IN ONE LINE:
  A developer submits Python/Java code, a pipeline of specialised AI agents
  finds quality and security problems, proposes fixes grounded in trusted
  security standards, and a chat assistant explains anything the developer
  does not understand.

--------------------------------------------------------------------------------
2. THE 5 OUTCOMES YOU MUST ACHIEVE
--------------------------------------------------------------------------------
  1. Multi-agent pipeline that automatically analyzes submitted code for
     quality issues, security vulnerabilities and best practice violations.
  2. Detect OWASP-standard vulnerabilities with severity scoring and
     specific remediation recommendations (Security Vulnerability Agent).
  3. Generate corrected code examples and refactoring suggestions grounded
     in secure coding standards (Remediation Agent).
  4. RAG-powered Conversational Code Assistant for follow-up queries on
     flagged issues and secure coding guidance.
  5. Structured, exportable code review reports with severity breakdown,
     findings summary and remediation roadmap.

--------------------------------------------------------------------------------
3. MILESTONE 1 (WEEK 1-2) - YOUR 4 ASSIGNED TASKS
--------------------------------------------------------------------------------
  TASK 1: Study OWASP vulnerability standards, secure coding guidelines,
          code smell patterns and RAG architecture.
          -> STATUS: DONE. Output = "Milestone 1 - Task 1 Research Report"
             (13-page PDF, text extracted to .txt)

  TASK 2: Design system architecture, agent responsibilities, orchestration
          flow and data models.

  TASK 3: Develop Code Submission Module - direct code paste and file upload
          for Python and Java source files with syntax validation.

  TASK 4: Build Secure Coding Knowledge Base - index OWASP guidelines,
          secure coding standards and best practice documents into a RAG
          pipeline via chunking, embedding and vector store indexing.

--------------------------------------------------------------------------------
4. WHAT THE TASK 1 RESEARCH REPORT CONTAINS
--------------------------------------------------------------------------------
  SECTION 1 - Purpose of the Report
    Maps the four research areas to the platform components:
      OWASP standards      -> Security Vulnerability Agent, severity scoring
      Secure coding        -> Remediation Agent, knowledge base content
      Code smell patterns  -> Code Analysis Agent
      RAG architecture     -> Knowledge base, Chat Assistant, Remediation
                              Agent grounding

  SECTION 2 - OWASP Vulnerability Standards
    - What OWASP is: Top 10, ASVS, Cheat Sheet Series, Code Review Guide.
    - OWASP Top 10 (2021) full table: A01 Broken Access Control through
      A10 SSRF, each with meaning and typical code-level signal.
    - Note: 2025 edition exists - keep OWASP version as configurable data.
    - The 8 vulnerabilities the project MUST detect, each with OWASP
      category + CWE ID + vulnerable pattern + secure pattern:
        SQL Injection            A03  CWE-89
        Cross-Site Scripting     A03  CWE-79
        Hardcoded secrets        A02/A07  CWE-798
        Broken access control    A01  CWE-284 / CWE-639
        CSRF                     A01/A04  CWE-352
        Insecure authentication  A07  CWE-256 / CWE-327
        Command injection        A03  CWE-78
        Insecure deserialization A08  CWE-502
        Path traversal           A01  CWE-22
    - Java equivalents: Statement.executeQuery concatenation, Runtime.exec,
      ObjectInputStream, MD5, unescaped getWriter(), hardcoded passwords,
      XXE (CWE-611).
    - Related standards: CWE, CVE, CVSS (0-10 severity bands), SANS/CWE Top 25.

  SECTION 3 - Secure Coding Guidelines
    - 10 core principles:
      1. Validate input, encode output
      2. Use parameterised interfaces
      3. Least privilege
      4. Defence in depth
      5. Fail securely
      6. Secure by default
      7. Never hardcode secrets
      8. Use proven cryptography
      9. Keep dependencies updated
      10. Log security events, never log secrets
    - Python-specific: avoid eval/exec/pickle/yaml.load/shell=True; use
      secrets module; defusedxml; no assert for security checks.
    - Java-specific: PreparedStatement; SecureRandom; disable XXE; OWASP
      Java Encoder; try-with-resources.
    - Knowledge base sources to index: OWASP Cheat Sheets, Top 10 pages,
      ASVS, CWE entries, SEI CERT standards, official language docs,
      project-authored fix notes.

  SECTION 4 - Code Smell Patterns
    - Definition: surface symptom indicating a deeper design problem
      (Fowler's Refactoring + Robert Martin's Clean Code).
    - Smell catalogue by group:
        Bloaters: Long Method, Large Class, Long Parameter List,
                  Primitive Obsession
        Object-orientation abusers: Switch chains, Refused Bequest
        Change preventers: Divergent Change, Shotgun Surgery
        Dispensables: Duplicate Code, Dead Code, Comments as deodorant
        Couplers: Feature Envy, Message Chains
        Other: Magic Numbers, Deep Nesting, Poor Naming,
               Empty/Broad Exception Handling
    - Measurable metrics and thresholds:
        Cyclomatic complexity      > 10 moderate, > 20 high
        Cognitive complexity       > 15
        Function length (LOC)      > 40-50
        Nesting depth              > 3
        Parameter count            > 5
        Class method count         > 20
        Duplication                > 5% or 6+ repeated lines
        Maintainability Index      < 20 poor
    - Detection: static AST rules (Python: ast/radon/pylint/flake8;
      Java: javalang/PMD/Checkstyle/SpotBugs) + LLM reasoning.
      RECOMMENDED: Hybrid - deterministic metrics fed into the LLM prompt
      to reduce hallucination and give line-accurate output.
    - Benchmark tools: Bandit, Semgrep, SonarQube, PMD/SpotBugs/Checkstyle,
      Pylint/Radon.

  SECTION 5 - RAG Architecture
    - Why RAG: avoids hallucination, removes knowledge cutoff, enables
      citations to authoritative sources (e.g. OWASP cheat sheets).
    - Phase A (Indexing, offline):
        Documents -> Load & clean -> Chunk -> Embed -> Store in vector DB
    - Phase B (Query, online):
        Question -> (rewrite) -> Embed -> Top-k similarity search ->
        (rerank/filter) -> Build prompt with context -> LLM answer
        with citations
    - Chunking: structure-aware (by heading) with recursive splitter inside
      long sections. Target 400-800 tokens, 10-15% overlap, keep code
      examples intact, prefix each chunk with its heading path.
    - Embeddings: start free/local - all-MiniLM-L6-v2 (384 dims) or
      BAAI/bge-small-en-v1.5. SAME model for indexing and querying.
    - Vector store: ChromaDB recommended (easy, persistent, metadata
      filtering). Alternatives: FAISS, Qdrant, Weaviate, pgvector.
    - Retrieval: top-k (k = 4-6); improvements = MMR, metadata filters,
      hybrid BM25+vector, cross-encoder re-ranking.
    - Generation: answer only from supplied context, cite source IDs, say
      "not found in knowledge base" if insufficient, temperature 0-0.3.
    - RAG uses in this platform:
        Remediation Agent  -> query built from the finding
        Security Agent     -> confirm category and CWE (optional)
        Chat Assistant     -> developer question + current finding context
    - Evaluation: Recall@k, MRR (retrieval); faithfulness, answer relevance,
      citation correctness (generation) - RAGAS framework automates this.
    - Multi-agent concepts: pipeline, fan-out/fan-in, shared state.
      Frameworks: LangGraph, CrewAI, AutoGen, or custom orchestrator.

  SECTION 6 - Key Design Conclusions
    1. Hybrid detection: AST/static rules for facts, LLM for reasoning.
    2. Tag every finding: OWASP category + CWE ID + severity + line numbers.
    3. Knowledge base order: OWASP Cheat Sheets first, then Top 10, ASVS,
       CERT, CWE.
    4. Structure-aware chunking + free local embedding model + ChromaDB
       with metadata filters.
    5. Remediation Agent and chat assistant must be retrieval-grounded
       with citations.
    6. OWASP version (2021 vs 2025) = configurable data, not hardcoded.

  SECTION 7 - Self-Check / Likely Viva Questions
    1. Difference between OWASP Top 10, ASVS and Cheat Sheets?
    2. Why does string-concatenated SQL cause injection and how does
       parameterisation stop it?
    3. Difference between a bug, a vulnerability and a code smell?
    4. What does cyclomatic complexity measure and typical threshold?
    5. Why combine static analysis with an LLM instead of only one?
    6. Why does chunk size affect retrieval quality?
    7. Role of the embedding model - why must indexing and query use the
       same one?
    8. How does RAG reduce hallucination?
    9. What would you do if retrieval returns irrelevant chunks?

  SECTION 8 - References
    OWASP Top 10 - owasp.org/Top10
    OWASP Cheat Sheet Series - cheatsheetseries.owasp.org
    OWASP ASVS - owasp.org/www-project-application-security-verification-standard
    CWE - cwe.mitre.org
    FIRST CVSS - first.org/cvss
    SEI CERT Coding Standards - wiki.sei.cmu.edu/confluence/display/seccode
    Refactoring Guru, Code Smells - refactoring.guru/refactoring/smells
    Fowler, M., Refactoring: Improving the Design of Existing Code
    Lewis et al. (2020), Retrieval-Augmented Generation for
      Knowledge-Intensive NLP Tasks
    ChromaDB docs - docs.trychroma.com
    sentence-transformers docs - sbert.net

--------------------------------------------------------------------------------
5. RELATED FILES IN THIS FOLDER
--------------------------------------------------------------------------------
  "Milestone 1 - Task 1 Research Report.txt"
      Full 13-page verbatim text extracted from your Task 1 PDF.
  "Milestone 1 – Task 1 Research Report (OWASP, Secure Coding,
   Code Smells, RAG).pdf"
      Original PDF.
================================================================================

================================================================================
6. MILESTONE 3 - REMEDIATION, PR SUMMARY, HEALTH SCORE, ASSISTANT, EXPORT
================================================================================

WHAT WAS ADDED (all additive: no M1/M2 route, payload key or behaviour changed)

  Backend service layer (m3/)
    config.py     environment-driven configuration (LLM optional, size limits)
    health.py     deterministic code-health score (formula below)
    kb.py         retrieval over the existing secure-kb documents (reuses
                  secure-kb/kb/chunker.py + loader.py models/metadata): hybrid
                  BM25 + cosine vectors fused by reciprocal rank, with BM25 as
                  the fallback whenever vectors are unavailable
    llm.py        optional OpenAI-compatible client (stdlib urllib, no hardcoded keys)
    store.py      per-run artifacts: remediation, PR summary, chat history
    report.py     JSON + PDF export (reportlab) built only from real run data
    service.py    facade used by both the HTTP layer and the tests

  Agents (agents/)
    remediation_agent.py   per-finding fixes with corrected code examples
    pr_summary_agent.py    PR-style review summary with status policy
    assistant_agent.py     citation-required RAG assistant

  HTTP routes (server.py, additive)
    GET  /api/m3/status
    GET  /api/analysis/<run_id>/remediation
    GET  /api/analysis/<run_id>/summary
    POST /api/analysis/chat                  { run_id, question, selected_finding_id? }
    GET  /api/analysis/<run_id>/chat/history
    GET  /api/analysis/<run_id>/report?format=json|pdf
    POST /api/analysis/report                { run_id, format }
    POST /api/analysis now also returns an additive "health" object.

  Health score (m3/health.py)
    penalty = sum(severity_weight) over de-duplicated findings
    score   = max(0, 100 - min(100, penalty))
    weights = critical 25, high 12, medium 5, low 2, info 0
    Findings are grouped by (rule family, file, line) so the built-in engine and
    Bandit reporting the same sink are charged once. The score is WITHHELD
    (score=null, available=false) for PARTIAL/FAILED runs, and 100 never means
    "secure" - only "the implemented rules reported nothing".

  Frontend (code-submission-ui/src/components/analysis/)
    HealthScoreCard.jsx    score, label, deduction breakdown, withholding notice
    PrSummaryPanel.jsx     review status, overview, breakdown, priorities, caveats
    RemediationPanel.jsx   per-finding fix + original/suggested comparison, KB refs
    AssistantPanel.jsx     cited Q&A, no-KB honesty, loading/error states
    ReportExportBar.jsx    real PDF/JSON downloads from the backend
    FindingDetails.jsx     now embeds the remediation block for the selected finding

  Tests
    tests/test_m3_health.py, test_m3_remediation.py, test_m3_pr_summary.py,
    test_m3_rag.py, test_m3_report.py, test_m3_api.py
    Run everything with:  python -m pytest tests -q

  Optional LLM configuration (never required, never hardcoded)
    OPENAI_API_KEY or LLM_API_KEY, LLM_MODEL (default gpt-4o-mini),
    LLM_BASE_URL (default https://api.openai.com/v1).
    Without a key every M3 feature still works deterministically; the assistant
    answers in retrieval_only mode and remediation uses templates.

  Explicit limitations
    - Knowledge base retrieval defaults to hybrid (BM25 + cosine vectors). The
      offline embedding provider is feature hashing, which is genuine vector
      retrieval but lexical, not neural; set EMBEDDING_PROVIDER=openai with a
      key and model for semantic embeddings. BM25 remains the fallback.
    - Remediation corrected code is illustrative and is NEVER applied to the
      submitted source.
    - PMD/Bandit availability depends on the local environment; degraded coverage
      is reported, never silently treated as a clean scan.

7. M3 QA GAP CLOSURE (vector RAG, fault tests, PDF fonts)

  Vector retrieval (m3/embeddings.py, m3/kb.py)
    - One provider interface with three backends: `hashing` (default, offline,
      no dependencies), `openai` (OpenAI-compatible /embeddings) and
      `sentence-transformers` when installed.
    - One vector per existing KB chunk; vectors persist to m3/.cache/ (gitignored)
      keyed by provider/model/dimensions/chunk ids and reload on startup.
    - Strategies: KB_RETRIEVAL_STRATEGY=auto|bm25|vector|hybrid. `auto` uses
      hybrid when the index is available and BM25 otherwise. Hybrid fuses both
      ranked lists with reciprocal rank fusion.
    - Retrieval never fails: if an embedding provider is unavailable the status
      reports `available: false` with the reason and search falls back to BM25.
      `/api/m3/status` therefore reports the backend actually serving queries.
    - Embedding env vars: EMBEDDING_PROVIDER, EMBEDDING_MODEL,
      EMBEDDING_API_KEY (falls back to LLM_API_KEY/OPENAI_API_KEY),
      EMBEDDING_BASE_URL, EMBEDDING_DIMENSIONS (hashing only), KB_RETRIEVAL_STRATEGY.
      No key is ever hardcoded.
    - Tests: tests/test_m3_vector.py covers Python/Java SQL injection, XSS,
      secrets, command injection, path traversal, an unrelated question,
      persistence, real-document citations and the unconfigured-provider fallback.

  Optional LLM (m3/llm.py)
    - Contract tests in tests/test_m3_llm_contract.py run the client against a
      local OpenAI-compatible server (auth header, request shape, parsing, HTTP
      error, malformed JSON, empty content, unreachable host) and cover mocked
      remediation enrichment and assistant answers.
    - Live-provider verification is PENDING: no LLM_API_KEY/OPENAI_API_KEY and
      LLM_MODEL are configured in this environment. To verify live, set both and
      POST /api/analysis/remediation or /api/analysis/chat with "use_llm": true.
    - An LLM can never add findings, rule ids or locations; deterministic output
      is used whenever a call fails.

  Test-only failure simulation (m3/faults.py)
    - CODE_REVIEW_TEST_FAULTS=partial|failed, read once at process start. There is
      no HTTP route or request field that can enable it, so a normal deployment
      cannot be forced into a fake failure. server.py applies it after the real
      pipeline and re-derives the terminal status with the orchestrator's rules.
    - Unset the variable (or restart normally) to return to production behavior.

  PDF fonts (m3/report.py)
    - A system TrueType font is registered when available (DejaVu, Segoe UI,
      Arial, Liberation) with a monospace companion, enabling Unicode headings,
      descriptions and code. Nothing is bundled and no dependency was added; when
      no TTF is found the report falls back to the previous Helvetica output.
    - The generated PDF states which font was used, and characters that font
      cannot draw (CJK, emoji) are rendered as '?' instead of silently
      disappearing.

--------------------------------------------------------------------------------
8. SETUP, CONFIGURATION AND TESTING
--------------------------------------------------------------------------------

  Prerequisites
    Python 3.11+ (developed on 3.13), Node 18+ (developed on 24), npm.
    PMD is downloaded on demand into tools/pmd/ (gitignored); no JDK is
    required for the Python rules. Bandit, radon and javalang come from
    requirements.txt.

  8.1 Backend install and start
    python -m venv .venv
    .venv\Scripts\activate          (Windows)   source .venv/bin/activate (POSIX)
    python -m pip install -r requirements.txt
    python server.py                 ->  http://127.0.0.1:8000
    The server prints its routes on startup and answers GET /api/m3/status.

  8.2 Frontend install and start
    cd code-submission-ui
    npm install
    npm run dev                      ->  http://localhost:5173 (5174 if busy)
    The UI calls the backend at API_BASE in src/utils/analysisApi.js
    (http://localhost:8000). Change that constant if the backend moves port.
    npm run build                    ->  production bundle in dist/
    run_full_system.bat              ->  starts both on Windows

  8.3 Environment variables (all optional; see .env.example)
    LLM_API_KEY / OPENAI_API_KEY     optional. Enables LLM remediation prose
                                     and LLM assistant answers.
    LLM_MODEL                        required together with the key; a key
                                     without a model keeps the LLM disabled.
    LLM_BASE_URL                     default https://api.openai.com/v1
    LLM_TIMEOUT_SECONDS              default 45
    EMBEDDING_PROVIDER               auto | hashing | openai |
                                     sentence-transformers (default auto)
    EMBEDDING_MODEL                  embedding model id (openai provider)
    EMBEDDING_API_KEY                falls back to LLM_API_KEY/OPENAI_API_KEY
    EMBEDDING_BASE_URL               embeddings endpoint base URL
    EMBEDDING_DIMENSIONS             hashing provider width (default 512)
    EMBEDDING_TIMEOUT_SECONDS        default 30
    EMBEDDING_SENTENCE_MODEL         default all-MiniLM-L6-v2
    KB_RETRIEVAL_STRATEGY            auto | bm25 | vector | hybrid
    PMD_DISABLE_DOWNLOAD             1 keeps PMD offline (reported as
                                     unavailable, never as a clean scan)
    PMD_VERSION / PMD_TIMEOUT        PMD pin and run timeout
    CODE_REVIEW_TEST_FAULTS          partial | failed. TEST ONLY - forces a
                                     simulated agent failure. Never set it in a
                                     real deployment.
    No key is read from source and no secret is required to run the platform.

  8.4 Optional LLM setup
    1. Copy .env.example to .env and set LLM_API_KEY and LLM_MODEL.
    2. Restart the backend (settings are read at start).
    3. GET /api/m3/status -> m3.capabilities.llm.configured must be true.
    4. Live behaviour to check: POST /api/analysis/remediation and
       POST /api/analysis/chat with "use_llm": true. Deterministic output is
       used automatically whenever the provider errors or times out.

  8.5 Optional semantic embedding setup
    1. Set EMBEDDING_PROVIDER=openai, EMBEDDING_MODEL=<model>, and an
       embedding key (EMBEDDING_API_KEY or LLM_API_KEY/OPENAI_API_KEY).
    2. Restart. The first query rebuilds the vector index into m3/.cache/.
    3. GET /api/m3/status -> knowledge_base.backend, .strategy, .vector
       (provider, dimensions, semantic) describe what is actually serving
       queries. If the provider is unavailable the field says so and search
       falls back to BM25 - retrieval never fails.
    The default hashing provider needs no key but is lexical: keep that in
    mind when quoting retrieval quality.

  8.6 Tests and checks
    python -m pytest tests -q        backend suite (see section 10 for counts)
    cd code-submission-ui
    npm run lint                     oxlint (0 errors)
    npm run build                    production build

--------------------------------------------------------------------------------
9. ARCHITECTURE, STACK AND WORKFLOWS
--------------------------------------------------------------------------------

  9.1 Request flow

    ```mermaid
    flowchart LR
      A[Developer: paste or upload Python/Java] --> B[M1 validation + language gate]
      B -->|rejected| R[Rejection reason, no analysis]
      B -->|accepted| C[M2 orchestrator: fan-out]
      C --> D[Code Analysis Agent]
      C --> E[Security Vulnerability Agent]
      D --> F[Merge + severity + de-duplication]
      E --> F
      F --> G[Code health score]
      F --> H[M3 Remediation Agent]
      F --> I[M3 PR Summary Agent]
      F --> J[M3 RAG Assistant]
      K[(secure-kb: 13 docs / 62 chunks)] --> J
      K --> H
      G --> L[UI panels + JSON/PDF export]
      H --> L
      I --> L
      J --> L
    ```

  9.2 Technology stack
    Frontend   React 19, Vite 8, Tailwind CSS 3, lucide-react icons, oxlint.
               No state library: the workspace holds run state and derives the
               M3 view from the current run id.
    Backend    Python 3 standard library HTTP server (server.py), a custom
               orchestrator, Bandit/radon for Python, PMD for Java, javalang for
               Java parsing.
    M3 layer   m3/ package: config, health, kb + embeddings, llm, faults,
               store, report (reportlab), service facade.
    Knowledge   secure-kb/ documents, chunker and loader reused as-is; vectors
               cached under m3/.cache/ (gitignored).

  9.3 Agent responsibilities
    M1  validation agent      syntax + language gate (Python/Java only),
                              rejection reasons, no analysis on invalid input
    M2  code analysis agent   smells, complexity, naming/dead code, quality
        security agent        OWASP/CWE rules, Bandit, PMD
    M3  remediation agent     per-finding fix + illustrative corrected code
        pr summary agent      review status, overview, severity mix, priorities
        assistant agent       retrieval-grounded Q&A with mandatory citations

  9.4 Analysis workflow
    Validation runs on every keystroke (debounced) and is cancelled when new
    input arrives. A run id is created per accepted submission; the UI ignores
    responses whose run id no longer matches, so results cannot be shown for
    stale input. Agent failures produce PARTIAL/FAILED runs: findings are kept,
    the health score is withheld, and the PR summary says the review is
    incomplete.

  9.5 Remediation workflow
    One deterministic template per rule family supplies the fix, the reason
    (CWE), a best practice and a corrected snippet. Optional LLM prose may
    rewrite the explanation only: rule ids, locations and finding identity stay
    authoritative, and corrected code is illustrative - it is never applied to
    the submitted source.

  9.6 PR summary workflow
    Status is derived from severity and run status (Approved / Changes
    Requested / Incomplete Review), followed by overview, severity breakdown,
    prioritized actions and caveats naming any failed agent.

  9.7 Assistant and retrieval
    A question is embedded (or BM25-scored), the top chunks are retrieved with
    their real source file/section, and the answer cites them. Without a KB
    match the assistant says so; without an LLM it answers in retrieval_only
    mode from the retrieved passages instead of inventing content.

  9.8 Code health score
    penalty = sum(severity_weight) over findings de-duplicated by
    (rule family, file, line); score = max(0, 100 - min(100, penalty));
    weights critical 25, high 12, medium 5, low 2, info 0. It is withheld for
    PARTIAL/FAILED runs and 100 never means "secure".

  9.9 Known limitations (see also section 6)
    - Default retrieval vectors are lexical hashing, not neural semantics.
    - Optional LLM and semantic embedding providers are implemented and
      contract-tested, but not live-verified here (no credentials).
    - Static analysis only: submitted code is never executed.
    - PDF output needs a system TrueType font for full Unicode; characters
      missing from that font are shown as '?'.
    - No frontend unit-test framework: the UI is verified by build, lint and
      real browser runs.
    - PMD coverage depends on the local environment and is reported honestly
      when unavailable.

10. MILESTONE 4 - VALIDATED REPORT MODULE, END-TO-END SAMPLES, OPTIMISATION

  10.1 What M4 added
    No module was rebuilt. M4 added validation, measurable optimisation and
    documentation on top of M1/M2/M3:
    - three curated samples with a written oracle (tests/fixtures/m4/);
    - a report-consistency suite, a severity-consistency suite, a retrieval
      evaluation set and prompt regression tests;
    - retrieval diversity so one document cannot fill every citation slot;
    - one canonical health score in the JSON export (raw M2 value preserved as
      m2_health_score), remediation filtered to findings the report contains,
      and a note under the severity table explaining reported vs unique counts;
    - hardened optional LLM prompts (assistant and remediation) exposed as
      module constants and asserted, together with the exact request messages;
    - the selected-finding assistant crash (`'Finding' object has no attribute
      'get'`) fixed in `agents/assistant_agent.py` and covered by
      tests/test_m4_selected_finding_assistant.py.

  10.2 Measured results (this machine)
    - pytest tests -q -> 275 passed (197 pre-existing + 72 M4 + 6 P1 regression).
    - npm run lint -> 0 errors, 22 documented warnings; npm run build -> ok.
    - Samples: 4 / 3 / 11 findings, health 70 / 45 / 29, review status
      Changes Requested for all three; 12/12 expected detections present,
      0 false positives, 9/9 clean controls unflagged.
    - Retrieval: 12/12 top-1 and 12/12 top-3 on the M4 question set;
      0/12 queries now return a single document for all three citations.
    - Reports: PDF 3 / 3 / 6 pages with page numbering and run metadata;
      JSON contains the same findings, health and remediation.

  10.3 M4 documents
    docs/milestone-4/M4_Gap_Analysis.md
    docs/milestone-4/M4_Test_Report.md
    docs/milestone-4/M4_Optimization_Report.md
    docs/milestone-4/M4_Technical_Documentation.md
    docs/milestone-4/M4_Final_Demonstration_Guide.md
    docs/milestone-4/M4_Known_Limitations.md
    docs/milestone-4/M4_Project_Report.md

  10.4 Running only the M4 checks
    python -m pytest tests/test_m4_samples.py tests/test_m4_report_validation.py \
      tests/test_m4_severity_consistency.py tests/test_m4_rag_eval.py \
      tests/test_m4_prompts.py -q
