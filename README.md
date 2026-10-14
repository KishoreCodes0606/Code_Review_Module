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
