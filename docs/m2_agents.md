# M2 — Code Analysis & Security Vulnerability Agents

Two static-analysis agents orchestrate in parallel, merging findings into one
schema. Everything is deterministic static analysis: **submitted source code is
never executed** (no eval/exec/import/compile of submissions anywhere in the
pipeline; Bandit and PMD analyze source text themselves).

## Endpoints (additive; M1 routes untouched)

| Method | Path | Notes |
|---|---|---|
| POST | `/api/analysis` | `{code, language, filename?}` → run summary. Syntax-invalid or non-Python/Java submissions → `422` with `{"error": "syntax_error"}` / `{"error": "unsupported_language"}`; over 200 KB or 2000 lines → `413`; invalid JSON / method mismatches behave exactly like M1. |
| GET | `/api/analysis/<run_id>` | Re-fetch the summary of a stored run. |
| GET | `/api/analysis/<run_id>/findings` | Findings list; deduplicated, sorted security-first then severity. Optional `?category=security\|quality`, `?severity=critical`. Unknown id → `404`. |

Run state is in-memory per server process (single-machine dev tool); a restart
clears History — documented limitation.

## Agents

**Code Analysis Agent** (`agents/code_analysis_agent.py`)
- Python: `ast` + `radon` metrics → long method, large class, long parameter
  list, high cyclomatic complexity, deep nesting, broad exception, magic
  numbers, unused imports/variables, low maintainability index.
- Java: custom javalang-based detectors for the same smell families; **PMD**
  (ruleset `analysis/pmd_ruleset.xml`) is used if the CLI is installed — it is
  download-on-demand into `tools/pmd/` (git-ignored) and invoked as a
  subprocess (`PMD_DISABLE_DOWNLOAD=1` skips it). If PMD is unavailable its
  status is recorded honestly as `pmd_status: unavailable/skipped` and the
  custom detectors carry the analysis — never silently absent.

**Security Vulnerability Agent** (`agents/security_agent.py`)
- Python: custom `ast`/regex rules + **Bandit** (run as `python -m bandit`,
  JSON report) when importable. Bandit is optional; if missing the custom
  rules still cover the core sinks, and the summary notes it.
- Java: custom token/regex rules (javalang parse failure degrades to line
  scanning instead of disabling detection).

## Implemented detector coverage (complete, honest list)

| Category | Python rules | Java rules | OWASP / CWE |
|---|---|---|---|
| SQL injection (concat/f-string/format into execute) | `S-PY-SQLI` (+ Bandit B608) | `S-JAVA-SQLI` | A03 / CWE-89 |
| Command injection (os.system/popen, subprocess w/ string) | `S-PY-CMDI`, `S-PY-SHELL` (+ Bandit B602/B605) | `S-JAVA-CMDI` | A03 / CWE-78 |
| eval/exec/compile of dynamic strings | `S-PY-EVAL` (+ Bandit B102/B307) | n/a (no equivalent) | A03 / CWE-95 |
| Insecure deserialization (pickle, unsafe yaml) | `S-PY-DESER` (+ Bandit B301/B506) | `S-JAVA-DESER` (ObjectInputStream) | A08 / CWE-502 |
| Weak crypto/hashing (MD5/SHA-1, DES, ECB) | `S-PY-CRYPTO`; Bandit crypto ids where applicable | `S-JAVA-CRYPTO` | A02 / CWE-327 |
| Hardcoded secrets | `S-PY-SECRET` (heuristic_warning) + Bandit B105–B107 | `S-JAVA-SECRET` (heuristic_warning) | A02/A07 / CWE-798 |
| Path traversal (open/os.* with a concatenated path var) | `S-PY-PATH` (heuristic_warning) | `S-JAVA-PATH` (heuristic_warning) | A01 / CWE-22 |
| XML External Entity (parser factory w/o hardening) | n/a | `S-JAVA-XXE` | A05 / CWE-611 |
| XSS output sink (`println`/`write` of user data) | n/a (documented: no directly reachable sink for pasted Python snippets) | `S-JAVA-XSS` (heuristic_warning) | A03 / CWE-79 |

Bandit rule ids are surfaced as `bandit-<testid>` findings mapped into the
same schema. PMD quality findings (when PMD is present) likewise map onto the
shared schema.

**Not implemented (explicit out of scope for M2):** SSRF, CSRF, access
control/IDOR, open redirects, XXE on Python (defusedxml-based) rules,
dependency/CVE scanning (pip-audit/OWASP Dependency-Check), templating or ORM
deep type inference, and any dynamic/runtime detection. Scanner findings are
*pattern evidence*; the LLM confirmation step exists in the design but is
deliberately not wired into M2 (no API-key dependency). No claim of complete
OWASP Top 10 coverage is made.

## Orchestration

`orchestrator/pipeline.py` fans each agent out to a thread, waits with a
60 s per-agent timeout, and **is explicit about partial failure**: if an agent
crashes or times out, its `agent_results` entry records `failed`/`timeout`
with the error and the run is marked `PARTIAL` — a scanner failure is never
reported as a clean result. Findings merge with dedup on
`(rule_id, file_path, line_start)` and sort security-first by severity.
Health score: `100 − min(100, Σ band weights)` (critical 25 / high 12 /
medium 5 / low 2).

## Testing

`tests/` holds unit tests for rule detection, line locations, clean-fixture
false positives, Bandit adapter, API round-trips, and **M1 regression tests**
asserting the untouched `/api/health`, `/api/submissions`,
`/api/submissions/validate` behavior. `docs/accuracy_report.md` records
precision/recall/F1 computed from actual golden-fixture runs on this
environment (4 samples; not a general-accuracy claim). Run:

```bash
python -m pytest tests/test_security_rules.py tests/test_python_quality.py tests/test_java_quality.py -q
python -m pytest tests/ -q                    # full suite incl. M1 regression
python tools/generate_accuracy_report.py      # regenerate the accuracy report
```
