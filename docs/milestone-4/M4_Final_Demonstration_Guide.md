# M4 Final Demonstration Guide

A repeatable script for the final presentation. Three samples of increasing
complexity, each exercised through the real UI, with the expected output stated
up front so the demo can be judged, not just watched.

## Preparation (5 minutes before)

```bash
# terminal 1 — backend
.venv/Scripts/python.exe server.py          # http://localhost:8000

# terminal 2 — frontend
cd code-submission-ui && npm run dev        # http://localhost:5174
```

Open `http://localhost:5174`, confirm the header shows **Analysis Ready** and
that `http://localhost:8000/api/m3/status` returns `backend: hybrid`,
`semantic: false`, `llm.configured: false` (state this honestly if asked about
AI providers).

Sample sources to paste (or open in an editor window):

| # | File | Language | Complexity |
|---|---|---|---|
| 1 | `tests/fixtures/m4/sample1_basic_inventory.py` | Python | Low |
| 2 | `tests/fixtures/m4/sample2_medium_accounts.java` | Java | Medium |
| 3 | `tests/fixtures/m4/sample3_complex_backend.py` | Python | High |

## Sample 1 — basic Python (≈30 seconds of analysis)

1. Paste `sample1_basic_inventory.py` into the editor (or use *Upload File*).
2. Point out: **Language Status: Python (.py) · Accepted**, then
   **AUTOMATIC SYNTAX VALIDATION → ACCEPTED** with no button pressed.
3. Wait for the analysis summary.
4. Expected result:
   * **2 findings** (4 rows, because Bandit reports the same two issues):
     `S-PY-SQLI` critical at the query line, `S-PY-CRYPTO` medium at the MD5 line.
   * **Health 70/100** with "2 unique finding(s) deduct 30 point(s) after grouping
     2 duplicate report(s)" — note the numbering difference between the findings
     table (4 rows) and the health table (2 scored findings), and read the
     one-line explanation under the severity table.
   * **Review status: Changes Requested**.
5. Talking point: the two clean helpers (`format_price`, `total_quantity`) are
   not flagged — the tool is not simply pattern-matching keywords.

## Sample 2 — intermediate Java

1. Paste `sample2_medium_accounts.java`; language auto-detects as Java.
2. Expected result:
   * `S-JAVA-SQLI` critical (Statement concatenation),
     `S-JAVA-DESER` critical (`ObjectInputStream.readObject`),
     `S-JAVA-CRYPTO` medium (`AES/ECB`).
   * **Health 45/100**, review status **Changes Requested**.
   * The `AuditLog` class produces no finding (clean component).
3. Show the **Remediation** panel: `PreparedStatement` example for the SQL
   finding, `ProcessBuilder`/data-format guidance where applicable, and the
   note that nothing is auto-applied.

## Sample 3 — complex Python backend

1. Paste `sample3_complex_backend.py`.
2. Expected result: **11 findings**, **health 29/100**, **Changes Requested**:
   * security: hardcoded token (Bandit B105), f-string SQL (`S-PY-SQLI`),
     MD5 password digest (`S-PY-CRYPTO`), unconfined path (`S-PY-PATH`),
     `shell=True` (`S-PY-SHELL`), plus Bandit cross-reports;
   * quality: bare `except` (`Q-broad-exception`), 4-level nesting
     (`Q-deep-nesting`).
3. Demonstrate in order:
   * **Filters** — severity `critical`, category `Security`, then free-text
     search for `sql`; clear them.
   * **View Details** on the SQL injection finding — snippet, severity score,
     CWE-89 / OWASP A03, remediation guidance.
   * **Health card** — deduction breakdown and the "Grouped duplicates" disclosure.
   * **PR summary** — executive overview, severity mix, prioritized fixes in
     severity order, final recommendation, caveats.
   * **Code assistant** — ask *"How do I prevent SQL injection in Python?"*;
     the answer cites `[1]`–`[3]` and lists the real sources underneath. Then ask
     *"What is the capital of France?"* to show the explicit refusal with no
     citations.
   * **Export** — click **JSON** (a `code-review-<run>.json` file downloads) and
     then **PDF**; open the PDF and show the title block, review status, health
     table, severity table, findings with remediation, caveats, and the footer
     with page numbers.

## PARTIAL / FAILED honesty (optional but persuasive)

```bash
# stop the backend, then:
CODE_REVIEW_TEST_FAULTS=partial .venv/Scripts/python.exe server.py
```

Re-run a sample: the health card shows **withheld**, "The analysis run is
PARTIAL…", and the PR summary shows **Incomplete Review**. Repeat with
`CODE_REVIEW_TEST_FAULTS=failed` to show **Analysis failed** with no score and no
findings. Restart normally afterwards (the flag is process-start only).

## Screens / artifacts to show

| Screen | What it proves |
|---|---|
| Editor + validation banner | automatic M1 validation, accepted/rejected states |
| Analysis summary | both agents, duration, counts |
| Health card | transparent formula, duplicate grouping, withheld on PARTIAL |
| Findings table + details | rule ids, severity, locations, CWE/OWASP |
| Remediation panel | per-finding fix, illustrative code, limitations |
| PR summary | review decision and priorities a reviewer would act on |
| Assistant | grounded answer with citations, honest refusal |
| Export buttons | JSON/PDF generated from the same run |
| `docs/qa/ui-mobile-390.png` | narrow layout, no horizontal overflow |

## Talking points

* Deterministic analysis decides what is found; the optional LLM only rewords
  remediation/answers and cannot add, remove or relocate a finding.
* Health is severity-weighted and de-duplicated, and is withheld when the scan is
  incomplete — the tool never converts "not analysed" into "clean".
* Retrieval is measured (12/12 top-1 on the project's evaluation set) and the
  assistant refuses instead of inventing a source.
* Everything runs offline; no key is required for any demonstrated feature.

## If something goes wrong

* Backend not answering → check terminal 1 and `http://localhost:8000/api/m3/status`.
* Analysis never appears → confirm the code is Python/Java and non-empty; rejected
  input is intentional for unsupported languages.
* PDF not opening → the file is downloaded, not opened inline; check the browser
  download bar.
