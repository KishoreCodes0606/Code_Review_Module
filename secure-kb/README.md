# Secure Coding Knowledge Base (Milestone 1, Task 4)

Indexes OWASP guidelines, secure coding standards and project-authored best-practice notes into a
**RAG pipeline**: load -> clean -> chunk -> embed -> index in a ChromaDB vector store. The same
`Retriever` class is what the Remediation Agent and the Conversational Code Assistant call in later milestones.

```
sources.yaml ----> kb.download ----> knowledge_base/raw/*.md   (45 OWASP docs)
knowledge_base/custom/*.md (12 project notes, YAML front matter)
        |
        v
  kb.loader  (strip images/comments, read metadata)
        v
  kb.chunker (heading-aware, code-safe, overlap, tiny-chunk merge, stable ids)
        v
  kb.embedder (all-MiniLM-L6-v2, 384-dim, normalised)
        v
  kb.store   (ChromaDB, cosine, persistent, model-mismatch guard)
        v
  kb.retriever (metadata filters + similarity threshold + MMR) --> format_context() --> LLM prompt with [1] [2] citations
```

## 1. Setup

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The first ingest downloads the embedding model (about 90 MB) from Hugging Face, so internet is needed once.

## 2. Build the knowledge base

```bash
python -m kb.download              # fetch the OWASP sources listed in sources.yaml
python -m kb.ingest --dry-run      # optional: chunk statistics only, nothing is embedded
python -m kb.ingest --rebuild      # chunk, embed, index (first run)
python -m kb.ingest                # later runs: only changed documents are re-indexed
```

## 3. Test it

```bash
python -m pytest -q                                   # unit + end-to-end tests (offline, 20 tests)
python -m kb.search "how do I stop SQL injection?" --language python
python -m kb.smoke_test                               # 16 queries, writes docs/retrieval_report.md
```

Attach `docs/retrieval_report.md` and the `data/kb_stats.json` file to your milestone submission as evidence.

## 4. What is in the knowledge base

| Source | Docs | Licence | Role |
|---|---|---|---|
| OWASP Cheat Sheet Series | 35 | CC BY-SA 4.0 | Main how-to-fix content (best RAG material) |
| OWASP Top 10 (2021) pages | 10 | CC BY-SA 4.0 (verify on owasp.org) | Category definitions and prevention |
| Project notes (`knowledge_base/custom/`) | 12 | Project-authored | Vulnerable-vs-fixed code for Python and Java, code smell catalogue, CWE/severity table |

Every chunk carries metadata: `doc_id, source_doc, source_url, doc_type, owasp_category, cwe_ids, language,
section_path, has_code, chunk_index, token_estimate, license`. This matches section 7.3 of the design document.

## 5. Design decisions (and why)

| Decision | Choice | Reason |
|---|---|---|
| Chunking | Split by headings, then pack paragraphs up to 600 tokens, 80-token overlap, minimum 80 tokens | Keeps one idea per chunk; overlap rescues ideas that straddle a boundary |
| Code blocks | Never split unless larger than the limit (then split by line with fences re-closed) | A half code example is useless for remediation |
| Heading prefix | Each chunk starts with `Title > H2 > H3` | Gives the embedding the topic even when the paragraph is generic |
| Embeddings | `all-MiniLM-L6-v2` (change with `KB_EMBEDDING_MODEL`; `bge-small-en-v1.5` is handled, including its query prefix) | Free, local, fast, 384 dims |
| Vector store | ChromaDB persistent, cosine | Easy, metadata filters, no server |
| Idempotent indexing | Chunk id = `doc#index-sha1(text)`; changed documents are deleted then re-inserted; removed documents are purged | Re-running never duplicates or leaves stale chunks |
| Model guard | Collection remembers its embedding model and refuses another | Mixing models silently ruins retrieval |
| Retrieval | `language IN (lang, general)` filter, similarity threshold, MMR over the top 20 | Python questions get Python notes plus general guidance; MMR removes near-duplicate chunks |
| Citations | `format_context()` numbers each block `[1]`, `[2]` with title and URL | The assistant can cite sources, and says "not found" if nothing passes the threshold |

## 6. Using the retriever from the agents (next milestones)

```python
from kb.retriever import Retriever, format_context

retriever = Retriever()
hits = retriever.retrieve(
    "parameterized queries cursor.execute CWE-89",
    k=5, language="python", owasp_category=None)
context = format_context(hits)        # paste into the Remediation Agent / chat prompt
```

Suggested prompt rule: *"Answer only from the numbered context. Cite sources like [1]. If the context does not
contain the answer, say it was not found in the knowledge base."*

## 7. Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `KB_EMBEDDING_BACKEND` | `sentence-transformers` | `hash` = offline test embedder (tests/CI only) |
| `KB_EMBEDDING_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Any sentence-transformers model |
| `KB_CHUNK_MAX` / `KB_CHUNK_MIN` / `KB_CHUNK_OVERLAP` | 600 / 80 / 80 | Chunk sizes (approximate tokens) |
| `KB_TOP_K` / `KB_FETCH_K` / `KB_MIN_SCORE` / `KB_MMR_LAMBDA` | 5 / 20 / 0.20 / 0.7 | Retrieval behaviour |
| `KB_CHROMA_DIR`, `KB_COLLECTION` | `data/chroma`, `secure_coding_kb` | Storage location and name |

Changing the model or chunk settings changes every document fingerprint, so the next `python -m kb.ingest`
re-indexes everything. Use `--rebuild` after changing the model.

## 8. Adding your own document

Create `knowledge_base/custom/my-note.md`:

```markdown
---
id: custom-my-note
title: "My note title"
doc_type: custom
owasp: A03
cwe: [CWE-89]
language: python          # python | java | general
---
# My note title
...content...
```

Then run `python -m kb.ingest`. To add another OWASP page, add a line to `sources.yaml`, run `python -m kb.download`, then ingest.

## 9. Tuning if retrieval is weak

1. Open `docs/retrieval_report.md` and look at the MISS rows and which chunk was returned instead.
2. Add a short project note for that topic (notes are the fastest fix).
3. Adjust `KB_CHUNK_MAX` (smaller chunks = more precise, less context).
4. Try `KB_EMBEDDING_MODEL=BAAI/bge-small-en-v1.5` and rebuild.
5. Tune `KB_MIN_SCORE` against real scores printed by `python -m kb.smoke_test`.
6. Later improvements: hybrid BM25 + vector search, cross-encoder re-ranking.

## 10. Project layout

```
kb/            config, models, sources, download, loader, chunker, embedder, store, retriever, ingest, search, smoke_test
knowledge_base/custom/   project-authored notes (committed)
knowledge_base/raw/      downloaded OWASP files (git-ignored, re-created by kb.download)
eval/queries.yaml        retrieval test set (edit and extend it)
tests/                   chunker, loader and end-to-end pipeline tests
data/                    Chroma database, manifest, stats (git-ignored)
```

## 11. Attribution

OWASP Cheat Sheet Series and OWASP Top 10 content is published by the OWASP Foundation under Creative Commons
Attribution-ShareAlike licences. This project stores each chunk's source URL and licence so answers can credit the original.
