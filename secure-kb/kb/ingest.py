"""Build / refresh the secure-coding knowledge base.

    python -m kb.download          # 1. fetch OWASP sources (once)
    python -m kb.ingest            # 2. chunk -> embed -> index  (incremental)
    python -m kb.ingest --rebuild  #    wipe and rebuild from scratch
    python -m kb.ingest --dry-run  #    show chunk statistics only, no embedding
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from collections import Counter

from .chunker import chunk_document
from .config import Settings, get_settings
from .embedder import get_embedder
from .loader import load_custom, load_downloaded
from .models import Chunk, Document
from .sources import load_sources
from .store import VectorStore


def collect_documents(cfg: Settings) -> list[Document]:
    docs: list[Document] = []
    missing: list[str] = []
    for spec in load_sources(cfg.sources_file):
        doc = load_downloaded(spec, cfg.raw_dir)
        if doc is None:
            missing.append(spec.doc_id)
        else:
            docs.append(doc)
    if missing:
        print(f"! {len(missing)} source files not downloaded yet (run `python -m kb.download`): "
              f"{', '.join(missing[:5])}{' ...' if len(missing) > 5 else ''}")
    docs.extend(load_custom(cfg.custom_dir))
    ids = [d.doc_id for d in docs]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Duplicate document ids across sources/custom: {sorted(dupes)}")
    return docs


def doc_fingerprint(doc: Document, cfg: Settings, embedder_name: str) -> str:
    payload = json.dumps(
        {
            "text": doc.text,
            "meta": doc.metadata,
            "chunk": [cfg.chunk_max_tokens, cfg.chunk_min_tokens, cfg.chunk_overlap_tokens],
            "embedder": embedder_name,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def summarise(chunks: list[Chunk]) -> dict:
    toks = [c.tokens for c in chunks] or [0]
    return {
        "chunks": len(chunks),
        "tokens_avg": round(statistics.mean(toks)),
        "tokens_min": min(toks),
        "tokens_max": max(toks),
        "with_code": sum(c.has_code for c in chunks),
        "by_doc_type": dict(Counter(c.metadata["doc_type"] for c in chunks)),
        "by_language": dict(Counter(c.metadata["language"] for c in chunks)),
        "by_owasp": dict(sorted(Counter(c.metadata["owasp_category"] for c in chunks).items())),
    }


def run(rebuild: bool = False, dry_run: bool = False, cfg: Settings | None = None) -> dict:
    cfg = cfg or get_settings()
    t0 = time.time()
    docs = collect_documents(cfg)
    print(f"Loaded {len(docs)} documents "
          f"({sum(d.metadata['origin'] == 'download' for d in docs)} OWASP downloads, "
          f"{sum(d.metadata['origin'] == 'custom' for d in docs)} project notes)")

    if dry_run:
        all_chunks = [c for d in docs for c in chunk_document(
            d, cfg.chunk_max_tokens, cfg.chunk_min_tokens, cfg.chunk_overlap_tokens)]
        stats = summarise(all_chunks)
        print(json.dumps(stats, indent=2))
        return stats

    embedder = get_embedder(cfg.embedding_backend, cfg.embedding_model, cfg.hash_dim, cfg.embed_batch_size)
    store = VectorStore(cfg.chroma_dir, cfg.collection, embedder.name)
    manifest: dict[str, str] = {}
    if cfg.manifest_file.exists() and not rebuild:
        manifest = json.loads(cfg.manifest_file.read_text(encoding="utf-8"))
    if rebuild:
        store.reset()

    # remove documents that disappeared from the sources
    current_ids = {d.doc_id for d in docs}
    for stale in set(manifest) - current_ids:
        store.delete_doc(stale)
        manifest.pop(stale, None)
        print(f"  removed stale document {stale}")

    new_chunks: list[Chunk] = []
    skipped = updated = 0
    for doc in docs:
        fp = doc_fingerprint(doc, cfg, embedder.name)
        if manifest.get(doc.doc_id) == fp:
            skipped += 1
            continue
        store.delete_doc(doc.doc_id)  # drop old chunks of a changed document
        chunks = chunk_document(doc, cfg.chunk_max_tokens, cfg.chunk_min_tokens, cfg.chunk_overlap_tokens)
        new_chunks.extend(chunks)
        manifest[doc.doc_id] = fp
        updated += 1

    if new_chunks:
        print(f"Embedding {len(new_chunks)} chunks with '{embedder.name}' ...")
        vectors = embedder.embed_documents([c.text for c in new_chunks])
        store.upsert(new_chunks, vectors)

    cfg.manifest_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    stats = summarise(new_chunks) if new_chunks else {}
    stats.update(
        documents_total=len(docs),
        documents_updated=updated,
        documents_skipped=skipped,
        collection_size=store.count(),
        embedding_model=embedder.name,
        embedding_dim=embedder.dim,
        seconds=round(time.time() - t0, 1),
    )
    (cfg.manifest_file.parent / "kb_stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rebuild", action="store_true", help="wipe the collection and re-index everything")
    ap.add_argument("--dry-run", action="store_true", help="chunk only; print statistics; no embedding/indexing")
    args = ap.parse_args(argv)
    run(rebuild=args.rebuild, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
