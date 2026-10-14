"""Retrieval smoke test + quality report.

    python -m kb.smoke_test                 # run eval/queries.yaml, print top-3 per query
    python -m kb.smoke_test --min-hit5 0.8  # exit code 1 if Hit@5 is below the threshold

Writes docs/retrieval_report.md (attach it to the milestone submission).
"""
from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

import yaml

from .config import ROOT
from .retriever import Retriever


def evaluate(queries: list[dict], retriever: Retriever, k: int, mmr: bool = False) -> dict:
    rows = []
    for item in queries:
        hits = retriever.retrieve(item["q"], k=k, language=item.get("language"), min_score=0.0, mmr=mmr)
        doc_ids = [h.metadata.get("doc_id", "") for h in hits]
        rank = next((i + 1 for i, d in enumerate(doc_ids) if d in set(item["expect"])), None)
        rows.append({"item": item, "hits": hits, "rank": rank})
    n = len(rows)
    return {
        "rows": rows,
        "n": n,
        "hit1": sum(1 for r in rows if r["rank"] == 1) / n,
        "hit3": sum(1 for r in rows if r["rank"] and r["rank"] <= 3) / n,
        "hit5": sum(1 for r in rows if r["rank"] and r["rank"] <= 5) / n,
        "mrr": sum(1 / r["rank"] for r in rows if r["rank"]) / n,
    }


def write_report(result: dict, path: Path, model: str, collection_size: int) -> None:
    lines = [
        "# Retrieval Smoke Test Report",
        "",
        f"- Date: {date.today().isoformat()}",
        f"- Embedding model: `{model}`",
        f"- Chunks in collection: {collection_size}",
        f"- Queries: {result['n']}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Hit@1 | {result['hit1']:.0%} |",
        f"| Hit@3 | {result['hit3']:.0%} |",
        f"| Hit@5 | {result['hit5']:.0%} |",
        f"| MRR | {result['mrr']:.2f} |",
        "",
        "## Per-query results",
        "",
        "| # | Query | First correct rank | Top-3 sources (score) |",
        "|---|---|---|---|",
    ]
    for i, r in enumerate(result["rows"], 1):
        top3 = "<br>".join(f"{h.metadata.get('doc_id')} ({h.score:.2f})" for h in r["hits"][:3])
        rank = r["rank"] if r["rank"] else "MISS"
        lines.append(f"| {i} | {r['item']['q']} | {rank} | {top3} |")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--queries", default=str(ROOT / "eval" / "queries.yaml"))
    ap.add_argument("-k", type=int, default=5)
    ap.add_argument("--min-hit5", type=float, default=0.8)
    ap.add_argument("--mmr", action="store_true", help="evaluate with MMR re-ordering (default: pure similarity)")
    ap.add_argument("--report", default=str(ROOT / "docs" / "retrieval_report.md"))
    args = ap.parse_args(argv)

    queries = yaml.safe_load(Path(args.queries).read_text(encoding="utf-8"))
    retriever = Retriever()
    size = retriever.store.count()
    if size == 0:
        print("Collection is empty. Run `python -m kb.ingest` first.")
        return 2

    result = evaluate(queries, retriever, args.k, mmr=args.mmr)
    for i, r in enumerate(result["rows"], 1):
        status = f"rank {r['rank']}" if r["rank"] else "MISS"
        print(f"\n{i:>2}. {r['item']['q']}\n    -> {status}")
        for h in r["hits"][:3]:
            print(f"       [{h.score:.3f}] {h.metadata.get('section_path', '')[:90]}")

    print(f"\nHit@1 {result['hit1']:.0%} | Hit@3 {result['hit3']:.0%} | "
          f"Hit@5 {result['hit5']:.0%} | MRR {result['mrr']:.2f}  ({result['n']} queries)")
    write_report(result, Path(args.report), retriever.embedder.name, size)
    print(f"Report written to {args.report}")
    return 0 if result["hit5"] >= args.min_hit5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
