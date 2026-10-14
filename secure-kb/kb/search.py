"""Tiny CLI to try the retriever by hand.

    python -m kb.search "how do I stop SQL injection in Python?" --language python
"""
from __future__ import annotations

import argparse

from .retriever import Retriever, format_context


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("query")
    ap.add_argument("-k", type=int, default=5)
    ap.add_argument("--language", choices=["python", "java"])
    ap.add_argument("--owasp", help="e.g. A03")
    ap.add_argument("--doc-type", help="cheatsheet | top10 | custom")
    ap.add_argument("--no-mmr", action="store_true")
    ap.add_argument("--show-context", action="store_true", help="print the LLM-ready context block")
    args = ap.parse_args(argv)

    hits = Retriever().retrieve(
        args.query, k=args.k, language=args.language, owasp_category=args.owasp,
        doc_type=args.doc_type, mmr=not args.no_mmr,
    )
    if not hits:
        print("No results above the similarity threshold.")
        return 0
    if args.show_context:
        print(format_context(hits))
        return 0
    for i, h in enumerate(hits, 1):
        path = h.metadata.get("section_path", "")
        print(f"{i}. [{h.score:.3f}] {path}\n   {h.url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
