"""Download the OWASP source documents listed in sources.yaml.

Usage:
    python -m kb.download            # fetch missing files
    python -m kb.download --force    # re-fetch everything
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone

import requests

from .config import get_settings
from .sources import load_sources


def fetch(url: str, retries: int = 3, timeout: int = 30) -> str:
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "secure-kb-ingest/1.0"})
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as exc:  # network / HTTP error
            last = exc
            time.sleep(1.5 * attempt)
    raise RuntimeError(f"Failed to download {url}: {last}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-download existing files")
    args = parser.parse_args(argv)

    cfg = get_settings()
    specs = load_sources(cfg.sources_file)
    cfg.raw_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, dict] = {}
    failed: list[str] = []
    for spec in specs:
        target = cfg.raw_dir / spec.local_rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not args.force:
            text = target.read_text(encoding="utf-8")
            status = "cached"
        else:
            try:
                text = fetch(spec.raw_url)
            except RuntimeError as exc:
                print(f"  FAIL  {spec.doc_id}: {exc}", file=sys.stderr)
                failed.append(spec.doc_id)
                continue
            target.write_text(text, encoding="utf-8")
            status = "downloaded"
        manifest[spec.doc_id] = {
            "file": spec.local_rel_path,
            "url": spec.raw_url,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "bytes": len(text.encode("utf-8")),
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        print(f"  {status:<10} {spec.doc_id}")

    (cfg.raw_dir / "download_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n{len(manifest)} documents ready, {len(failed)} failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
