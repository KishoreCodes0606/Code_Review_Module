"""Load + clean documents (OWASP downloads and project-authored notes)."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Document
from .sources import SourceSpec

_FRONT_MATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)(\{:[^}]*\})?")
_ATTR_LIST = re.compile(r"\{:\s*[^}]*\}")
_BLANKS = re.compile(r"\n{3,}")
_TOC_LINE = re.compile(r"^\s*\[TOC\]\s*$", re.IGNORECASE | re.MULTILINE)


def split_front_matter(raw: str) -> tuple[dict, str]:
    m = _FRONT_MATTER.match(raw)
    if not m:
        return {}, raw
    meta = yaml.safe_load(m.group(1)) or {}
    return (meta if isinstance(meta, dict) else {}), raw[m.end():]


def clean_markdown(text: str) -> str:
    """Strip noise that hurts embeddings but keep code blocks untouched."""
    # Protect fenced code so regexes below never touch it.
    fences: list[str] = []

    def _stash(m: re.Match) -> str:
        fences.append(m.group(0))
        return f"\u0000FENCE{len(fences) - 1}\u0000"

    text = re.sub(r"^```.*?^```[ \t]*$", _stash, text, flags=re.DOTALL | re.MULTILINE)
    text = _HTML_COMMENT.sub("", text)
    text = _IMAGE.sub("", text)
    text = _ATTR_LIST.sub("", text)
    text = _TOC_LINE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\t", "    ")
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = _BLANKS.sub("\n\n", text).strip()
    for i, block in enumerate(fences):
        text = text.replace(f"\u0000FENCE{i}\u0000", block)
    return text


def first_heading(text: str, fallback: str) -> str:
    for line in text.split("\n"):
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def load_downloaded(spec: SourceSpec, raw_dir: Path) -> Document | None:
    path = raw_dir / spec.local_rel_path
    if not path.exists():
        return None
    _, body = split_front_matter(path.read_text(encoding="utf-8"))
    text = clean_markdown(body)
    title = first_heading(text, Path(spec.file).stem.replace("_", " "))
    return Document(
        doc_id=spec.doc_id,
        title=title,
        text=text,
        metadata={
            "source_doc": title,
            "source_url": spec.source_url,
            "doc_type": spec.doc_type,
            "owasp_category": spec.owasp,
            "cwe_ids": ",".join(spec.cwe),
            "language": spec.language,
            "license": spec.license,
            "origin": "download",
        },
    )


def load_custom(custom_dir: Path) -> list[Document]:
    """Project-authored notes. Metadata comes from YAML front matter."""
    docs: list[Document] = []
    for path in sorted(Path(custom_dir).glob("*.md")):
        meta, body = split_front_matter(path.read_text(encoding="utf-8"))
        text = clean_markdown(body)
        title = meta.get("title") or first_heading(text, path.stem.replace("-", " "))
        docs.append(
            Document(
                doc_id=meta.get("id", f"custom-{path.stem}"),
                title=title,
                text=text,
                metadata={
                    "source_doc": title,
                    "source_url": meta.get("source_url", ""),
                    "doc_type": meta.get("doc_type", "custom"),
                    "owasp_category": str(meta.get("owasp", "general")),
                    "cwe_ids": ",".join(meta.get("cwe", []) or []),
                    "language": meta.get("language", "general"),
                    "license": meta.get("license", "Project-authored"),
                    "origin": "custom",
                },
            )
        )
    return docs
