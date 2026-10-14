"""Structure-aware chunking for Markdown knowledge documents.

Strategy (see the design document, section 8.2):
  1. Split on headings and remember the heading path (Title > H2 > H3).
  2. Inside a section, pack paragraphs into chunks of <= max_tokens.
  3. Never split a fenced code block unless it alone exceeds max_tokens.
  4. Carry ~overlap_tokens of trailing text into the next chunk of the SAME
     section so an idea that straddles a boundary is still retrievable.
  5. Merge tiny chunks (< min_tokens) into a neighbour.
  6. Prefix each chunk with its heading path so the embedding "knows" its topic.
  7. Chunk ids are content hashes, so re-ingesting is idempotent.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .models import Chunk, Document

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def estimate_tokens(text: str) -> int:
    """Cheap, dependency-free token estimate (close enough for chunk sizing)."""
    if not text:
        return 0
    return max(int(len(text.split()) * 1.3), len(text) // 4, 1)


@dataclass
class _Section:
    path: list[str]
    blocks: list[str]


@dataclass
class _Piece:
    path: list[str]
    body: str
    has_code: bool

    @property
    def tokens(self) -> int:
        return estimate_tokens(self.body)


# --------------------------------------------------------------------------
# 1. parsing
# --------------------------------------------------------------------------
def parse_sections(text: str) -> list[_Section]:
    sections: list[_Section] = []
    stack: list[tuple[int, str]] = []
    blocks: list[str] = []
    para: list[str] = []
    fence: list[str] = []
    in_fence = False
    path: list[str] = []

    def flush_para() -> None:
        if para:
            blocks.append("\n".join(para).strip("\n"))
            para.clear()

    def close_section() -> None:
        flush_para()
        if blocks:
            sections.append(_Section(path=list(path), blocks=list(blocks)))
        blocks.clear()

    for line in text.split("\n"):
        if in_fence:
            fence.append(line)
            if _FENCE.match(line):
                blocks.append("\n".join(fence))
                fence.clear()
                in_fence = False
            continue
        if _FENCE.match(line):
            flush_para()
            in_fence = True
            fence.append(line)
            continue
        m = _HEADING.match(line)
        if m:
            close_section()
            level, title = len(m.group(1)), m.group(2).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            path = [t for _, t in stack]
            continue
        if not line.strip():
            flush_para()
        else:
            para.append(line)

    if fence:  # unterminated fence: keep the text rather than lose it
        blocks.append("\n".join(fence))
    close_section()
    return sections


# --------------------------------------------------------------------------
# 2. splitting oversize blocks
# --------------------------------------------------------------------------
def _split_code(block: str, max_tokens: int) -> list[str]:
    lines = block.split("\n")
    opener = lines[0] if _FENCE.match(lines[0]) else "```"
    body = [ln for ln in lines if not _FENCE.match(ln)]
    parts, cur, cur_t = [], [], 0
    for ln in body:
        t = estimate_tokens(ln) + 1
        if cur and cur_t + t > max_tokens:
            parts.append("\n".join([opener, *cur, "```"]))
            cur, cur_t = [], 0
        cur.append(ln)
        cur_t += t
    if cur:
        parts.append("\n".join([opener, *cur, "```"]))
    return parts


def _split_text(block: str, max_tokens: int) -> list[str]:
    pieces: list[str] = []
    cur: list[str] = []
    cur_t = 0
    for sent in _SENTENCE.split(block):
        words = sent.split()
        # a single "sentence" larger than the limit (e.g. a long table row)
        while estimate_tokens(" ".join(words)) > max_tokens:
            n = max(1, int(max_tokens / 1.3))
            if cur:
                pieces.append(" ".join(cur))
                cur, cur_t = [], 0
            pieces.append(" ".join(words[:n]))
            words = words[n:]
        sent = " ".join(words)
        if not sent:
            continue
        t = estimate_tokens(sent)
        if cur and cur_t + t > max_tokens:
            pieces.append(" ".join(cur))
            cur, cur_t = [], 0
        cur.append(sent)
        cur_t += t
    if cur:
        pieces.append(" ".join(cur))
    return pieces


def _normalise_blocks(blocks: list[str], max_tokens: int) -> list[str]:
    out: list[str] = []
    for b in blocks:
        if estimate_tokens(b) <= max_tokens:
            out.append(b)
        elif _FENCE.match(b.split("\n", 1)[0]):
            out.extend(_split_code(b, max_tokens))
        elif "\n|" in b or b.lstrip().startswith("|"):  # markdown table: split by rows
            out.extend(_split_table(b, max_tokens))
        else:
            out.extend(_split_text(b, max_tokens))
    return out


def _split_table(block: str, max_tokens: int) -> list[str]:
    rows = block.split("\n")
    header = rows[:2] if len(rows) > 2 and set(rows[1].replace("|", "").strip()) <= set("-: ") else []
    body = rows[len(header):]
    parts, cur, cur_t = [], [], 0
    base = estimate_tokens("\n".join(header))
    for r in body:
        t = estimate_tokens(r) + 1
        if cur and base + cur_t + t > max_tokens:
            parts.append("\n".join([*header, *cur]))
            cur, cur_t = [], 0
        cur.append(r)
        cur_t += t
    if cur:
        parts.append("\n".join([*header, *cur]))
    return parts


# --------------------------------------------------------------------------
# 3. packing + overlap
# --------------------------------------------------------------------------
def _pack_section(sec: _Section, max_tokens: int, overlap_tokens: int) -> list[_Piece]:
    units = _normalise_blocks(sec.blocks, max_tokens)
    pieces: list[_Piece] = []
    cur: list[str] = []
    cur_t = 0

    def emit() -> None:
        body = "\n\n".join(cur)
        pieces.append(_Piece(path=sec.path, body=body, has_code="```" in body or "~~~" in body))

    for u in units:
        t = estimate_tokens(u)
        if cur and cur_t + t > max_tokens:
            emit()
            carry: list[str] = []
            carry_t = 0
            for prev in reversed(cur):
                pt = estimate_tokens(prev)
                if carry_t + pt > overlap_tokens or prev.lstrip().startswith(("```", "~~~")):
                    break
                carry.insert(0, prev)
                carry_t += pt
            if carry_t + t > max_tokens:
                carry, carry_t = [], 0
            cur, cur_t = carry, carry_t
        cur.append(u)
        cur_t += t
    if cur and (not pieces or "\n\n".join(cur) != pieces[-1].body):
        emit()
    return pieces


def _merge_tiny(pieces: list[_Piece], min_tokens: int, max_tokens: int) -> list[_Piece]:
    limit = int(max_tokens * 1.25)
    out: list[_Piece] = []
    for p in pieces:
        if out and p.tokens < min_tokens and out[-1].tokens + p.tokens <= limit:
            prev = out[-1]
            label = f"### {p.path[-1]}\n" if p.path and p.path != prev.path else ""
            out[-1] = _Piece(prev.path, f"{prev.body}\n\n{label}{p.body}", prev.has_code or p.has_code)
        else:
            out.append(p)
    # a tiny FIRST piece could not merge backwards: merge it forward instead
    if len(out) > 1 and out[0].tokens < min_tokens and out[0].tokens + out[1].tokens <= limit:
        a, b = out[0], out[1]
        label = f"### {b.path[-1]}\n" if b.path and b.path != a.path else ""
        out[1] = _Piece(a.path, f"{a.body}\n\n{label}{b.body}", a.has_code or b.has_code)
        out.pop(0)
    return out


# --------------------------------------------------------------------------
# 4. public API
# --------------------------------------------------------------------------
def make_prefix(doc_title: str, path: list[str]) -> str:
    parts = [doc_title] + [p for p in path if p != doc_title]
    return " > ".join(parts)


def chunk_document(
    doc: Document,
    max_tokens: int = 600,
    min_tokens: int = 80,
    overlap_tokens: int = 80,
) -> list[Chunk]:
    if overlap_tokens >= max_tokens:
        raise ValueError("overlap must be smaller than max_tokens")
    pieces: list[_Piece] = []
    for sec in parse_sections(doc.text):
        pieces.extend(_pack_section(sec, max_tokens, overlap_tokens))
    pieces = _merge_tiny(pieces, min_tokens, max_tokens)

    chunks: list[Chunk] = []
    for i, p in enumerate(pieces):
        prefix = make_prefix(doc.title, p.path)
        text = f"{prefix}\n\n{p.body}"
        digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]
        meta = dict(doc.metadata)
        meta.update(
            doc_id=doc.doc_id,
            section_path=prefix,
            has_code=p.has_code,
            chunk_index=i,
            token_estimate=estimate_tokens(text),
        )
        chunks.append(
            Chunk(
                chunk_id=f"{doc.doc_id}#{i:03d}-{digest}",
                doc_id=doc.doc_id,
                text=text,
                tokens=estimate_tokens(text),
                section_path=prefix,
                has_code=p.has_code,
                metadata=meta,
            )
        )
    return chunks
