"""Shared source-text helpers for detectors (comment/quote stripping, lazy line
look-ups). Used by both the Python and Java detector modules."""
from __future__ import annotations


def strip_inline_comment(line: str, comment_char: str) -> str:
    """Remove '...# comment' or '...// comment' outside string literals."""
    in_single = in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and (in_single or in_double):
            i += 2
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "'" and not in_double:
            in_single = not in_single
        elif (
            comment_char == line[i : i + 1]
            and not in_single
            and not in_double
        ):
            return line[:i]
        i += 1
    return line


def snippet(lines: list[str], start: int, end: int) -> str:
    """Collect source lines 1-indexed [start, end] trimmed."""
    return "\n".join(
        ln.strip() for ln in lines[start - 1 : end] if ln.strip()
    )
