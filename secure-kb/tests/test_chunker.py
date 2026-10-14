from kb.chunker import chunk_document, estimate_tokens, parse_sections
from kb.models import Document


def doc(text, title="Doc"):
    return Document(doc_id="d1", title=title, text=text, metadata={"doc_type": "t", "language": "general", "owasp_category": "A03"})


def test_heading_path_is_prefixed():
    text = "# Title\n\n## Prevention\n\n### Option 1\n\n" + ("Use parameterized queries. " * 20)
    chunks = chunk_document(doc(text, "Title"), min_tokens=1)
    assert chunks[0].section_path == "Title > Prevention > Option 1"
    assert chunks[0].text.startswith("Title > Prevention > Option 1\n\n")


def test_hash_inside_code_fence_is_not_a_heading():
    text = "# T\n\n## Real\n\n```python\n# not a heading\nx = 1\n```\n"
    secs = parse_sections(text)
    assert [s.path[-1] for s in secs] == ["Real"]


def test_code_block_is_never_split_when_it_fits():
    code = "```python\n" + "\n".join(f"line_{i} = {i}" for i in range(30)) + "\n```"
    text = "# T\n\n## S\n\n" + ("intro words " * 60) + "\n\n" + code + "\n\n" + ("tail words " * 60)
    chunks = chunk_document(doc(text, "T"), max_tokens=250, min_tokens=1, overlap_tokens=20)
    holders = [c for c in chunks if "line_0 = 0" in c.text]
    assert len(holders) >= 1
    assert all("line_29 = 29" in c.text for c in holders)


def test_oversize_code_block_is_split_with_valid_fences():
    code = "```python\n" + "\n".join(f"value_{i} = {i}" for i in range(400)) + "\n```"
    chunks = chunk_document(doc("# T\n\n## S\n\n" + code, "T"), max_tokens=200, min_tokens=1, overlap_tokens=10)
    assert len(chunks) > 1
    for c in chunks:
        assert c.text.count("```") % 2 == 0


def test_chunks_respect_max_size():
    text = "# T\n\n## S\n\n" + "\n\n".join("Paragraph number %d. " % i + "word " * 80 for i in range(30))
    chunks = chunk_document(doc(text, "T"), max_tokens=300, min_tokens=1, overlap_tokens=40)
    assert len(chunks) > 3
    assert max(c.tokens for c in chunks) <= 300 * 1.25 + 20


def test_overlap_repeats_trailing_paragraph():
    paras = [f"Unique paragraph {i}. " + "filler " * 60 for i in range(6)]
    chunks = chunk_document(doc("# T\n\n## S\n\n" + "\n\n".join(paras), "T"), max_tokens=220, min_tokens=1, overlap_tokens=120)
    assert len(chunks) >= 2
    shared = [i for i in range(6) if f"Unique paragraph {i}." in chunks[0].text and f"Unique paragraph {i}." in chunks[1].text]
    assert shared, "expected at least one paragraph repeated across the boundary"


def test_tiny_sections_are_merged():
    text = "# T\n\n## A\n\nShort.\n\n## B\n\nAlso short.\n\n## C\n\n" + ("longer body text " * 40)
    chunks = chunk_document(doc(text, "T"), max_tokens=600, min_tokens=60)
    assert len(chunks) <= 2


def test_ids_are_stable_and_change_with_content():
    text = "# T\n\n## S\n\n" + "alpha " * 100
    a = chunk_document(doc(text, "T"))
    b = chunk_document(doc(text, "T"))
    c = chunk_document(doc(text.replace("alpha", "beta"), "T"))
    assert [x.chunk_id for x in a] == [x.chunk_id for x in b]
    assert a[0].chunk_id != c[0].chunk_id


def test_metadata_is_primitive_and_complete():
    chunks = chunk_document(doc("# T\n\n## S\n\n```python\nx=1\n```\n" + "word " * 50, "T"), min_tokens=1)
    meta = chunks[0].metadata
    assert meta["doc_id"] == "d1" and meta["has_code"] is True
    assert all(isinstance(v, (str, int, float, bool)) for v in meta.values())


def test_estimate_tokens_monotonic():
    assert estimate_tokens("") == 0
    assert estimate_tokens("a b c") < estimate_tokens("a b c d e f g h")
