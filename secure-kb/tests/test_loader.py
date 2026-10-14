from kb.loader import clean_markdown, load_custom, split_front_matter


def test_front_matter_split():
    meta, body = split_front_matter("---\nid: x\nlanguage: python\n---\n# Hi\n")
    assert meta == {"id": "x", "language": "python"} and body.startswith("# Hi")


def test_clean_removes_images_comments_and_attr_lists_but_keeps_code():
    raw = "# A03 ![icon](a.png){: style=\"x\"}\n<!-- hidden -->\ntext\n\n```md\n![keep](a.png)\n<!-- keep -->\n```\n"
    out = clean_markdown(raw)
    assert "icon" not in out and "hidden" not in out
    assert "![keep](a.png)" in out and "<!-- keep -->" in out


def test_load_custom_reads_metadata(tmp_path):
    (tmp_path / "n.md").write_text("---\nid: custom-n\nlanguage: java\nowasp: A03\ncwe: [CWE-89]\n---\n# Note\n\nBody\n", encoding="utf-8")
    docs = load_custom(tmp_path)
    assert docs[0].doc_id == "custom-n"
    assert docs[0].metadata["language"] == "java"
    assert docs[0].metadata["cwe_ids"] == "CWE-89"
