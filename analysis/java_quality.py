"""Java code-quality detectors.

Primary path: PMD CLI (see analysis/pmd_client.py) when the tool is installed/
downloadable. Custom detectors built on the pure-python `javalang` parser always
run as well, so Java quality output is available even without a JVM download.
javalang is intentionally NOT the only Java analyser — PMD carries the richer
rule set when available; both run and findings are de-duplicated at merge time.
"""
from __future__ import annotations

import re
from collections import Counter

from analysis.findings import Finding
from analysis.rule_catalog import QUALITY
from analysis.severity import compute_finding_score
from analysis.source_utils import snippet

AGENT = "code_analysis_agent"
DETECTION_CUSTOM = "rule_based"
DETECTION_PMD = "analyzer:pmd"

MAX_FUNCTION_LOC = 50
MAX_NESTING = 3
MAX_PARAMS = 5
MAX_METHODS_PER_CLASS = 20
MAGIC_NUMBER_MIN = 100
MAGIC_NUMBER_HITS = 3

_SQL_TOKEN = re.compile(
    r"\?\s*|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b", re.I
)


def analyze_java_quality(java_source: str, file_path: str) -> dict:
    """Returns {'findings': [...], 'metrics': {...}} — never executes code."""
    try:
        import javalang
        tree = javalang.parse.parse(java_source)
    except Exception as e:          # javalang cannot read the file at all
        return {"findings": [], "metrics": {"parsed": False, "parse_error": str(e)}}

    lines = java_source.splitlines()
    findings: list[Finding] = []
    metrics: dict = {"parsed": True}

    # ---- imports (unused) --------------------------------------------------
    declared_imports: dict[str, int] = {}
    for imp in tree.imports or []:
        base = (imp.path or "").split(".")[-1]
        if base:
            declared_imports[base] = imp.position.line if imp.position else 1
    used_names: Counter[str] = Counter()
    for token in re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", java_source):
        used_names[token] += 1
    if declared_imports:
        for imp in tree.imports or []:
            base = (imp.path or "").split(".")[-1]
            if used_names.get(base, 0) <= 1:
                line = imp.position.line
                f = Finding.from_rule(
                    "Q-unused-import", line, line, snippet(lines, line, line), file_path,
                    f"Import '{base}' on line {line} is never referenced.",
                    AGENT, DETECTION_CUSTOM, QUALITY["Q-unused-import"])
                compute_finding_score(f, confirmed=False)
                findings.append(f)

    # ---- class/method iteration -------------------------------------------
    method_count_by_class: dict[str, int] = {}
    class_spans: dict[str, dict] = {}
    for type_decl in (tree.types or []):
        cname = type_decl.name
        methods = [m for m in (type_decl.methods or [])] + [
            m for m in (type_decl.constructors or []) if isinstance(m, object)
        ]
        if isinstance(type_decl, __import__("javalang").tree.ClassDeclaration):
            method_count_by_class[cname] = len(type_decl.methods or [])

        # javalang gives -1 ranges when braces are broken; guard them
        def span(node, default_start=1):
            return (node.position.line if node.position else default_start,
                    getattr(node, "_position", None) and node.position.line or None)

        for m in (type_decl.methods or []) + list(type_decl.constructors or []):
            if m.position is None:
                continue
            start = m.position.line
            end = _method_end_line(m, lines, start)
            loc = end - start + 1
            body_text = "\n".join(lines[start - 1 : end])

            if loc > MAX_FUNCTION_LOC:
                f = Finding.from_rule(
                    "Q-long-method", start, end, snippet(lines, start, start + 5), file_path,
                    f"Method '{cname}.{m.name}' is {loc} LOC (threshold {MAX_FUNCTION_LOC}).",
                    AGENT, DETECTION_CUSTOM, QUALITY["Q-long-method"])
                compute_finding_score(f, confirmed=False)
                findings.append(f)

            params = list(m.parameters or [])
            if len(params) > MAX_PARAMS:
                f = Finding.from_rule(
                    "Q-long-param-list", start, start, snippet(lines, start, start), file_path,
                    f"Method '{cname}.{m.name}' takes {len(params)} parameters (threshold {MAX_PARAMS}).",
                    AGENT, DETECTION_CUSTOM, QUALITY["Q-long-param-list"])
                compute_finding_score(f, confirmed=False)
                findings.append(f)

            depth = _max_nesting_depth(m, lines, start, end)
            if depth > MAX_NESTING:
                f = Finding.from_rule(
                    "Q-deep-nesting", start, end, snippet(lines, start, start + 3), file_path,
                    f"Method '{cname}.{m.name}' nests {depth} blocks deep (threshold {MAX_NESTING}).",
                    AGENT, DETECTION_CUSTOM, QUALITY["Q-deep-nesting"])
                compute_finding_score(f, confirmed=False)
                findings.append(f)

            # ---- unused local variables within this method ----------------
            findings.extend(
                _unused_locals(
                    m, lines, start, end, body_text, cname, file_path))

            # ---- magic numbers within the method --------------------------
            for value, first_line in _magic_numbers(body_text, start).items():
                f = Finding.from_rule(
                    "Q-magic-number", first_line, first_line, snippet(lines, first_line, first_line),
                    file_path,
                    f"Magic number {value} repeated in '{cname}.{m.name}' without a named constant.",
                    AGENT, DETECTION_CUSTOM, QUALITY["Q-magic-number"])
                compute_finding_score(f, confirmed=False)
                findings.append(f)

        class_spans[cname] = {
            "start": type_decl.position.line if type_decl.position else 1,
            "methods": len(type_decl.methods or []),
        }

    for cname, info in class_spans.items():
        if info["methods"] > MAX_METHODS_PER_CLASS:
            f = Finding.from_rule(
                "Q-large-class", info["start"], info["start"] + 2,
                snippet(lines, info["start"], info["start"]), file_path,
                f"Class '{cname}' declares {info['methods']} methods (threshold {MAX_METHODS_PER_CLASS}).",
                AGENT, DETECTION_CUSTOM, QUALITY["Q-large-class"])
            compute_finding_score(f, confirmed=False)
            findings.append(f)

    metrics["method_count"] = sum(len(td.methods or []) for td in (tree.types or []))
    metrics["class_count"] = len(list(tree.types or []))
    return {"findings": findings, "metrics": metrics}


# --- helpers ---------------------------------------------------------------


def _method_end_line(m, lines, start: int) -> int:
    """Walk from the method header to the brace that closes the method body."""
    if m.body is not None:
        max_child = start
        for stmt in m.body:
            ln = getattr(stmt, "position", None) and stmt.position.line
            if ln and ln > max_child:
                max_child = ln
            for descendant in stmt.children if hasattr(stmt, "children") else []:
                ln2 = getattr(descendant, "position", None)
                # javalang children are AST nodes/attributes — use token scan instead
        # fall back to brace balancing over the raw text (robust for any AST oddity)
        return _brace_balanced_end(lines, start)
    return _brace_balanced_end(lines, max(start, 1))


def _brace_balanced_end(lines, start: int) -> int:
    depth = 0
    opened = False
    in_string = in_char = in_line_comment = in_block_comment = False
    for idx in range(start - 1, len(lines)):
        line = lines[idx]
        i = 0
        while i < len(line):
            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
                i += 1
                continue
            if in_char:
                if ch == "\\":
                    i += 2
                    continue
                if ch == "'":
                    in_char = False
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == '"':
                in_string = True
                i += 1
                continue
            if ch == "'":
                in_char = True
                i += 1
                continue
            if ch == "{":
                opened = True
                depth += 1
            elif ch == "}":
                depth -= 1
                if opened and depth <= 0:
                    return idx + 1
            i += 1
    return len(lines)


def _max_nesting_depth(m, lines, start: int, end: int) -> int:
    depth = best = 0
    in_string = in_char = in_block_comment = False
    for idx in range(start - 1, min(end, len(lines))):
        line = lines[idx]
        i = 0
        while i < len(line):
            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
                i += 1
                continue
            if in_char:
                if ch == "\\":
                    i += 2
                    continue
                if ch == "'":
                    in_char = False
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == '"':
                in_string = True
                i += 1
                continue
            if ch == "'":
                in_char = True
                i += 1
                continue
            if ch == "{":
                depth += 1
                best = max(best, depth)
            elif ch == "}":
                depth = max(0, depth - 1)
            i += 1
    return best


def _unused_locals(m, lines, start: int, end: int, body_text: str, cname: str, file_path: str):
    """vars declared in the method body but never read before method end."""
    decl_pattern = re.compile(
        r"\b(?:final\s+)?[A-Za-z_$][\w.<>\[\]]*\s+([a-z][A-Za-z0-9_$]*)\s*=", re.M)
    for var, line in [(m.groups()[0], i + 1) for i, line in enumerate(lines[start - 1:end])
                      for m in [decl_pattern.search(line)] if m]:
        # names like field/class-name assignments are out of method scope guard
        if var in ("this", "args"):
            continue
        used_count = len(re.findall(rf"\b{re.escape(var)}\b", body_text))
        declared = 1 if re.search(rf"\b{re.escape(var)}\s*=", body_text) else 0
        if used_count <= declared and not re.search(
                rf"\b{re.escape(var)}\)", body_text):
            f = Finding.from_rule(
                "Q-unused-variable", start + line - 1, start + line - 1,
                snippet(lines, start + line - 1, start + line - 1), file_path,
                f"Variable '{var}' assigned on line {start + line - 1} but never read in '{cname}.{m.name}'.",
                AGENT, DETECTION_CUSTOM, QUALITY["Q-unused-variable"])
            compute_finding_score(f, confirmed=False)
            yield f


def _magic_numbers(body_text: str, start: int) -> dict[str, int]:
    hits: dict[str, list[int]] = {}
    for i, raw in enumerate(body_text.splitlines()):
        line = raw.split("//")[0]
        for match in re.finditer(r"(?<![\w.])\d{3,}(?![\w.])", line):
            hits.setdefault(match.group(0), []).append(start + i)
    return {value: first_line for value, lines_ in hits.items()
            for first_line in [min(lines_)] if len(set(lines_)) >= MAGIC_NUMBER_HITS}


# --- PMD passthrough -------------------------------------------------------


def add_pmd_findings(java_path: str, file_path: str, findings: list) -> list[str]:
    """Run PMD over the file and convert quality violations. Returns a status
    note ('pmd: unavailable' / 'pmd: ok') rather than raising."""
    from analysis.pmd_client import run_pmd
    pmd_findings, status = run_pmd(java_path)
    if status != "ok" or not pmd_findings:
        return status
    try:
        with open(java_path, "r", encoding="utf-8") as fh:
            source_lines = fh.read().splitlines()
    except OSError:
        source_lines = []
    existing = {(f.rule_id, f.line_start) for f in findings}
    for v in pmd_findings:
        f = _pmd_to_finding(v, file_path, source_lines)
        if f and (f.rule_id, f.line_start) not in existing:
            compute_finding_score(f, confirmed=False)
            findings.append(f)
    return status


PMD_RULE_MAP = {
    "LongMethod": "Q-long-method",
    "ExcessiveMethodLength": "Q-long-method",
    "ExcessiveClassLength": "Q-large-class",
    "CyclomaticComplexity": "Q-high-complexity",
    "NPathComplexity": "Q-high-complexity",
    "ExcessiveParameterList": "Q-long-param-list",
    "TooManyParams": "Q-long-param-list",
    "AvoidDeeplyNestedIfStmts": "Q-deep-nesting",
    "CognitiveComplexity": "Q-high-complexity",
    "UnusedImports": "Q-unused-import",
    "UnusedLocalVariable": "Q-unused-variable",
    "UnusedPrivateField": "Q-unused-variable",
    "UnusedPrivateMethod": "Q-unused-variable",
    "UnusedFormalParameter": "Q-unused-variable",
    "UnusedAssignment": "Q-unused-variable",
    "TooManyMethods": "Q-large-class",
    "GodClass": "Q-large-class",
    "EmptyCatchBlock": "Q-broad-exception",
}


def _pmd_to_finding(v: dict, file_path: str, source_lines: list[str] | None = None):
    rule = v.get("rule", "")
    rule_id = PMD_RULE_MAP.get(rule, "Q-pmd-generic")
    title = QUALITY[rule_id].title if rule_id in QUALITY else rule
    spec = QUALITY[rule_id]
    begin = int(v.get("beginline", 1))
    end = int(v.get("endline", v.get("beginline", 1)))
    snippet_text = ""
    if source_lines and 0 < begin <= len(source_lines):
        snippet_text = "\n".join(
            source_lines[begin - 1:min(end, len(source_lines))])
    f = Finding.from_rule(
        rule_id,
        begin,
        end,
        snippet_text[:200],
        file_path,
        v.get("description") or f"PMD rule {rule} violated.",
        AGENT, DETECTION_PMD, spec, title_override=f"{title} (PMD: {rule})")
    return f
