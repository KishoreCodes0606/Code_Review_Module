"""Python code-quality detectors: metrics via `ast` walking + radon complexity.

All rules are AST walks over the submitted code — no code is ever executed.
"""
from __future__ import annotations

import ast

import radon.complexity as radon_cx
from radon.metrics import mi_visit

from analysis.findings import Finding
from analysis.rule_catalog import QUALITY
from analysis.severity import compute_finding_score
from analysis.source_utils import snippet

AGENT = "code_analysis_agent"
DETECTION = "rule_based"

# thresholds (design doc section 4 / research report section 4)
MAX_FUNCTION_LOC = 50
MAX_NESTING = 3
MAX_PARAMS = 5
MAX_METHODS_PER_CLASS = 20
MAX_CC = 10          # "high" complexity boundary
MAGIC_NUMBER_MIN = 100
MAGIC_NUMBER_HITS = 3

_COND_CLASSES = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor)
_EXC = ast.ExceptHandler
_COND_NODES_ALL = _COND_CLASSES + (_EXC, ast.IfExp, ast.BoolOp)


def analyze_python_quality(code: str, file_path: str) -> dict:
    """Returns {'findings': [Finding], 'metrics': {..}}."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        # "not analysed" is not "clean": the agent reads these metrics and
        # reports the quality scan as failed instead of returning a tidy [].
        return {"findings": [], "metrics": {
            "parsed": False,
            "parser": "ast",
            "parse_error": (f"ast.parse failed at line {e.lineno}, col {e.offset}: "
                            f"{e.msg or 'invalid syntax'}"),
        }}

    findings: list[Finding] = []
    metrics: dict = {"parsed": True}
    functions = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    metrics["function_count"] = len(functions)
    metrics["class_count"] = len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)])

    # ---- radon CC and Maintainability Index -------------------------------
    try:
        cc_blocks = radon_cx.cc_visit(code)
        metrics["avg_complexity"] = round(radon_cx.average_complexity(cc_blocks), 2) if cc_blocks else 0.0
        metrics["max_complexity"] = max((b.complexity for b in cc_blocks), default=0)
        metrics["maintainability_index"] = round(mi_visit(code, multi=True), 1)
    except Exception:  # radon failure must never kill the agent
        metrics["maintainability_index"] = None

    for block in cc_blocks:
        if getattr(block, "complexity", 0) > MAX_CC:
            finding = Finding.from_rule(
                "Q-high-complexity", block.lineno, block.endline,
                snippet(code.splitlines(), block.lineno, min(block.endline, block.lineno + 5)),
                file_path,
                f"Function '{block.name}' has cyclomatic complexity {block.complexity} (threshold {MAX_CC}).",
                AGENT, DETECTION, QUALITY["Q-high-complexity"])
            compute_finding_score(finding, confirmed=False)
            findings.append(finding)

    lines = code.splitlines()
    for fn in functions:
        span = _fn_length_span(fn)
        if not span:
            continue
        start, end, length = span
        # 1. long method
        if length > MAX_FUNCTION_LOC:
            f = Finding.from_rule(
                "Q-long-method", start, end, snippet(lines, start, start + 5), file_path,
                f"Method '{fn.name}' is {length} LOC (threshold {MAX_FUNCTION_LOC}).",
                AGENT, DETECTION, QUALITY["Q-long-method"])
            compute_finding_score(f, confirmed=False)
            findings.append(f)
        # 2. long parameter list
        args = _args_list(fn.args)
        if len(args) > MAX_PARAMS:
            f = Finding.from_rule(
                "Q-long-param-list", start, start, snippet(lines, start, start), file_path,
                f"Method '{fn.name}' takes {len(args)} parameters (threshold {MAX_PARAMS}).",
                AGENT, DETECTION, QUALITY["Q-long-param-list"])
            compute_finding_score(f, confirmed=False)
            findings.append(f)
        # 3. deep nesting
        depth = _max_nesting(fn)
        if depth > MAX_NESTING:
            f = Finding.from_rule(
                "Q-deep-nesting", start, end, snippet(lines, start, start + 3), file_path,
                f"Function '{fn.name}' nests {depth} levels deep (threshold {MAX_NESTING}).",
                AGENT, DETECTION, QUALITY["Q-deep-nesting"])
            compute_finding_score(f, confirmed=False)
            findings.append(f)

    # 4. large class
    for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
        method_count = sum(
            1 for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        start = getattr(cls, "lineno", 1)
        end = getattr(cls, "end_lineno", start) or start
        if method_count > MAX_METHODS_PER_CLASS:
            f = Finding.from_rule(
                "Q-large-class", start, end, snippet(lines, start, start + 3), file_path,
                f"Class '{cls.name}' defines {method_count} methods (threshold {MAX_METHODS_PER_CLASS}).",
                AGENT, DETECTION, QUALITY["Q-large-class"])
            compute_finding_score(f, confirmed=False)
            findings.append(f)

    # 5. broad exception handling (bare 'except:' / 'except Exception')
    for node in ast.walk(tree):
        if isinstance(node, _EXC):
            bare = node.type is None
            catch_all = isinstance(node.type, ast.Name) and node.type.id == "Exception"
            if bare or catch_all:
                f = Finding.from_rule(
                    "Q-broad-exception", node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno,
                    snippet(lines, node.lineno, node.lineno), file_path,
                    f"Bare/broad 'except' on line {node.lineno} hides real errors; catch specific types.",
                    AGENT, DETECTION, QUALITY["Q-broad-exception"])
                compute_finding_score(f, confirmed=False)
                findings.append(f)

    # 6. magic numbers
    for finding in _magic_number_findings(tree, lines, file_path):
        findings.append(finding)

    # 7. unused imports
    for finding in _unused_imports(tree, lines, file_path):
        findings.append(finding)

    # 8. unused local variables
    for finding in _unused_locals(functions, lines, file_path):
        findings.append(finding)

    return {"findings": findings, "metrics": metrics}


# --- helpers ---------------------------------------------------------------


def _fn_length_span(fn: ast.stmt):
    """(start, end, loc) excluding a leading docstring."""
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str) and len(body) > 1:
        body = body[1:]
    if not body:
        return None
    start = getattr(fn, "lineno", 0)
    end = max(getattr(b, "end_lineno", getattr(b, "lineno", start)) for b in body)
    return start, end, end - start + 1


def _args_list(a: ast.arguments) -> list[str]:
    return [
        x.arg for x in (a.posonlyargs + a.args + a.kwonlyargs)
        if getattr(x, "arg", None)
    ]


def _max_nesting(fn) -> int:
    best = 0

    def recurse(node, depth: int):
        nonlocal best
        for child in ast.iter_child_nodes(node):
            bump = (
                1 if isinstance(child, _COND_CLASSES)
                or isinstance(child, (_EXC, ast.IfExp))
                and not isinstance(child, ast.BoolOp)
                else 0
            )
            child_depth = depth + bump
            best = max(best, child_depth)
            recurse(child, child_depth)

    recurse(fn, 0)
    return best


def _magic_number_findings(tree, lines, file_path):
    value_lines: dict[float, list[int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, int) \
                and not isinstance(node.value, bool) and abs(node.value) >= MAGIC_NUMBER_MIN:
            value_lines.setdefault(node.value, []).append(getattr(node, "lineno", 1))
    for value, occurs in value_lines.items():
        if len(occurs) >= MAGIC_NUMBER_HITS:
            f = Finding.from_rule(
                "Q-magic-number", occurs[0], occurs[0],
                snippet(lines, occurs[0], occurs[0]), file_path,
                f"Magic number {value} is used {len(occurs)} times without a named constant.",
                AGENT, DETECTION, QUALITY["Q-magic-number"])
            compute_finding_score(f, confirmed=False)
            yield f


def _collect_names(node) -> set[str]:
    """Names actually READ (Load/Del context), not assignment targets."""
    names: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Load, ast.Del)):
            names.add(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                and isinstance(n.value.ctx, (ast.Load, ast.Del)):
            names.add(n.value.id)
    return names


def _unused_imports(tree, lines, file_path):
    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    imported[alias.asname or alias.name] = node.lineno
    used = _collect_names(tree)
    for name, line in imported.items():
        if name not in used:
            f = Finding.from_rule(
                "Q-unused-import", line, line, snippet(lines, line, line), file_path,
                f"Import '{name}' on line {line} is never referenced.",
                AGENT, DETECTION, QUALITY["Q-unused-import"])
            yield f


def _unused_locals(functions, lines, file_path):
    for fn in functions:
        assigned: dict[str, int] = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                assigned[node.targets[0].id] = node.lineno
        if not assigned:
            continue
        used = _collect_names(fn)
        for inner in [n for n in ast.walk(fn)
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n is not fn]:
            used |= _collect_names(inner)
        for name, line in assigned.items():
            if name.startswith("_") or name in used:
                continue
            f = Finding.from_rule(
                "Q-unused-variable", line, line, snippet(lines, line, line), file_path,
                f"Variable '{name}' assigned on line {line} but never read.",
                AGENT, DETECTION, QUALITY["Q-unused-variable"])
            yield f
