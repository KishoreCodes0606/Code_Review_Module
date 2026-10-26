"""Security detectors (deterministic, static only — never executes code).

Python rules: AST walks (sink-call argument inspection).
Java rules: line/token scans with comment/string awareness.

`confirmed=True` (higher exploitability factor) is reserved for a later flow
when data flow into a sink is traced; today every detector hit passes
confirmed=False (pattern-level evidence). Confidence stays a documented tier
in the rule catalog — never summed into scores (docs/severity_scoring.md).
"""
from __future__ import annotations

import ast
import re

from analysis.findings import Finding
from analysis.rule_catalog import SECURITY
from analysis.severity import compute_finding_score
from analysis.source_utils import snippet

AGENT = "security_agent"
DETECTION = "rule_based"

SQL_KEYWORDS = re.compile(
    r"\b(select|insert\s+into|update\s+|delete\s+from|drop\s+table|alter\s+table)\b", re.I)
SQL_SHAPE = re.compile(
    r"\b(select|insert|update|delete|drop)\b.*\b(from|into|table|set|where)\b", re.I)

EXEC_SINK_METHODS = {"execute", "executemany", "executescript", "executesql"}
PY_SINK_NAMES = ("os.system", "os.popen", "eval", "exec", "compile")
BROKEN_HASHES = {"md5", "sha1"}

SECRET_VAR_RE = re.compile(
    r"\b(password|passwd|pwd|secret|api_?key|auth_?token|access_?token|private_key)\w*\b", re.I)
SECRET_PLACEHOLDERS = re.compile(
    r"['\"](?:\s*|<[^>]*>|\.{3,}|x{3,}|\*{3,}|placeholder|change[-_ ]?(?:me|it)"
    r"|replace[_ ]?me|todo|example|dummy)[\"']"
    r"|os\.environ|getenv|input\(", re.I)


# =====================================================================
# PYTHON
# =====================================================================

def analyze_python_security(code: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings
    lines = code.splitlines()
    # variable -> (line, value) for entries built by dynamic string ops, so a
    # later `cursor.execute(query)` can resolve the constructed query.
    dyn_assign: dict[str, tuple[int, ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) \
                and _dynamic_string_parts([node.value]):
            dyn_assign[node.targets[0].id] = (node.lineno, node.value)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        arg_src = " ".join(ast.unparse(a) for a in node.args)

        # --- SQL injection: dynamic string built into a sink, containing SQL
        # Case A: the dynamic SQL lives in the call args themselves.
        if name and name.split(".")[-1] in EXEC_SINK_METHODS:
            dynamic = _dynamic_string_parts(node.args)
            if dynamic and _has_sql(dynamic):
                f = Finding.from_rule(
                    "S-PY-SQLI", node.lineno,
                    getattr(node, "end_lineno", node.lineno) or node.lineno,
                    snippet(lines, node.lineno, node.lineno), file_path,
                    "User-controlled value is concatenated/interpolated into a SQL query "
                    "before execution.",
                    AGENT, DETECTION, SECURITY["S-PY-SQLI"])
                compute_finding_score(f)
                findings.append(f)
                continue
            # Case B: the SQL is built into a variable, then executed.
            reported = False
            for a in node.args:
                if isinstance(a, ast.Name) and a.id in dyn_assign:
                    value = dyn_assign[a.id][1]
                    if _has_sql([value]):
                        f = Finding.from_rule(
                            "S-PY-SQLI", dyn_assign[a.id][0], node.lineno,
                            snippet(lines, dyn_assign[a.id][0], dyn_assign[a.id][0]),
                            file_path,
                            f"Query built from concatenation/interpolation (variable '{a.id}') "
                            "is executed; use parameterized queries instead.",
                            AGENT, DETECTION, SECURITY["S-PY-SQLI"])
                        compute_finding_score(f)
                        findings.append(f)
                        reported = True
                        break
            if not reported:
                pass
            # parameterized call with a static-only query stays safe: no finding
            continue

        # --- dangerous direct sinks
        if name in PY_SINK_NAMES:
            rule_map = {
                "os.system": "S-PY-CMDI", "os.popen": "S-PY-CMDI",
                "eval": "S-PY-EVAL", "exec": "S-PY-EVAL", "compile": "S-PY-EVAL",
            }
            rule_id = rule_map[name]
            finding = Finding.from_rule(
                rule_id, node.lineno,
                getattr(node, "end_lineno", node.lineno) or node.lineno,
                snippet(lines, node.lineno, node.lineno), file_path,
                f"'{name}()' is a dangerous code-execution sink reachable from application "
                "logic; verify no untrusted data reaches this call.",
                AGENT, DETECTION, SECURITY[rule_id])
            compute_finding_score(finding)
            findings.append(finding)

        # --- subprocess with shell=True (S-PY-SHELL)
        if name and name.split(".")[-1] in {"run", "call", "check_output", "check_call", "Popen"} \
                and _is_subprocess_call(name):
            shell_true = any(
                isinstance(kw, ast.keyword) and kw.arg == "shell"
                and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords)
            if shell_true:
                finding = Finding.from_rule(
                    "S-PY-SHELL", node.lineno, node.lineno,
                    snippet(lines, node.lineno, node.lineno), file_path,
                    "subprocess invoked with shell=True; untrusted input can inject commands.",
                    AGENT, DETECTION, SECURITY["S-PY-SHELL"])
                compute_finding_score(finding)
                findings.append(finding)

        # --- insecure deserialization (yaml SafeLoader/BaseLoader stay safe)
        deser_rule = _deser_rule(name)
        if deser_rule:
            if name == "yaml.load" and any(
                    isinstance(kw, ast.keyword) and kw.arg in ("Loader", "fmt")
                    and re.search(r"(Safe|Base)Loader\b", ast.dump(kw.value))
                    for kw in node.keywords):
                continue
            finding = Finding.from_rule(
                deser_rule, node.lineno, node.lineno,
                snippet(lines, node.lineno, node.lineno), file_path,
                f"'{name}' deserializes a binary/YAML stream that must never be untrusted.",
                AGENT, DETECTION, SECURITY[deser_rule])
            compute_finding_score(finding)
            findings.append(finding)

        # --- broken crypto hashes
        if name and name.startswith("hashlib.") and name.split(".")[-1] in BROKEN_HASHES:
            finding = Finding.from_rule(
                "S-PY-CRYPTO", node.lineno, node.lineno,
                snippet(lines, node.lineno, node.lineno), file_path,
                f"{name}() is cryptographically broken; use SHA-256+ for data digests or "
                "bcrypt/argon2 password hashers for passwords.",
                AGENT, DETECTION, SECURITY["S-PY-CRYPTO"])
            compute_finding_score(finding)
            findings.append(finding)

        # --- path traversal heuristic: open() built from a function parameter
        if name == "open":
            func_params = set(_func_params(tree))
            arg_names = re.findall(r"\b[A-Za-z_]\w*\b", arg_src)
            tainted = bool(set(arg_names) & func_params) or re.search(r"\.\.", arg_src)
            if tainted:
                finding = Finding.from_rule(
                    "S-PY-PATH", node.lineno, node.lineno,
                    snippet(lines, node.lineno, node.lineno), file_path,
                    "File path is built from a caller-supplied value without confinement; "
                    "validate/canonicalize before use.",
                    AGENT, DETECTION, SECURITY["S-PY-PATH"])
                compute_finding_score(finding)
                findings.append(finding)

    findings.extend(_secret_lines(lines, file_path, "S-PY-SECRET"))
    return findings


def _call_name(func) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        qual = _call_name(func.value)
        return f"{qual}.{func.attr}" if qual else func.attr
    return None


def _dynamic_string_parts(args: list[ast.expr]) -> list[ast.expr]:
    """SQL string pieces that are NOT plain literals (f-strings, '+', '%', [n])."""
    parts: list[ast.expr] = []
    for a in args:
        dynamic = (
            isinstance(a, ast.JoinedStr)
            or (isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Mod)))
            or isinstance(a, ast.Subscript)
        )
        if dynamic:
            parts.append(a)
    return parts


def _has_sql(parts) -> bool:
    for p in parts:
        text = ast.unparse(p)
        if SQL_SHAPE.search(text) or SQL_KEYWORDS.search(text):
            return True
    return False


def _is_subprocess_call(name: str) -> bool:
    return name.split(".")[0] in ("subprocess", "sh", "commands", "os")


def _deser_rule(name: str | None) -> str | None:
    if not name:
        return None
    tail = name.split(".")[-1]
    if name.startswith("pickle.") and tail in {"loads", "load"}:
        return "S-PY-DESER"
    if name in ("yaml.load", "yaml.unsafe_load"):
        return "S-PY-DESER"
    return None


def _func_params(tree):
    params: set[str] = set()
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for a in fn.args.args:
            params.add(a.arg)
    params.difference_update({"self", "cls"})
    return sorted(params)


# =====================================================================
# JAVA
# =====================================================================

JAVA_EXECUTE_METHODS = {"executeQuery", "executeUpdate", "execute", "executeLargeUpdate"}
JAVA_APPEND_EXEC = re.compile(r"(\w+)\s*=\s*\"[^\"]*\"(?:\s*\+|$)")


def analyze_java_security(java_source: str, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    tree = None
    try:
        import javalang
        tree = javalang.parse.parse(java_source)
    except Exception:
        # partial/invalid syntax: the line scanners below do not need the AST,
        # so detection degrades gracefully instead of switching off.
        pass
    lines = java_source.splitlines()
    if not lines:
        return findings

    xxe_hardened_anywhere = (
        "EXTERNAL_GENERAL_ENTITIES" in java_source
        or "disallow-doctype-decl" in java_source.lower()
        or "DISALLOW_DOCTYPE_DECL" in java_source
    )
    xxe_flagged = False
    ois_declared = False
    # var -> line for String variables built with a '+' concatenation, so a
    # later `st.executeQuery(q)` resolves the constructed query.
    dyn_string_vars: dict[str, dict] = {}
    for li, rawline in enumerate(lines, 1):
        cm = re.match(r"\s*String\s+(\w+)\s*=\s*(.+);\s*$", rawline.split("//")[0])
        if cm and "+" in cm.group(2):
            dyn_string_vars[cm.group(1)] = {"line": li, "value": cm.group(2)}

    for i, raw in enumerate(lines, 1):
        codepart = raw.split("//")[0]

        # --- SQL injection: Statement.execute*() fed a concatenated query
        for method in JAVA_EXECUTE_METHODS:
            m = re.search(rf"\.{method}\s*\(\s*([\w$]+)", codepart)
            if not m:
                continue
            arg = m.group(1)
            arg_text = codepart[m.end():].split(";")[0]

            # Case A: query built into a String variable, then executed
            if arg in dyn_string_vars:
                info = dyn_string_vars[arg]
                src_line = info["line"]
                context = "\n".join(lines[max(0, src_line - 5):src_line])
                is_sql = bool(SQL_SHAPE.search(context) or SQL_KEYWORDS.search(info["value"]))
                f = Finding.from_rule(
                    "S-JAVA-SQLI", src_line, src_line, snippet(lines, src_line, src_line),
                    file_path,
                    f"Query built with concatenation (variable '{arg}') is passed to "
                    "execute*(); use PreparedStatement parameters."
                    if is_sql else
                    f"Dynamically built value '{arg}' passed to execute*(); verify it is "
                    "not user-molded and prefer PreparedStatement.",
                    AGENT, DETECTION, SECURITY["S-JAVA-SQLI"])
                compute_finding_score(f)
                findings.append(f)
                continue

            # Case B: concatenation happens inline inside the call
            if "+" not in arg_text:
                continue
            context = "\n".join(lines[max(0, i - 5):i])
            is_sql = bool(SQL_SHAPE.search(context) or SQL_KEYWORDS.search(context))
            f = Finding.from_rule(
                "S-JAVA-SQLI", i, i, snippet(lines, i, i), file_path,
                "String-concatenated query passed to Statement.execute*(); use "
                "PreparedStatement parameters instead."
                if is_sql else
                "Concatenated dynamic string passed to Statement.execute*(); verify the query "
                "is not user-molded and prefer PreparedStatement.",
                AGENT, DETECTION, SECURITY["S-JAVA-SQLI"])
            compute_finding_score(f)
            findings.append(f)
            break

        # --- Command Injection: Runtime.exec with a non-constant argument
        if "Runtime" in codepart and ".exec(" in codepart:
            open_idx = codepart.find(".exec(")
            close_idx = codepart.find(")", open_idx)
            arg_txt = codepart[open_idx + 6: close_idx if close_idx != -1 else len(codepart)]
            # safe only if the argument list is entirely string literals
            literal_only = re.fullmatch(
                r'\s*"[^"]*"(?:\s*,\s*"[^"]*")*\s*', arg_txt or "")
            if arg_txt and not literal_only:
                f = Finding.from_rule(
                    "S-JAVA-CMDI", i, i, snippet(lines, i, i), file_path,
                    "Runtime.exec with a non-constant command; use ProcessBuilder with a "
                    "fixed argument array.",
                    AGENT, DETECTION, SECURITY["S-JAVA-CMDI"])
                compute_finding_score(f)
                findings.append(f)

        # --- deserialization: ObjectInputStream declared on this or an
        # earlier line, then readObject() called (the common two-line usage)
        if "ObjectInputStream" in codepart:
            ois_declared = True
        if ".readObject(" in codepart and ois_declared:
            f = Finding.from_rule(
                "S-JAVA-DESER", i, i, snippet(lines, i, i), file_path,
                "ObjectInputStream.readObject() on an untrusted stream enables remote code "
                "execution; exchange explicit explicit-format data instead.",
                AGENT, DETECTION, SECURITY["S-JAVA-DESER"])
            compute_finding_score(f)
            findings.append(f)

        # --- XXE: parser factory created without entity hardening (once/file)
        if (not xxe_hardened_anywhere and not xxe_flagged and "newInstance" in codepart
                and re.search(r"\b(DocumentBuilderFactory|XMLInputFactory)\b", codepart)):
            f = Finding.from_rule(
                "S-JAVA-XXE", i, i, snippet(lines, i, i), file_path,
                "XML parser factory instantiated without disabling external entities/DTDs; "
                "set Feature ACCESS_EXTERNAL_* to empty strings.",
                AGENT, DETECTION, SECURITY["S-JAVA-XXE"])
            compute_finding_score(f)
            findings.append(f)
            xxe_flagged = True

        # --- broken crypto (MD5/SHA-1 digest, DES/DESede/RC4/AES-ECB cipher)
        crypto = re.search(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"', codepart, re.I) \
            or re.search(r'Cipher\.getInstance\(\s*"(DES|DESede|RC4)[^"]*"', codepart) \
            or re.search(r'Cipher\.getInstance\(\s*"(AES/ECB[^"]*)"', codepart, re.I)
        if crypto:
            f = Finding.from_rule(
                "S-JAVA-CRYPTO", i, i, snippet(lines, i, i), file_path,
                f"Insecure cryptographic primitive '{crypto.group(1)}'; use SHA-256+ digests "
                "and AES-GCM ciphers.",
                AGENT, DETECTION, SECURITY["S-JAVA-CRYPTO"])
            compute_finding_score(f)
            findings.append(f)

    findings.extend(_secret_lines(lines, file_path, "S-JAVA-SECRET"))

    # --- path traversal heuristic: new File(<variable>) without confinement
    for i, raw in enumerate(lines, 1):
        stripped = raw.split("//")[0]
        if re.search(r"new\s+File\((?!\s*\")", stripped):
            f = Finding.from_rule(
                "S-JAVA-PATH", i, i, snippet(lines, i, i), file_path,
                "File constructed from a variable without confinement; canonicalize and "
                "validate against a fixed base directory.",
                AGENT, DETECTION, SECURITY["S-JAVA-PATH"])
            compute_finding_score(f)
            findings.append(f)
            break

    # --- XSS output sink heuristic (narrow, heuristic_warning)
    if re.search(r'getWriter\(\)\.print(?:ln)?\s*\(\s*[a-z][\w$]*\s*\+', java_source) \
            or re.search(r'\.print(?:ln)?\s*\(\s*[a-z][\w$]*\s*\+\s*(?=request)', java_source, re.I):
        for i, raw in enumerate(lines, 1):
            if "getWriter" in raw and re.search(r"print(ln)?\(", raw):
                f = Finding.from_rule(
                    "S-JAVA-XSS", i, i, snippet(lines, i, i), file_path,
                    "Concatenated request data looks like a raw HTML output sink; "
                    "HTML-encode output (or let the templating engine escape).",
                    AGENT, DETECTION, SECURITY["S-JAVA-XSS"])
                compute_finding_score(f)
                findings.append(f)
                break
    return findings


# --- shared line-based secret detector (Python + Java) ----------------------

SECRET_ASSIGN_RE = re.compile(r"\w+\s*=\s*[\"'][^\"']{6,}[\"']")


def _secret_lines(lines, file_path: str, rule_id: str):
    for i, raw in enumerate(lines, 1):
        scrub = raw.split("//")[0].rstrip()
        if not SECRET_VAR_RE.search(scrub):
            continue
        if SECRET_PLACEHOLDERS.search(scrub):
            continue
        if not SECRET_ASSIGN_RE.search(scrub):
            continue
        f = Finding.from_rule(
            rule_id, i, i, snippet(lines, i, i), file_path,
            f"Credential-like string assigned to a sensitive-named variable on line {i}; "
            "load secrets from configuration/environment instead.",
            AGENT, DETECTION, SECURITY[rule_id])
        compute_finding_score(f)
        yield f


def _unused_alias(*_a):  # reserved for future confirmed=True data-flow pass
    return None
