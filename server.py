#!/usr/bin/env python3
"""
AI Code Review Platform — Code Submission Module API Server
Python and Java Syntax Validation Service (Strict Gatekeeper)

Endpoints:
  - POST /api/submissions         : Validate and store submission entity
  - POST /api/submissions/validate: Language check & syntax validator
  - GET  /api/health              : Liveness check
"""

import ast
import json
import hashlib
import sys
import uuid
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import re

# M2 analysis pipeline (additive; import failure degrades gracefully so the
# M1-only server can still run without analysis deps present)
try:
    from orchestrator import pipeline as orchestrator
    ORCHESTRATOR_AVAILABLE = True
except Exception as _orch_exc:  # pragma: no cover
    orchestrator = None
    ORCHESTRATOR_AVAILABLE = False
    _ORCHESTRATOR_ERROR = str(_orch_exc)

PORT = 8000

def classify_language(code: str, filename: str = "", target_lang: str = "auto") -> dict:
    """Classifies language and ensures ONLY Python and Java are accepted."""
    if filename:
        ext = filename.lower().split('.')[-1]
        if ext == 'py':
            return {"accepted": True, "language": "python", "name": "Python"}
        if ext == 'java':
            return {"accepted": True, "language": "java", "name": "Java"}
        return {
            "accepted": False,
            "language": ext,
            "name": ext.upper(),
            "reason": f"File extension .{ext} is not allowed. Only Python (.py) and Java (.java) are accepted."
        }

    # Heuristic checks for explicit other languages to reject them
    if re.search(r'\b(console\.(log|error|warn)|document\.getElementById|window\.|require\(|function\s*\(|=>\s*\{|\blet\s+[a-zA-Z0-9_$]+\s*=|\bconst\s+[a-zA-Z0-9_$]+\s*=)\b', code):
        return {"accepted": False, "language": "javascript", "name": "JavaScript", "reason": "Detected JavaScript/TypeScript syntax."}
    if re.search(r'(#include\s*<[a-zA-Z0-9_.]+>|std::cout|std::cin|printf\s*\(|malloc\s*\()', code):
        return {"accepted": False, "language": "c_cpp", "name": "C/C++", "reason": "Detected C/C++ syntax."}
    if re.search(r'(<\?php|\$_POST|\$_GET|\$this->)', code):
        return {"accepted": False, "language": "php", "name": "PHP", "reason": "Detected PHP syntax."}
    if re.search(r'(<!DOCTYPE\s+html|<html[\s>]|<div[\s>])', code, re.I):
        return {"accepted": False, "language": "html", "name": "HTML", "reason": "Detected HTML markup."}
    if re.search(r'\b(using\s+System(\.[a-zA-Z0-9_]+)*\s*;|Console\.WriteLine)\b', code):
        return {"accepted": False, "language": "csharp", "name": "C#", "reason": "Detected C# syntax."}
    if re.search(r'\b(SELECT\s+.*\s+FROM\b|INSERT\s+INTO\b|CREATE\s+TABLE\b)', code, re.I) and not re.search(r'(cursor\.execute|cur\.execute|stmt\.execute)', code):
        return {"accepted": False, "language": "sql", "name": "SQL", "reason": "Detected raw SQL query script."}

    # If the user or client explicitly chose Python or Java, honor that selection
    if target_lang in ("python", "java"):
        return {"accepted": True, "language": target_lang, "name": "Python" if target_lang == "python" else "Java"}

    # Python indicators (tolerant matching for incomplete or broken code)
    py_score = 0
    if re.search(r'^\s*def\s+[a-zA-Z_][a-zA-Z0-9_]*', code, re.M): py_score += 4
    if re.search(r'^\s*class\s+[a-zA-Z_][a-zA-Z0-9_]*', code, re.M) and "{" not in code: py_score += 3
    if re.search(r'^\s*import\s+[a-zA-Z_0-9]+|^\s*from\s+[a-zA-Z_0-9.]+\s+import', code, re.M): py_score += 4
    if re.search(r'\bprint\s*\(|\bprint\s+["\']', code): py_score += 3
    if re.search(r'^\s*(elif\b|except\b|finally\b)', code, re.M): py_score += 4
    if re.search(r'^\s*if\s+__name__\s*==\s*[\'"]__main__[\'"]', code, re.M): py_score += 5
    if re.search(r'\b(None|True|False)\b', code): py_score += 2
    if re.search(r'^\s*#.*$', code, re.M) and "//" not in code: py_score += 2
    if re.search(r':\s*$', code, re.M) and "{" not in code: py_score += 2
    if re.search(r'^\s*(if|for|while|try|with)\s+', code, re.M) and "{" not in code: py_score += 2

    # Java indicators (tolerant matching for incomplete or broken code)
    java_score = 0
    if re.search(r'\bpublic\s+(class|interface|enum|record)\b', code): java_score += 5
    if re.search(r'\bpublic\s+static\s+void\s+main\b', code): java_score += 5
    if re.search(r'\bSystem\.(out|err)\.(println|print|printf)\b', code): java_score += 5
    if re.search(r'\bimport\s+java\.', code): java_score += 4
    if re.search(r'\bpackage\s+[a-z0-9_.]+\s*;', code): java_score += 4
    if re.search(r'\b(private|protected|public)\s+[a-zA-Z0-9_<>[\]]+\s+[a-zA-Z0-9_]+\s*\(', code): java_score += 4
    if re.search(r'\b(String|int|boolean|double|float|long|byte|short|void)\b', code): java_score += 2
    if re.search(r';\s*$', code, re.M) and "{" in code: java_score += 3

    if java_score > py_score and java_score >= 2:
        return {"accepted": True, "language": "java", "name": "Java"}
    if py_score >= 2:
        return {"accepted": True, "language": "python", "name": "Python"}

    # Lenient fallback checks for broken code
    if java_score > 0 and ("{" in code or ";" in code):
        return {"accepted": True, "language": "java", "name": "Java"}
    if py_score > 0 or ("def " in code) or (":" in code and "{" not in code):
        return {"accepted": True, "language": "python", "name": "Python"}

    # Default to Python if no conflicting foreign signatures detected
    return {
        "accepted": True,
        "language": "python",
        "name": "Python"
    }

def validate_python_ast(code: str) -> dict:
    """Validates Python syntax using Python's standard ast module and pinpoints missing items."""
    if not code or not code.strip():
        return {
            "valid": False,
            "rejected_code": True,
            "rejection_reason": "empty_input",
            "has_missing_item": True,
            "errors": [{
                "line": 1,
                "col": 1,
                "message": "SyntaxError: Empty code submission",
                "rule": "empty_input",
                "is_missing_item": True,
                "missing_item": "code content",
                "missing_detail": "No code provided. Please paste or upload Python code.",
                "hint": "Paste valid Python source code to analyze."
            }],
            "warnings": []
        }
    try:
        ast.parse(code)
        return {
            "valid": True,
            "rejected_code": False,
            "has_missing_item": False,
            "errors": [],
            "warnings": []
        }
    except SyntaxError as e:
        msg = str(e.msg) if e.msg else "Syntax error"
        line_num = e.lineno or 1
        col_num = e.offset or 1
        line_text = e.text.strip() if e.text else ""

        # Analyze error message and line content to detect missing items
        is_missing_item = False
        missing_item = None
        missing_detail = None
        rule = "syntax_error"
        hint = "Review code syntax around this line."

        # Case 1: Unclosed delimiter
        if "was never closed" in msg:
            m = re.search(r"'(.)' was never closed", msg)
            opened_char = m.group(1) if m else "("
            closing_map = {'(': ')', '[': ']', '{': '}'}
            expected_char = closing_map.get(opened_char, ')')
            is_missing_item = True
            missing_item = f"closing '{expected_char}'"
            rule = "unclosed_delimiter"
            missing_detail = f"Unclosed '{opened_char}' on line {line_num} - missing closing '{expected_char}'."
            hint = f"Add matching closing '{expected_char}' to balance the expression."

        # Case 2: Missing colon ':'
        elif "expected ':'" in msg or (re.search(r'^\s*(def|class|if|elif|else|for|while|try|except|finally|with|async\s+def|async\s+for|async\s+with)\b', line_text) and not line_text.endswith(':')):
            is_missing_item = True
            missing_item = "':' (colon)"
            rule = "missing_colon"
            missing_detail = f"Missing ':' at end of statement '{line_text}' on line {line_num}."
            hint = "Python compound statements ('def', 'if', 'for', 'class', etc.) must end with a colon ':'."

        # Case 3: Missing indented block
        elif "expected an indented block" in msg:
            is_missing_item = True
            missing_item = "indented block body"
            rule = "missing_block_body"
            missing_detail = f"Missing indented block statement body after line {line_num}."
            hint = "Provide at least one indented statement inside the block, or use 'pass' as a placeholder."

        # Case 4: Unterminated string literal
        elif "unterminated string literal" in msg or "EOL while scanning string literal" in msg:
            is_missing_item = True
            missing_item = "closing quote (' or \")"
            rule = "unterminated_string"
            missing_detail = f"String literal on line {line_num} is missing closing quotation mark."
            hint = "Ensure quotation marks match and are closed before the end of the line, or use triple quotes for multi-line strings."

        # Case 5: Incomplete expression (e.g. 'x = 10 +' or 'x =')
        elif "invalid syntax" in msg and re.search(r'[\+\-\*\/\=\,\<\>\&\|\^]\s*$', line_text):
            is_missing_item = True
            missing_item = "operand / value expression"
            rule = "incomplete_expression"
            missing_detail = f"Incomplete expression ending with an operator on line {line_num}."
            hint = "Complete the expression by supplying the missing right-hand operand or value."

        elif isinstance(e, IndentationError):
            rule = "indentation_error"
            hint = "Check indentation level; ensure consistent use of 4 spaces."

        error_item = {
            "line": line_num,
            "col": col_num,
            "message": f"SyntaxError: {msg}",
            "text": line_text,
            "snippet": line_text,
            "rule": rule,
            "is_missing_item": is_missing_item,
            "missing_item": missing_item,
            "missing_detail": missing_detail,
            "hint": hint
        }

        return {
            "valid": False,
            "rejected_code": True,
            "rejection_reason": "missing_item" if is_missing_item else "incorrect_code",
            "has_missing_item": is_missing_item,
            "errors": [error_item],
            "warnings": []
        }
    except Exception as e:
        return {
            "valid": False,
            "rejected_code": True,
            "rejection_reason": "parsing_error",
            "has_missing_item": False,
            "errors": [{
                "line": 1,
                "col": 1,
                "message": f"ParsingError: {str(e)}",
                "rule": "parsing_error",
                "is_missing_item": False,
                "missing_item": None,
                "missing_detail": None,
                "hint": "Check Python syntax."
            }],
            "warnings": []
        }

def validate_java_syntax(code: str) -> dict:
    """Lightweight deterministic syntax check for Java source files with missing item detection."""
    if not code or not code.strip():
        return {
            "valid": False,
            "rejected_code": True,
            "rejection_reason": "empty_input",
            "has_missing_item": True,
            "errors": [{
                "line": 1,
                "col": 1,
                "message": "SyntaxError: Empty code submission",
                "rule": "empty_input",
                "is_missing_item": True,
                "missing_item": "code content",
                "missing_detail": "No code provided. Please paste or upload Java code.",
                "hint": "Paste valid Java source code to analyze."
            }],
            "warnings": []
        }

    lines = code.split("\n")
    errors = []
    warnings = []
    stack = []
    
    in_block_comment = False
    in_string = False

    for idx, line in enumerate(lines):
        line_num = idx + 1
        i = 0
        while i < len(line):
            rest = line[i:]
            ch = line[i]

            if not in_string and not in_block_comment and rest.startswith("/*"):
                in_block_comment = True
                i += 2
                continue
            if in_block_comment:
                if rest.startswith("*/"):
                    in_block_comment = False
                    i += 2
                else:
                    i += 1
                continue
            if not in_string and rest.startswith("//"):
                break
            if ch == '\\' and in_string:
                i += 2
                continue
            if ch == '"':
                in_string = not in_string
                i += 1
                continue
            if in_string:
                i += 1
                continue

            if ch in "({[":
                stack.append((ch, line_num, i + 1))
            elif ch in ")}]":
                if not stack:
                    errors.append({
                        "line": line_num,
                        "col": i + 1,
                        "message": f"SyntaxError: unmatched closing '{ch}'",
                        "rule": "unmatched_closing_delimiter",
                        "snippet": line.strip(),
                        "is_missing_item": False,
                        "missing_item": None,
                        "missing_detail": None,
                        "hint": f"Remove extra closing '{ch}' or add matching opening bracket."
                    })
                else:
                    top_char, top_line, top_col = stack.pop()
                    match = {'(': ')', '[': ']', '{': '}'}
                    if match.get(top_char) != ch:
                        errors.append({
                            "line": line_num,
                            "col": i + 1,
                            "message": f"SyntaxError: mismatched delimiter '{ch}', expected '{match.get(top_char)}' for '{top_char}' on line {top_line}",
                            "rule": "mismatched_delimiter",
                            "snippet": line.strip(),
                            "is_missing_item": False,
                            "missing_item": None,
                            "missing_detail": None,
                            "hint": f"Replace '{ch}' with '{match.get(top_char)}' to match line {top_line}."
                        })
            i += 1

        if in_string:
            errors.append({
                "line": line_num,
                "col": len(line),
                "message": "SyntaxError: unclosed string literal at EOL",
                "rule": "unclosed_string_literal",
                "snippet": line.strip(),
                "is_missing_item": True,
                "missing_item": 'closing quotation mark (")',
                "missing_detail": f"Unclosed string literal on line {line_num} - missing closing quote.",
                "hint": 'Close the string literal with a double quote (") before the end of line.'
            })
            in_string = False

        stripped = re.sub(r'//.*$', '', line).strip()
        if stripped and not in_block_comment:
            if re.match(r'^(return\b|throw\b|package\b|import\b|assert\b|[a-zA-Z0-9_<>[\]]+\s+[a-zA-Z0-9_]+\s*=|System\.(out|err)\.)', stripped):
                if not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}'):
                    errors.append({
                        "line": line_num,
                        "col": len(stripped) + 1,
                        "message": "SyntaxError: ';' expected",
                        "rule": "missing_semicolon",
                        "snippet": stripped,
                        "is_missing_item": True,
                        "missing_item": "';' (semicolon)",
                        "missing_detail": f"Missing ';' at end of statement '{stripped}' on line {line_num}.",
                        "hint": "Java statements must terminate with a semicolon ';'."
                    })

        if errors:
            break

    if not errors and in_block_comment:
        errors.append({
            "line": len(lines),
            "col": 1,
            "message": "SyntaxError: unclosed block comment (expected */)",
            "rule": "unclosed_comment",
            "snippet": lines[-1].strip(),
            "is_missing_item": True,
            "missing_item": "*/ (closing comment delimiter)",
            "missing_detail": "Multi-line comment was opened but never closed with '*/'.",
            "hint": "Add '*/' to close the block comment."
        })

    if not errors:
        while stack:
            top_char, top_line, top_col = stack.pop()
            closing_map = {'(': ')', '[': ']', '{': '}'}
            exp = closing_map.get(top_char, ')')
            errors.append({
                "line": top_line,
                "col": top_col,
                "message": f"SyntaxError: '{top_char}' was never closed (missing '{exp}')",
                "rule": "unclosed_delimiter",
                "snippet": lines[top_line - 1].strip() if top_line <= len(lines) else "",
                "is_missing_item": True,
                "missing_item": f"closing '{exp}'",
                "missing_detail": f"Missing closing '{exp}' to balance '{top_char}' opened on line {top_line}.",
                "hint": f"Add matching '{exp}' to close the block or expression."
            })

    if not re.search(r'\b(class|interface|enum|record)\s+[a-zA-Z_][a-zA-Z0-9_]*', code):
        warnings.append("Notice: No class, interface, or record definition detected. Standard Java files require an enclosing class/type.")

    has_missing_item = any(e.get("is_missing_item") for e in errors)
    return {
        "valid": len(errors) == 0,
        "rejected_code": len(errors) > 0,
        "rejection_reason": ("missing_item" if has_missing_item else "incorrect_code") if errors else None,
        "has_missing_item": has_missing_item,
        "errors": errors,
        "warnings": warnings
    }

class SubmissionHandler(BaseHTTPRequestHandler):
    # ---- M2 additive routes (no change to any M1 behavior) ----

    def _m2_handle_analysis_post(self, body):
        """POST /api/analysis - run the multi-agent pipeline (M2 additive)."""
        code = body.get("code", "")
        language = (body.get("language") or "auto").lower()
        filename = body.get("filename", "")

        # Same gatekeeper as M1
        lang_info = classify_language(code, filename, target_lang=language)
        if not lang_info["accepted"]:
            self.send_response(422)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "unsupported_language",
                "message": lang_info.get("reason", "Only Python and Java are accepted."),
            }).encode("utf-8"))
            return
        target_lang = lang_info["language"]

        # Same syntax gate as M1: no analysis run on rejected code
        if target_lang == "python":
            val_result = validate_python_ast(code)
        else:
            val_result = validate_java_syntax(code)
        if not val_result["valid"]:
            self.send_response(422)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "syntax_error",
                "message": "Code must pass syntax validation before analysis.",
                "syntax_errors": val_result["errors"],
            }).encode("utf-8"))
            return

        try:
            run_id = orchestrator.analyze_code(code, target_lang, filename)
        except Exception as exc:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "pipeline_failure", "message": str(exc)}).encode("utf-8"))
            return

        state = orchestrator.get_run(run_id)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(orchestrator.run_summary(state)).encode("utf-8"))

    def _m2_send_analysis_not_found(self):
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": "run_not_found"}).encode("utf-8"))
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        # Root: JSON service index (the browser page people find at the bare URL).
        # The React UI is NOT served here -- it runs separately on port 5173.
        if self.path.split("?", 1)[0] == "/":
            info = {
                "service": "AI Code Review Platform -- Code Submission & Syntax Validation API",
                "status": "running",
                "note": "This is the REST API server. The React developer UI is a separate app: run 'npm run dev' in code-submission-ui/ and open http://localhost:5173.",
                "endpoints": {
                    "POST /api/submissions": "Validate and store a submission entity",
                    "POST /api/submissions/validate": "Language gate + syntax validation",
                    "POST /api/analysis": "Multi-agent quality/security analysis run",
                    "GET /api/analysis/<run_id>": "Analysis run status summary",
                    "GET /api/analysis/<run_id>/findings": "Findings (?category=&severity= filters)",
                    "GET /api/health": "Liveness check",
                },
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(info).encode("utf-8"))
            return

        # ---- M2 additive GET routes (M1 /api/health unchanged below) ----
        if self.path.startswith("/api/analysis/"):
            from urllib.parse import urlsplit, parse_qs
            parts = urlsplit(self.path)
            segments = [s for s in parts.path.split("/") if s]
            run_id = segments[2] if len(segments) > 2 else ""
            subsection = segments[3] if len(segments) > 3 else ""
            state = orchestrator.get_run(run_id) if run_id else None
            if state is None:
                self._m2_send_analysis_not_found()
                return
            if subsection == "findings":
                params = parse_qs(parts.query)
                category = (params.get("category") or [None])[0]
                severity = (params.get("severity") or [None])[0]
                findings_payload = [f.to_dict() for f in state.merged_findings]
                if category:
                    findings_payload = [f for f in findings_payload if f["category"] == category]
                if severity:
                    findings_payload = [f for f in findings_payload if f["severity"] == severity]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "run_id": state.run_id,
                    "count": len(findings_payload),
                    "findings": findings_payload,
                }).encode("utf-8"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(orchestrator.run_summary(state)).encode("utf-8"))
            return

        if self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            response = {
                "status": "healthy",
                "service": "Code Submission & Syntax Validation API",
                "timestamp": datetime.utcnow().isoformat()
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON body"}).encode("utf-8"))
            return

        # ---- M2 additive route (runs before M1 logic; M1 paths unchanged) ----
        if self.path == "/api/analysis":
            if not ORCHESTRATOR_AVAILABLE:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "analysis_unavailable",
                    "message": "Analysis pipeline not loaded: " + _ORCHESTRATOR_ERROR[:200],
                }).encode("utf-8"))
                return
            # size guards consistent with the M1 line/KB submission limits
            code_size = len(body.get("code", "").encode("utf-8"))
            line_count = len(body.get("code", "").split("\n"))
            if code_size > 200 * 1024 or line_count > 2000:
                self.send_response(413)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "payload_too_large",
                    "message": "Submission exceeds the 200 KB / 2000-line analysis limit.",
                }).encode("utf-8"))
                return
            self._m2_handle_analysis_post(body)
            return
        # ---------------- end M2 additive route ----------------

        code = body.get("code", "")
        language = (body.get("language") or "auto").lower()
        source_type = body.get("source_type", "paste")
        filename = body.get("filename", "")


        # 1. Gatekeeper check
        lang_info = classify_language(code, filename, target_lang=language)
        if not lang_info["accepted"]:
            self.send_response(422)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            response = {
                "valid": False,
                "rejected_language": True,
                "rejected_code": True,
                "rejection_reason": "unsupported_language",
                "has_missing_item": False,
                "language": lang_info["language"],
                "language_name": lang_info["name"],
                "message": f"This code is not acceptable as it is from a different language ({lang_info['name']}). Only Python and Java are accepted.",
                "errors": [{
                    "line": 1,
                    "col": 1,
                    "message": f"Code rejected: Unsupported language ({lang_info['name']}). Only Python and Java are accepted.",
                    "rule": "unsupported_language",
                    "is_missing_item": False,
                    "missing_item": None,
                    "missing_detail": None,
                    "hint": "Please submit Python (.py) or Java (.java) code."
                }]
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
            return

        target_lang = lang_info["language"]

        # 2. Syntax validation (only executed if within line limits)
        if target_lang == "python":
            val_result = validate_python_ast(code)
        else:
            val_result = validate_java_syntax(code)

        if self.path == "/api/submissions/validate":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            val_result["language"] = target_lang
            val_result["language_name"] = lang_info["name"]
            self.wfile.write(json.dumps(val_result).encode("utf-8"))
            return

        if self.path == "/api/submissions":
            code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
            submission = {
                "id": str(uuid.uuid4()),
                "source_type": source_type,
                "filename": filename,
                "language": target_lang,
                "code": code,
                "code_hash": code_hash,
                "line_count": len(code.split("\n")),
                "size_bytes": len(code.encode("utf-8")),
                "syntax_valid": val_result["valid"],
                "rejected_code": val_result.get("rejected_code", not val_result["valid"]),
                "rejection_reason": val_result.get("rejection_reason"),
                "has_missing_item": val_result.get("has_missing_item", False),
                "syntax_errors": val_result["errors"],
                "created_at": datetime.utcnow().isoformat()
            }

            self.send_response(201 if val_result["valid"] else 422)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(submission).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

class AnalysisHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer used by the real server (tests boot the same class).

    A single analysis request runs synchronously in its request thread and can
    take seconds-to-minutes (Bandit subprocess, PMD JVM run, first-run PMD
    download). The previous single-threaded HTTPServer made every queued
    request -- including GET /api/health -- wait for it, which caused the
    observed health-hang. Threads also mean a client disconnect (browser tab
    closed mid-response: WinError 10053 / ConnectionReset / BrokenPipe) cannot
    wedge the server, and such disconnects are logged quietly instead of as a
    full traceback because they are not server faults.
    """

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionAbortedError,
                                          ConnectionResetError, BrokenPipeError)):
            return  # client went away mid-response; next request is unaffected
        super().handle_error(request, client_address)


def build_analysis_server(server_address):
    """Single construction point for the live server (tests reuse this)."""
    return AnalysisHTTPServer(server_address, SubmissionHandler)


def main():
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

    server_address = ("", PORT)
    httpd = build_analysis_server(server_address)
    print(f"[READY] Code Submission Validation API Server running on http://localhost:{PORT}")
    print(f"   - POST /api/submissions (Full Submission Model)")
    print(f"   - POST /api/submissions/validate (Syntax Check)")
    print(f"   - GET  /api/health (Health Check)")
    if ORCHESTRATOR_AVAILABLE:
        print(f"   - POST /api/analysis (Multi-Agent Code Analysis)")
        print(f"   - GET  /api/analysis/<run_id> (Run Status)")
        print(f"   - GET  /api/analysis/<run_id>/findings (Findings)")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
