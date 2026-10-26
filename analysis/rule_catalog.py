"""Rule catalog: single source of truth for every M2 detector rule.

Each rule defines the metadata the finding schema needs. The severity engine
and both agents read from these tables so no agent hardcodes impact scores.
(base impacts and confidence tiers follow docs/severity_scoring.md)
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    title: str
    category: str                     # "security" | "quality"
    finding_kind: str                 # "vulnerability" | "heuristic_warning"
    base_impact: float                # 0-10 deterministic weight, see docs/severity_scoring.md
    confidence: float                 # heuristic certainty tier (0-1), NOT a probability
    cwe_id: str | None = None
    owasp_category: str | None = None
    remediation: str | None = None


QUALITY = {
    "Q-long-method": RuleSpec(
        "Q-long-method", "Long Method", "quality", "heuristic_warning",
        base_impact=3.5, confidence=0.9,
        remediation="Extract cohesive blocks of this method into smaller named helpers.",
    ),
    "Q-large-class": RuleSpec(
        "Q-large-class", "Large Class", "quality", "heuristic_warning",
        base_impact=3.0, confidence=0.8,
        remediation="Split the class around distinct responsibilities.",
    ),
    "Q-long-param-list": RuleSpec(
        "Q-long-param-list", "Long Parameter List", "quality", "heuristic_warning",
        base_impact=2.5, confidence=0.9,
        remediation="Group parameters into an options/arguments object.",
    ),
    "Q-high-complexity": RuleSpec(
        "Q-high-complexity", "High Cyclomatic Complexity", "quality", "heuristic_warning",
        base_impact=4.0, confidence=0.9,
        remediation="Replace nested if/loops with early returns, guard clauses or lookup tables.",
    ),
    "Q-deep-nesting": RuleSpec(
        "Q-deep-nesting", "Deep Nesting", "quality", "heuristic_warning",
        base_impact=3.0, confidence=0.9,
        remediation="Flatten nesting with early returns/guard clauses; extract inner blocks.",
    ),
    "Q-broad-exception": RuleSpec(
        "Q-broad-exception", "Broad Exception Handling", "quality", "heuristic_warning",
        base_impact=2.5, confidence=0.9,
        cwe_id="CWE-703",
        remediation="Catch specific exception types; bare/broad except swallows real errors.",
    ),
    "Q-magic-number": RuleSpec(
        "Q-magic-number", "Magic Number", "quality", "heuristic_warning",
        base_impact=1.5, confidence=0.7,
        remediation="Name the constant (e.g. DAYS_PER_WEEK = 7) and reuse it.",
    ),
    "Q-unused-import": RuleSpec(
        "Q-unused-import", "Unused Import", "quality", "heuristic_warning",
        base_impact=1.5, confidence=0.9,
        remediation="Remove the unused import to keep the module surface minimal.",
    ),
    "Q-unused-variable": RuleSpec(
        "Q-unused-variable", "Unused Variable", "quality", "heuristic_warning",
        base_impact=1.5, confidence=0.8,
        remediation="Remove the dead assignment or return/use the value.",
    ),
    "Q-pmd-generic": RuleSpec(
        "Q-pmd-generic", "Java Design/Quality Violation", "quality", "heuristic_warning",
        base_impact=2.5, confidence=0.8,
        remediation="See the referenced PMD rule documentation.",
    ),
}

SECURITY = {
    "S-PY-SQLI": RuleSpec(
        "S-PY-SQLI", "SQL Injection", "security", "vulnerability",
        base_impact=9.4, confidence=0.9, cwe_id="CWE-89", owasp_category="A03:2021 Injection",
        remediation="Use parameterized queries (cursor.execute(sql, params)) instead of building SQL by concatenation/f-string.",
    ),
    "S-PY-CMDI": RuleSpec(
        "S-PY-CMDI", "Command Injection", "security", "vulnerability",
        base_impact=9.6, confidence=0.9, cwe_id="CWE-78", owasp_category="A03:2021 Injection",
        remediation="Avoid os.system/popen with user data; use subprocess.run with an argument list and shell=False.",
    ),
    "S-PY-SHELL": RuleSpec(
        "S-PY-SHELL", "subprocess Call With shell=True", "security", "vulnerability",
        base_impact=9.5, confidence=0.85, cwe_id="CWE-78", owasp_category="A03:2021 Injection",
        remediation="Pass the command as a list argument and keep shell=False.",
    ),
    "S-PY-EVAL": RuleSpec(
        "S-PY-EVAL", "Dangerous eval/exec/compile", "security", "vulnerability",
        base_impact=9.3, confidence=0.9, cwe_id="CWE-95", owasp_category="A03:2021 Injection",
        remediation="Never evaluate code built from input data; use safe parsing/alternatives.",
    ),
    "S-PY-DESER": RuleSpec(
        "S-PY-DESER", "Insecure Deserialization (pickle/yaml.load)", "security", "vulnerability",
        base_impact=9.0, confidence=0.9, cwe_id="CWE-502", owasp_category="A08:2021 Software and Data Integrity Failures",
        remediation="Avoid pickle/yaml.load on untrusted data; use json, or yaml.safe_load.",
    ),
    "S-PY-CRYPTO": RuleSpec(
        "S-PY-CRYPTO", "Insecure Cryptographic Hash", "security", "vulnerability",
        base_impact=5.5, confidence=0.85, cwe_id="CWE-327", owasp_category="A02:2021 Cryptographic Failures",
        remediation="Replace MD5/SHA-1 with SHA-256+ (or bcrypt/argon2 for passwords).",
    ),
    "S-PY-SECRET": RuleSpec(
        "S-PY-SECRET", "Hardcoded Secret", "security", "heuristic_warning",
        base_impact=8.4, confidence=0.6, cwe_id="CWE-798", owasp_category="A02:2021 Cryptographic Failures",
        remediation="Move secrets to environment variables or a secret manager; never commit credentials.",
    ),
    "S-PY-PATH": RuleSpec(
        "S-PY-PATH", "Potential Path Traversal", "security", "heuristic_warning",
        base_impact=7.0, confidence=0.6, cwe_id="CWE-22", owasp_category="A01:2021 Broken Access Control",
        remediation="Validate/canonicalize file paths and confine access to a fixed base directory.",
    ),
    "S-JAVA-SQLI": RuleSpec(
        "S-JAVA-SQLI", "SQL Injection (Statement.concatenation)", "security", "vulnerability",
        base_impact=9.4, confidence=0.9, cwe_id="CWE-89", owasp_category="A03:2021 Injection",
        remediation="Use PreparedStatement with parameter placeholders (?,?,?,?,...).",
    ),
    "S-JAVA-CMDI": RuleSpec(
        "S-JAVA-CMDI", "Command Injection (Runtime.exec)", "security", "vulnerability",
        base_impact=9.6, confidence=0.85, cwe_id="CWE-78", owasp_category="A03:2021 Injection",
        remediation="Use ProcessBuilder with an argument array of validated, fixed values.",
    ),
    "S-JAVA-DESER": RuleSpec(
        "S-JAVA-DESER", "Insecure Deserialization (ObjectInputStream)", "security", "vulnerability",
        base_impact=9.0, confidence=0.9, cwe_id="CWE-502", owasp_category="A08:2021 Software and Data Integrity Failures",
        remediation="Do not deserialize untrusted streams; use explicit data formats for relational data.",
    ),
    "S-JAVA-XXE": RuleSpec(
        "S-JAVA-XXE", "XML External Entity (XXE) Risk", "security", "vulnerability",
        base_impact=7.5, confidence=0.7, cwe_id="CWE-611", owasp_category="A05:2021 Security Misconfiguration",
        remediation="Disable external entities/DTDs on the XML parser via setFeature(ACCESS_EXTERNAL_DTD/ENTITY, \"\").",
    ),
    "S-JAVA-CRYPTO": RuleSpec(
        "S-JAVA-CRYPTO", "Insecure Cryptographic Primitive", "security", "vulnerability",
        base_impact=5.5, confidence=0.85, cwe_id="CWE-327", owasp_category="A02:2021 Cryptographic Failures",
        remediation="Use SHA-256+ for digests; AES-GCM with SecureRandom for ciphers.",
    ),
    "S-JAVA-SECRET": RuleSpec(
        "S-JAVA-SECRET", "Hardcoded Secret", "security", "heuristic_warning",
        base_impact=8.4, confidence=0.6, cwe_id="CWE-798", owasp_category="A02:2021 Cryptographic Failures",
        remediation="Load credentials from environment/config stored outside the source tree.",
    ),
    "S-JAVA-PATH": RuleSpec(
        "S-JAVA-PATH", "Potential Path Traversal", "security", "heuristic_warning",
        base_impact=7.0, confidence=0.6, cwe_id="CWE-22", owasp_category="A01:2021 Broken Access Control",
        remediation="Canonicalize & validate paths; confine access to a fixed base directory.",
    ),
    "S-JAVA-XSS": RuleSpec(
        "S-JAVA-XSS", "Potential XSS Output Sink", "security", "heuristic_warning",
        base_impact=7.0, confidence=0.5, cwe_id="CWE-79", owasp_category="A03:2021 Injection",
        remediation="HTML-encode output or use a template engine that escapes by default.",
    ),
    "S-BANDIT-GENERIC": RuleSpec(
        "S-BANDIT-GENERIC", "Bandit Finding", "security", "vulnerability",
        base_impact=7.5, confidence=0.8, cwe_id=None, owasp_category=None,
        remediation=None,
    ),
}

ALL_RULES = {**QUALITY, **SECURITY}
