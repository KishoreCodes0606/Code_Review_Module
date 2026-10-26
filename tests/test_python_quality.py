"""Phase 1 tests: Python quality detectors (detections + line locations)."""
from analysis.python_metrics import analyze_python_quality

CLEAN_PY = '''"""Clean module."""


def add(a, b):
    return a + b


def divide(a, b):
    if b == 0:
        raise ValueError("division by zero")
    return a // b
'''

SMELLY_PY = '''import os
import json


def run(a, b, c, d, e, f, g):
    temp = 42
    try:
        if a:
            if b:
                if c:
                    if d:
                        if e:
                            return os.getcwd()
    except:
        pass
    return g
'''

SMELLY_MAGIC_PY = '''def compute_discount(price):
    discount = price * 100 + 100 + 100
    return discount - 100
'''


def findings_by_rule(result, rule_id):
    return [f for f in result["findings"] if f.rule_id == rule_id]


def test_clean_code_has_no_quality_findings():
    result = analyze_python_quality(CLEAN_PY, "clean.py")
    assert result["metrics"]["parsed"] is True
    assert result["findings"] == [], "clean fixture must produce ZERO false positives"


def test_unused_import_detected_with_line():
    result = analyze_python_quality(SMELLY_PY, "smelly.py")
    unused = findings_by_rule(result, "Q-unused-import")
    assert len(unused) == 1          # os is used, json is not
    assert unused[0].line_start == 2


def test_unused_variable_detected_with_line():
    result = analyze_python_quality(SMELLY_PY, "smelly.py")
    unused = findings_by_rule(result, "Q-unused-variable")
    assert {f.line_start for f in unused} == {6}   # 'temp = 42'


def test_long_parameter_list_detected():
    result = analyze_python_quality(SMELLY_PY, "smelly.py")
    long_params = findings_by_rule(result, "Q-long-param-list")
    assert len(long_params) == 1
    assert long_params[0].line_start == 5     # reported at the 'def' header


def test_deep_nesting_detected():
    result = analyze_python_quality(SMELLY_PY, "smelly.py")
    deep = findings_by_rule(result, "Q-deep-nesting")
    assert len(deep) == 1
    assert deep[0].line_start == 5            # reported at the 'def' header


def test_broad_exception_detected_at_except_line():
    result = analyze_python_quality(SMELLY_PY, "smelly.py")
    broad = findings_by_rule(result, "Q-broad-exception")
    assert len(broad) == 1
    assert broad[0].line_start == 14


def test_magic_number_repeated_detected():
    result = analyze_python_quality(SMELLY_MAGIC_PY, "magic.py")
    assert len(findings_by_rule(result, "Q-magic-number")) == 1


def test_finding_schema_shape():
    result = analyze_python_quality(SMELLY_PY, "smelly.py")
    f = result["findings"][0]
    for field in ("id", "category", "rule_id", "title", "description",
                  "finding_kind", "detection", "severity", "severity_score",
                  "confidence", "file_path", "line_start", "line_end",
                  "code_snippet", "source_agent"):
        assert hasattr(f, field), f"missing schema field {field}"
    assert f.category == "quality"
    assert f.finding_kind == "heuristic_warning"
    assert f.source_agent == "code_analysis_agent"
    assert f.file_path == "smelly.py"
    assert 0.0 <= f.severity_score <= 10.0
    assert f.severity in ("critical", "high", "medium", "low", "info")
