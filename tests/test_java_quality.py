"""Phase 1 tests: Java quality detectors (detections + line locations).
PMD download is disabled for the test run; custom javalang detectors must
carry the load on their own."""
import os
import pytest

os.environ.setdefault("PMD_DISABLE_DOWNLOAD", "1")

from analysis.java_quality import analyze_java_quality

CLEAN_JAVA = '''package demo;

import java.sql.Connection;

public class CleanService {
    public int add(Connection conn, int a, int b) {
        int total = a + b;
        return total;
    }
}
'''

SMELLY_JAVA = '''package demo;

import java.util.List;

public class ProfileService {
    public void update(String a, String b, String c, String d, String e, String f, String g) {
        String stale = "old";
        if (a != null) {
            if (b != null) {
                if (c != null) {
                    if (d != null) {
                        if (e != null) {
                            System.out.println("deep");
                        }
                    }
                }
            }
        }
    }
}
'''


def findings_by_rule(result, rule_id):
    return [f for f in result["findings"] if f.rule_id == rule_id]


def test_clean_java_zero_false_positives():
    result = analyze_java_quality(CLEAN_JAVA, "CleanService.java")
    assert result["metrics"]["parsed"] is True
    assert result["findings"] == [], "clean Java fixture must produce NO findings"


def test_java_unused_import_detected_with_line():
    result = analyze_java_quality(SMELLY_JAVA, "ProfileService.java")
    unused = findings_by_rule(result, "Q-unused-import")
    assert len(unused) == 1      # List unused
    assert unused[0].line_start == 3


def test_java_long_parameter_list_detected():
    result = analyze_java_quality(SMELLY_JAVA, "ProfileService.java")
    params = findings_by_rule(result, "Q-long-param-list")
    assert len(params) == 1
    assert params[0].line_start == 6


def test_java_deep_nesting_detected():
    result = analyze_java_quality(SMELLY_JAVA, "ProfileService.java")
    deep = findings_by_rule(result, "Q-deep-nesting")
    assert len(deep) == 1
    assert deep[0].line_start == 6


def test_java_unused_variable_detected_with_line():
    result = analyze_java_quality(SMELLY_JAVA, "ProfileService.java")
    unused = findings_by_rule(result, "Q-unused-variable")
    assert {f.line_start for f in unused} == {7}


def test_java_parse_failure_is_reported_not_crash():
    result = analyze_java_quality("public class Broken {", "Broken.java")
    assert result["metrics"]["parsed"] is False
    assert result["findings"] == []
