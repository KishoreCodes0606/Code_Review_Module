"""Phase 2 tests: security detectors — expected detections, exact line
locations, and zero findings on clean code."""
from analysis.security_rules import analyze_python_security, analyze_java_security

CLEAN_PY = '''import sqlite3


def get_user(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    return cur.fetchone()
'''

PY_SQLI_CONCAT = '''import sqlite3


def get_user(conn, uid):
    cur = conn.cursor()
    q = "SELECT * FROM users WHERE id=" + uid
    cur.execute(q)
'''

PY_SQLI_FSTRING = '''import sqlite3


def update_status(conn, uid, active):
    cur = conn.cursor()
    sql = f"UPDATE users SET active = {active} WHERE id = '{uid}'"
    cur.execute(sql)
'''

PY_SINKS = '''import os
import pickle
import yaml
import hashlib


def bad(data):
    os.system("ls " + data)
    pickle.loads(data)
    yaml.load(data, Loader=yaml.UnsafeLoader)
    return hashlib.md5(data).hexdigest()
'''

PY_SECRETS = '''def connect():
    api_key = "sk-a8f3jdh3dh3d9fj2k"
    config = {"password": os.environ.get("PW")}
    return api_key
'''

JAVA_SQLI = '''package com.example.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class AccountDAO {

    public ResultSet findAccount(Connection conn, String acctId) {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM accounts WHERE id = '" + acctId + "'";
        return stmt.executeQuery(sql);
    }
}
'''

JAVA_SECCO = '''package com.example;

import java.security.MessageDigest;

public class CryptoUtil {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
'''

JAVA_CLEAN = '''package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserDao {
    public ResultSet find(Connection conn, String id) throws Exception {
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        return ps.executeQuery();
    }
}
'''


def findings_by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# --- Python -----------------------------------------------------------------

def test_python_clean_zero_findings():
    assert analyze_python_security(CLEAN_PY, "clean/repo.py") == [], \
        "parameterized query must NOT be flagged (false-positive guard)"


def test_python_sqli_concat_detected_at_assign_line():
    findings = analyze_python_security(PY_SQLI_CONCAT, "user_repository.py")
    sqli = findings_by_rule(findings, "S-PY-SQLI")
    assert len(sqli) == 1
    assert sqli[0].line_start == 6     # the dynamic SQL construction line
    assert sqli[0].cwe_id == "CWE-89"
    assert sqli[0].owasp_category == "A03:2021 Injection"
    assert sqli[0].finding_kind == "vulnerability"
    assert sqli[0].severity == "critical"
    assert sqli[0].severity_score == 9.4


def test_python_sqli_fstring_detected():
    findings = analyze_python_security(PY_SQLI_FSTRING, "user_repository.py")
    sqli = findings_by_rule(findings, "S-PY-SQLI")
    assert len(sqli) == 1
    assert sqli[0].line_start == 6


def test_python_sinks_detected_with_correct_lines():
    findings = analyze_python_security(PY_SINKS, "bag.py")
    assert {f.line_start for f in findings_by_rule(findings, "S-PY-CMDI")} == {8}
    assert {f.line_start for f in findings_by_rule(findings, "S-PY-DESER")} == {9, 10}
    assert {f.line_start for f in findings_by_rule(findings, "S-PY-CRYPTO")} == {11}


def test_python_hardcoded_secret_flagged_env_var_not():
    findings = analyze_python_security(PY_SECRETS, "x.py")
    secrets = findings_by_rule(findings, "S-PY-SECRET")
    lines = {f.line_start for f in secrets}
    assert 2 in lines           # hardcoded api_key on line 2
    assert 3 not in lines       # os.environ lookup is NOT hardcoded


def test_python_finding_schema_completeness():
    f = analyze_python_security(PY_SQLI_CONCAT, "user_repository.py")[0]
    for field in ("id", "category", "rule_id", "title", "description",
                  "finding_kind", "detection", "severity", "severity_score",
                  "confidence", "file_path", "line_start", "line_end",
                  "code_snippet", "source_agent", "owasp_category", "cwe_id",
                  "remediation_advice"):
        assert getattr(f, field) is not None, f"{field} must be populated"
    assert f.category == "security"
    assert f.source_agent == "security_agent"
    assert 0.0 <= f.confidence <= 1.0


# --- Java -------------------------------------------------------------------

def test_java_clean_zero_findings():
    assert analyze_java_security(JAVA_CLEAN, "UserDao.java") == []


def test_java_sqli_detected_at_concat_line():
    findings = analyze_java_security(JAVA_SQLI, "AccountDAO.java")
    sqli = findings_by_rule(findings, "S-JAVA-SQLI")
    assert len(sqli) == 1
    assert sqli[0].line_start == 11    # String sql = ... + acctId
    assert sqli[0].cwe_id == "CWE-89"


def test_java_broken_crypto_detected():
    findings = analyze_java_security(JAVA_SECCO, "CryptoUtil.java")
    crypto = findings_by_rule(findings, "S-JAVA-CRYPTO")
    assert len(crypto) == 1
    assert crypto[0].line_start == 7


def test_java_sqli_severity_critical():
    findings = analyze_java_security(JAVA_SQLI, "AccountDAO.java")
    assert findings[0].severity == "critical"
    assert findings[0].severity_score == 9.4
