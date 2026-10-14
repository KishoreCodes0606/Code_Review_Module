---
id: custom-cwe-owasp-severity-reference
title: "CWE to OWASP Mapping and Severity Guide"
doc_type: reference
owasp: general
cwe: [CWE-89, CWE-79, CWE-78, CWE-798, CWE-352, CWE-22, CWE-502, CWE-327, CWE-639, CWE-611]
language: general
source_url: https://cwe.mitre.org/
---
# CWE to OWASP Mapping and Severity Guide

This table maps the weaknesses the platform detects to a CWE identifier, an OWASP Top 10 (2021) category and a default severity band. Severity is a starting point: raise it when untrusted input demonstrably reaches the vulnerable line, lower it when the code path is not reachable.

| Weakness | CWE | OWASP 2021 | Default severity |
|---|---|---|---|
| SQL injection | CWE-89 | A03 Injection | Critical |
| OS command injection | CWE-78 | A03 Injection | Critical |
| Unsafe deserialization | CWE-502 | A08 Software and Data Integrity Failures | Critical |
| Hardcoded credentials or keys | CWE-798 | A02 Cryptographic Failures | High |
| Broken access control, IDOR | CWE-639, CWE-285 | A01 Broken Access Control | High |
| XML external entity (XXE) | CWE-611 | A05 Security Misconfiguration | High |
| Path traversal | CWE-22 | A01 Broken Access Control | High |
| Cross-site scripting (XSS) | CWE-79 | A03 Injection | Medium to High |
| Cross-site request forgery (CSRF) | CWE-352 | A01 Broken Access Control | Medium |
| Weak hash or cipher (MD5, SHA-1, DES, ECB) | CWE-327 | A02 Cryptographic Failures | Medium |
| Sensitive data in logs | CWE-532 | A09 Logging and Monitoring Failures | Medium |
| Verbose error messages | CWE-209 | A05 Security Misconfiguration | Low |

## Severity bands (CVSS style)
Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9. A finding with low confidence should be reported with the confidence value so the developer can verify it.

## Version note
OWASP revises the Top 10 periodically. Category numbers in this table follow the 2021 edition. When the platform moves to a newer edition, update this table and the `owasp` fields in `sources.yaml`.
