---
id: custom-hardcoded-secrets
title: "Hardcoded Secrets: Detection and Fixes (Python and Java)"
doc_type: custom
owasp: A02
cwe: [CWE-798, CWE-259]
language: general
---
# Hardcoded Secrets: Detection and Fixes (Python and Java)

## Why it is dangerous
Passwords, API keys, tokens and private keys written in source code leak through version control, logs and shared builds. Anyone with read access to the code gets the secret, and it cannot be rotated without a code change (CWE-798, CWE-259).

## Warning signs
Variables named `password`, `passwd`, `secret`, `api_key`, `token`, `private_key`; long random-looking strings; prefixes such as `sk-`, `AKIA` or `ghp_`; connection strings with embedded credentials.

## Python fix
```python
import os
API_KEY = os.environ["API_KEY"]            # fails fast if missing
DB_URL = os.getenv("DATABASE_URL")
```
Load a local `.env` file with python-dotenv in development and add `.env` to `.gitignore`.

## Java fix
```java
String apiKey = System.getenv("API_KEY");
if (apiKey == null) throw new IllegalStateException("API_KEY not set");
```
Spring Boot: reference `${API_KEY}` in `application.properties` and supply it through the environment.

## Production
Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager). Rotate any secret that was ever committed: removing it from the latest commit is not enough because it stays in git history.
