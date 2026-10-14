---
id: custom-python-unsafe-deserialization
title: "Python: Unsafe Deserialization (pickle, yaml.load)"
doc_type: custom
owasp: A08
cwe: [CWE-502]
language: python
---
# Python: Unsafe Deserialization (pickle, yaml.load)

## The problem
`pickle.loads` can run arbitrary code while loading data, so loading attacker-controlled bytes is remote code execution (CWE-502). The same applies to `marshal`, `shelve`, and `yaml.load` with the default or full loader.

## Vulnerable
```python
obj = pickle.loads(request.data)
config = yaml.load(user_text)              # unsafe loader
```

## Fix
```python
import json, yaml
obj = json.loads(request.data)             # data-only format
config = yaml.safe_load(user_text)         # restricted to plain types
```
Use JSON for data from outside your trust boundary. Validate the parsed structure with a schema (for example Pydantic) before using it.

## If pickle is unavoidable
Only unpickle data you created and protected with an HMAC signature checked with `hmac.compare_digest`. Never unpickle data from users, queues or caches that others can write to.
