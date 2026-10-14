---
id: custom-python-command-injection
title: "Python: Preventing OS Command Injection"
doc_type: custom
owasp: A03
cwe: [CWE-78]
language: python
---
# Python: Preventing OS Command Injection

## Vulnerable patterns
```python
os.system("ping -c 1 " + host)
subprocess.run("convert " + filename + " out.png", shell=True)
os.popen(f"grep {term} app.log")
```
With `shell=True`, `os.system` or `os.popen`, the shell parses the string. Input like `8.8.8.8; rm -rf /` runs a second command (CWE-78).

## Fix: pass an argument list, no shell
```python
subprocess.run(["ping", "-c", "1", host], check=True, capture_output=True, timeout=10)
```
Each list item is one argument, and no shell interprets metacharacters such as `;`, `|` or `&&`.

## Also validate
```python
import ipaddress
ipaddress.ip_address(host)   # raises ValueError for anything that is not an IP
```
Use an allow-list or strict parser for the input type. Prefer a Python library over spawning a process when one exists (for example `shutil`, `zipfile`, `pathlib`).

## Related risks
`eval()` and `exec()` on user input execute arbitrary Python code (CWE-95). Replace them with `ast.literal_eval` for literals or `json.loads` for data.
