---
id: custom-path-traversal
title: "Path Traversal: Safe File Access in Python and Java"
doc_type: custom
owasp: A01
cwe: [CWE-22]
language: general
---
# Path Traversal: Safe File Access in Python and Java

## The problem
If a filename from the user is joined to a base directory, input like `../../etc/passwd` escapes that directory and reads or overwrites other files (CWE-22).

## Vulnerable Python
```python
with open("/var/app/files/" + filename) as f:
    data = f.read()
```

## Fix: resolve, then check containment
```python
from pathlib import Path
BASE = Path("/var/app/files").resolve()
target = (BASE / filename).resolve()
if BASE not in target.parents:
    raise PermissionError("path outside base directory")
data = target.read_text()
```
`resolve()` collapses `..` and follows symlinks before the check. For uploads also generate your own random file name and keep only an allow-listed extension.

## Fix in Java
```java
Path base = Paths.get("/var/app/files").toRealPath();
Path target = base.resolve(filename).normalize();
if (!target.startsWith(base)) {
    throw new SecurityException("path outside base directory");
}
```

## Notes
Reject names containing null bytes, drive letters or absolute paths. Prefer database ids that map to stored paths over accepting raw file names. Run the process with minimal file-system permissions.
