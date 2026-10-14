---
id: custom-password-hashing
title: "Password Hashing: Python and Java Examples"
doc_type: custom
owasp: A02
cwe: [CWE-916, CWE-327, CWE-759]
language: general
---
# Password Hashing: Python and Java Examples

## Weak approaches
MD5, SHA-1 and plain SHA-256 are fast general hashes, so attackers can test billions of guesses per second. Unsalted hashes also allow rainbow-table lookups (CWE-327, CWE-916, CWE-759).
```python
hashlib.md5(password.encode()).hexdigest()       # insecure for passwords
```

## Use a slow, salted password hash
Recommended order: Argon2id, then scrypt, then bcrypt, then PBKDF2 with a high iteration count.

### Python (bcrypt)
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
ok = bcrypt.checkpw(candidate.encode(), hashed)
```

### Python (Argon2)
```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
ph.verify(hashed, candidate)       # raises on mismatch
```

### Java (Spring Security)
```java
PasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(rawPassword);
boolean ok = encoder.matches(candidate, hash);
```

## Rules
The library generates a unique random salt for each password. Never invent your own scheme. Compare hashes with the library verify function (constant time). Do not log passwords or return them in API responses.
