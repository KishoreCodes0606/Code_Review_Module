---
id: custom-python-sql-injection
title: "Python: Preventing SQL Injection (vulnerable vs fixed)"
doc_type: custom
owasp: A03
cwe: [CWE-89]
language: python
---
# Python: Preventing SQL Injection (vulnerable vs fixed)

## Why it happens
SQL injection (CWE-89) happens when user input is concatenated or formatted into a SQL string, so the database cannot tell data from commands. An attacker input such as `' OR '1'='1` changes the meaning of the query.

## Vulnerable patterns
```python
cur.execute("SELECT * FROM users WHERE id = " + user_id)
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
```
String concatenation, f-strings and the `%` operator all build the query before the driver sees it.

## Fix: parameterized queries
Pass values separately from the SQL text. The driver sends them as data.
```python
# sqlite3 uses ? placeholders
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# psycopg2 / MySQL drivers use %s placeholders (still a separate argument tuple)
cur.execute("SELECT * FROM users WHERE name = %s", (name,))
```
Always pass the parameters as the second argument. Never wrap the placeholder in quotes.

## Fix: ORM query builders
```python
# SQLAlchemy
user = session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
```
Raw SQL in an ORM is still dangerous. With SQLAlchemy use `text("... WHERE id = :id")` with bound parameters.

## What placeholders cannot do
Table names, column names and `ORDER BY` direction cannot be parameters. Validate them against an allow-list instead:
```python
ALLOWED_SORT = {"name", "created_at"}
if sort not in ALLOWED_SORT:
    raise ValueError("invalid sort column")
query = f"SELECT * FROM users ORDER BY {sort}"
```

## Defence in depth
Use a database account with least privilege, validate input types (for example convert ids with `int()`), and never show raw database errors to users.
