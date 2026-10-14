---
id: custom-xss-output-encoding
title: "Cross-Site Scripting: Output Encoding in Flask and Java"
doc_type: custom
owasp: A03
cwe: [CWE-79]
language: general
---
# Cross-Site Scripting: Output Encoding in Flask and Java

## The problem
XSS (CWE-79) happens when untrusted input is written into an HTML page without encoding, so the browser runs it as script. Example payload: `<script>steal(document.cookie)</script>`.

## Vulnerable Python (Flask)
```python
@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"
```

## Fix: auto-escaping templates
```python
from flask import render_template
return render_template("hello.html", name=name)   # Jinja2 escapes {{ name }}
```
Avoid the `|safe` filter and `Markup()` on user data. If you must build HTML in code, use `markupsafe.escape(name)` or `html.escape(name)`.

## Vulnerable Java (servlet)
```java
response.getWriter().println("<h1>Hello " + request.getParameter("name") + "</h1>");
```

## Fix: encode for the output context
```java
import org.owasp.encoder.Encode;
response.getWriter().println("<h1>Hello " + Encode.forHtml(name) + "</h1>");
```
Use a template engine with auto-escaping (Thymeleaf `th:text`, not `th:utext`). Pick the encoder that matches the context: HTML body, HTML attribute, JavaScript, URL or CSS.

## Defence in depth
Set a Content-Security-Policy header, mark session cookies `HttpOnly` and `Secure`, and validate input on the server.
