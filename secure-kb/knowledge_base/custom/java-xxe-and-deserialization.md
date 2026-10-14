---
id: custom-java-xxe-deserialization
title: "Java: Safe XML Parsing (XXE) and Deserialization"
doc_type: custom
owasp: A05
cwe: [CWE-611, CWE-502]
language: java
---
# Java: Safe XML Parsing (XXE) and Deserialization

## XML External Entity (XXE, CWE-611)
Default XML parsers may resolve external entities, letting an attacker read local files or reach internal URLs through a crafted document.

### Fix: harden the factory
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder builder = dbf.newDocumentBuilder();
```
Apply the equivalent settings to `SAXParserFactory`, `XMLInputFactory` and `TransformerFactory`.

## Unsafe Java deserialization (CWE-502)
```java
ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
Object obj = in.readObject();       // gadget chains can run code
```
Avoid native serialization for untrusted input. Use JSON (Jackson) with a fixed target class and do not enable default typing. If you must keep `ObjectInputStream`, install a deserialization filter (`ObjectInputFilter`) with an allow-list of classes.
