---
id: custom-java-sql-injection
title: "Java: Preventing SQL Injection with PreparedStatement"
doc_type: custom
owasp: A03
cwe: [CWE-89]
language: java
---
# Java: Preventing SQL Injection with PreparedStatement

## Vulnerable pattern
```java
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
```
Concatenating input into `Statement.executeQuery` lets the input change the SQL structure (CWE-89).

## Fix: PreparedStatement with bound parameters
```java
String sql = "SELECT * FROM users WHERE name = ?";
try (PreparedStatement ps = conn.prepareStatement(sql)) {
    ps.setString(1, name);
    try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) { /* read columns */ }
    }
}
```
Use `setString`, `setInt` and the other typed setters. The driver treats the value as data only. try-with-resources closes the statement and result set.

## JPA / Hibernate
```java
TypedQuery<User> q = em.createQuery("SELECT u FROM User u WHERE u.name = :name", User.class);
q.setParameter("name", name);
```
Do not build JPQL or HQL strings by concatenation. Spring Data derived queries and `@Query` with named parameters are safe.

## Dynamic identifiers
Column names and sort order cannot be bound. Check them against a fixed allow-list (a `Set<String>` or an enum) before adding them to the SQL string.
