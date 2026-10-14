---
id: custom-code-smells-catalog
title: "Code Smells Catalog with Thresholds and Refactorings"
doc_type: codesmell
owasp: general
cwe: []
language: general
source_url: https://refactoring.guru/refactoring/smells
---
# Code Smells Catalog with Thresholds and Refactorings

A code smell is a symptom that may point to a deeper design problem. The code works, but it is harder to read, change and test. The catalogue follows Martin Fowler's *Refactoring* (smell names and fixes are summarised here in original words).

## Size and complexity smells
- **Long Method**: a function longer than about 40 lines or doing several jobs. Fix with Extract Method.
- **Large Class (God Class)**: a class with more than about 20 methods or many unrelated responsibilities. Fix with Extract Class.
- **Long Parameter List**: more than 4 or 5 parameters. Fix with a Parameter Object.
- **Deep Nesting**: more than 3 levels of indentation. Fix with guard clauses and extraction.
- **High cyclomatic complexity**: above 10 is moderate and above 20 is high risk. Split branching logic into smaller functions.

## Duplication and dead code
- **Duplicate Code**: the same logic copied in several places. Extract a shared function or module.
- **Dead Code**: unused variables, parameters, imports, functions or unreachable branches. Delete them.

## Design smells
- **Feature Envy**: a method uses another class's data more than its own. Move the method.
- **Primitive Obsession**: strings and ints used for concepts like money or email. Introduce small value classes.
- **Switch or long if-else chains** on a type code. Use polymorphism.
- **Message Chains** such as `a.b().c().d()`. Hide the delegate.
- **Shotgun Surgery**: one change forces edits in many classes. Move related behaviour together.

## Readability smells
- **Magic numbers and strings**: unexplained literals. Use named constants.
- **Poor naming**: names like `x`, `tmp`, `data2`. Rename to reveal intent.
- **Comments that explain bad code**: rewrite the code to be clear instead.

## Error-handling smells
- **Swallowed exceptions**: `except: pass` in Python or an empty `catch (Exception e) {}` in Java hides failures. Catch specific exceptions, log, and handle or re-raise.
- **Broad exception handling** that catches everything. Narrow it.

## Python-specific
Mutable default arguments (`def f(items=[])`), `from module import *`, bare `except:`, missing context managers for files, and comparing to `None` with `==` instead of `is`.

## Java-specific
Public mutable fields, resources not closed with try-with-resources, `==` used to compare strings, returning `null` instead of `Optional` or an empty collection, and overly long `if` chains on `instanceof`.

## Measurable thresholds (typical defaults)
| Metric | Flag when |
|---|---|
| Function length | more than 40 to 50 lines |
| Cyclomatic complexity | more than 10 |
| Cognitive complexity | more than 15 |
| Nesting depth | more than 3 |
| Parameters | more than 5 |
| Methods per class | more than 20 |
