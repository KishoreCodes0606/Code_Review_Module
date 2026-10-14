---
id: custom-access-control-checks
title: "Broken Access Control and IDOR: Authorization Checks in Code"
doc_type: custom
owasp: A01
cwe: [CWE-639, CWE-285, CWE-862]
language: general
---
# Broken Access Control and IDOR: Authorization Checks in Code

## The problem
Authentication proves who the user is. Authorization decides what that user may do. An insecure direct object reference (IDOR, CWE-639) happens when code loads a record by an id from the request without checking that the current user owns it or may see it.

## Vulnerable Python (Flask)
```python
@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    return jsonify(Order.query.get_or_404(order_id).to_dict())   # any logged-in user can read any order
```

## Fix: enforce ownership on the server
```python
@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, owner_id=current_user.id).first_or_404()
    return jsonify(order.to_dict())
```
Returning 404 for records the user may not see avoids confirming that they exist.

## Fix in Java (Spring Security)
```java
@PreAuthorize("hasRole('USER')")
@GetMapping("/orders/{id}")
public Order get(@PathVariable long id, Authentication auth) {
    return orderRepo.findByIdAndOwner(id, auth.getName()).orElseThrow(NotFoundException::new);
}
```

## Principles
Deny by default. Check permissions on every request, on the server side, close to the data access. Do not trust hidden form fields, client-side checks or role names sent by the client. Log access-control failures. Hiding a button in the UI is not access control.
