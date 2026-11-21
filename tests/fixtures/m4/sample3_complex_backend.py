"""Session and profile backend for the sample dashboard (M4 sample 3, high complexity).

Contains authentication-related code, database access, user input handling,
several security test cases and two deliberate safe implementations that
control for false positives.
"""

import hashlib
import os
import sqlite3
import subprocess
from dataclasses import dataclass

DB_PATH = "app.db"
DATA_ROOT = "/var/data"

# CONTROLLED VULNERABILITY: credential embedded in source.
API_TOKEN = "demo-token-8f3c2b91d4e5"

LOGIN_ATTEMPT_LIMIT = 5
UPLOAD_ROOT = "/var/data/uploads"


@dataclass
class User:
    user_id: int
    email: str
    role: str


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def load_user(conn, email):
    """SAFE IMPLEMENTATION: bound parameter, no string interpolation."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cursor.fetchone()


def search_users(conn, term):
    """CONTROLLED VULNERABILITY: f-string SQL built from caller input."""
    cursor = conn.cursor()
    query = f"SELECT id, email, role FROM users WHERE email LIKE '%{term}%'"
    cursor.execute(query)
    return cursor.fetchall()


def hash_password(password):
    """CONTROLLED VULNERABILITY: fast unsalted digest used for passwords."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def authenticate(conn, email, password, attempts):
    """Authentication path: broad exception hides failures, magic number."""
    try:
        user = load_user(conn, email)
        if user is None:
            return None
        if attempts > 5:
            return None
        if hash_password(password) == user["password_hash"]:
            return User(user_id=user["id"], email=user["email"], role=user["role"])
        return None
    except:
        return None


def export_report(filename):
    """CONTROLLED VULNERABILITY: caller-controlled path joined without checks."""
    with open(os.path.join(DATA_ROOT, filename)) as handle:
        return handle.read()


def read_upload(filename):
    """SAFE IMPLEMENTATION: canonicalise and confine to the upload root."""
    base = os.path.realpath(UPLOAD_ROOT)
    candidate = os.path.realpath(os.path.join(base, filename))
    if candidate != base and not candidate.startswith(base + os.sep):
        raise ValueError("path escapes the upload directory")
    with open(candidate) as handle:
        return handle.read()


def ping_host(host):
    """CONTROLLED VULNERABILITY: shell=True with concatenated input."""
    return subprocess.call("ping -c 1 " + host, shell=True)


def render_dashboard(user, orders, region):
    """Long method with deep nesting and repeated magic numbers."""
    lines = []
    if user is not None:
        if user.role == "admin":
            if region == "eu":
                if len(orders) > 10:
                    lines.append("EU admin bulk view")
                else:
                    lines.append("EU admin view")
            else:
                lines.append("admin view")
        else:
            if region == "eu":
                lines.append("EU customer view")
            else:
                lines.append("customer view")
    return "\n".join(lines)


def summarise_orders(orders):
    """Clean helper: explicit guard clauses, no nesting."""
    if not orders:
        return 0
    total = 0
    for order in orders:
        total += order["amount"]
    return total
