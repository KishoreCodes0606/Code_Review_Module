"""Inventory helpers for the sample storefront (M4 sample 1, low complexity).

Deliberately small: a few functions, one input check, one controlled SQL
injection and several clean helpers that must NOT be reported.
"""

import hashlib
import sqlite3

DB_PATH = "inventory.db"


def connect():
    return sqlite3.connect(DB_PATH)


def find_item(conn, name):
    """Look one item up by name.

    CONTROLLED VULNERABILITY: the name is interpolated into the SQL text, so
    the database parses caller-controlled text as SQL.
    """
    cursor = conn.cursor()
    query = "SELECT id, name, quantity FROM items WHERE name = '" + name + "'"
    cursor.execute(query)
    return cursor.fetchone()


def format_price(cents):
    """Clean helper: validate the input, then format integer cents."""
    if not isinstance(cents, int) or cents < 0:
        raise ValueError("price must be a non-negative integer")
    return f"${cents // 100}.{cents % 100:02d}"


def total_quantity(rows):
    """Clean helper: plain aggregation with no string building."""
    total = 0
    for quantity in rows:
        total += quantity
    return total


def stock_signature(name):
    """Weak digest used as a cache key (still flagged: MD5 is a weak hash)."""
    return hashlib.md5(name.encode("utf-8")).hexdigest()


def is_low_stock(quantity):
    """Clean helper: explicit comparison, no magic constant needed."""
    return quantity < 5
