import sqlite3
import os

DB_PATH = os.getenv("DB_PATH", "users.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, email, role) "
        "VALUES ('admin', 'admin123', 'admin@example.com', 'admin')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, email, role) "
        "VALUES ('alice', 'password1', 'alice@example.com', 'user')"
    )
    conn.commit()
    conn.close()


def get_all_users():
    conn = get_connection()
    rows = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# INTENTIONAL VULNERABILITY: SQL Injection — user input concatenated directly
# into SQL query without parameterization. Semgrep + ZAP should flag this.
def get_user_by_id_vulnerable(user_id: str):
    conn = get_connection()
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    try:
        rows = conn.execute(query).fetchall()
    except Exception as e:
        conn.close()
        raise ValueError(f"Query error: {e}")
    conn.close()
    return [dict(r) for r in rows]


def get_user_by_credentials(username: str, password: str):
    conn = get_connection()
    # INTENTIONAL VULNERABILITY: plain-text password comparison, no hashing
    row = conn.execute(
        "SELECT id, username, email, role FROM users "
        "WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()
    return dict(row) if row else None
