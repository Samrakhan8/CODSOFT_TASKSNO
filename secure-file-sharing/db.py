"""
db.py - SQLite schema and access helpers for the secure file-sharing system.

Tables:
  users   - accounts and their role (admin | user)
  files   - one row per encrypted file, with its crypto metadata
  grants  - extra access grants (to a specific user or a whole role)
  links   - temporary, expiring download links
  audit   - append-only action log

All queries are parameterised.
"""

import sqlite3
import time


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            orig_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            nonce TEXT NOT NULL,
            wrapped_key TEXT NOT NULL,
            wrap_nonce TEXT NOT NULL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS grants (
            id INTEGER PRIMARY KEY,
            file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            principal_type TEXT NOT NULL,   -- 'user' | 'role'
            principal TEXT NOT NULL,
            UNIQUE(file_id, principal_type, principal)
        );

        CREATE TABLE IF NOT EXISTS links (
            token TEXT PRIMARY KEY,
            file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            created_by TEXT NOT NULL,
            expires_at REAL NOT NULL,
            max_downloads INTEGER NOT NULL DEFAULT 0,  -- 0 = unlimited
            downloads INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY,
            ts REAL NOT NULL,
            actor TEXT,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT
        );
        """
    )
    conn.commit()


def log(conn, actor, action, target=None, detail=None):
    conn.execute(
        "INSERT INTO audit (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
        (time.time(), actor, action, target, detail),
    )
    conn.commit()
