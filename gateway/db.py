"""SQLite grant store — schema, migrations, connection helper."""

import sqlite3

from gateway.config import DATA_DIR, GRANTS_DB_PATH


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(GRANTS_DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS grants (
            id TEXT PRIMARY KEY,
            level INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            message_id TEXT,
            query TEXT,
            description TEXT,
            approval_token TEXT UNIQUE NOT NULL,
            signal_code TEXT,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            expires_at TEXT,
            duration_minutes INTEGER,
            metadata TEXT,
            callback_url TEXT,
            resource_type TEXT NOT NULL DEFAULT 'gmail',
            resource_params TEXT
        )
    """)
    # Idempotent migrations for existing databases
    migrations = [
        "ALTER TABLE grants ADD COLUMN callback_url TEXT",
        "ALTER TABLE grants ADD COLUMN resource_type TEXT NOT NULL DEFAULT 'gmail'",
        "ALTER TABLE grants ADD COLUMN resource_params TEXT",
        "ALTER TABLE grants ADD COLUMN requestor TEXT",
    ]
    for stmt in migrations:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    conn.close()


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(GRANTS_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn
