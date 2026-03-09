from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    auto_sync_interval_minutes INTEGER NOT NULL DEFAULT 0,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    two_factor_secret TEXT NOT NULL DEFAULT '',
    two_factor_pending_secret TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS calendar_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    sync_mode TEXT NOT NULL DEFAULT 'full',
    blocked_title TEXT NOT NULL DEFAULT 'Blocked',
    is_active INTEGER NOT NULL DEFAULT 1,
    settings_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS internal_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sync_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    is_all_day INTEGER NOT NULL DEFAULT 0,
    recurrence_rule TEXT NOT NULL DEFAULT '',
    source_provider TEXT NOT NULL DEFAULT 'webapp',
    source_connection_id INTEGER,
    origin_provider TEXT NOT NULL DEFAULT 'webapp',
    origin_connection_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(source_connection_id) REFERENCES calendar_connections(id),
    FOREIGN KEY(origin_connection_id) REFERENCES calendar_connections(id),
    UNIQUE(user_id, sync_id)
);

CREATE TABLE IF NOT EXISTS event_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    connection_id INTEGER NOT NULL,
    external_event_id TEXT NOT NULL,
    external_uid TEXT NOT NULL DEFAULT '',
    sync_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT 'full',
    fingerprint TEXT NOT NULL DEFAULT '',
    last_seen_at TEXT,
    last_synced_at TEXT,
    deleted_at TEXT,
    provider_payload_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(event_id) REFERENCES internal_events(id),
    FOREIGN KEY(connection_id) REFERENCES calendar_connections(id),
    UNIQUE(connection_id, external_event_id)
);

CREATE TABLE IF NOT EXISTS sync_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    triggered_by TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sync_log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    level TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    sync_id TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(job_id) REFERENCES sync_jobs(id)
);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    was_success INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

UPDATE sync_jobs
SET status = 'abandoned',
    message = CASE
        WHEN message = '' THEN 'Recovered duplicate running job during startup'
        ELSE message
    END,
    finished_at = COALESCE(finished_at, started_at)
WHERE status = 'running'
  AND id NOT IN (
    SELECT MAX(id)
    FROM sync_jobs
    WHERE status = 'running'
    GROUP BY user_id
  );

CREATE INDEX IF NOT EXISTS idx_connections_user_id ON calendar_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_events_user_id ON internal_events(user_id);
CREATE INDEX IF NOT EXISTS idx_links_event_id ON event_links(event_id);
CREATE INDEX IF NOT EXISTS idx_links_connection_id ON event_links(connection_id);
CREATE INDEX IF NOT EXISTS idx_jobs_user_id ON sync_jobs(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_running_sync_job_per_user
ON sync_jobs(user_id)
WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_logs_job_id ON sync_log_entries(job_id);
CREATE INDEX IF NOT EXISTS idx_auth_login_email_created_at ON auth_login_attempts(email, created_at);
CREATE INDEX IF NOT EXISTS idx_auth_login_ip_created_at ON auth_login_attempts(ip_address, created_at);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA_SQL)
            self._ensure_column(
                connection,
                "users",
                "auto_sync_interval_minutes",
                "ALTER TABLE users ADD COLUMN auto_sync_interval_minutes INTEGER NOT NULL DEFAULT 0",
            )
            self._ensure_column(
                connection,
                "users",
                "two_factor_enabled",
                "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0",
            )
            self._ensure_column(
                connection,
                "users",
                "two_factor_secret",
                "ALTER TABLE users ADD COLUMN two_factor_secret TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                connection,
                "users",
                "two_factor_pending_secret",
                "ALTER TABLE users ADD COLUMN two_factor_pending_secret TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                connection,
                "internal_events",
                "origin_provider",
                "ALTER TABLE internal_events ADD COLUMN origin_provider TEXT NOT NULL DEFAULT 'webapp'",
            )
            self._ensure_column(
                connection,
                "internal_events",
                "origin_connection_id",
                "ALTER TABLE internal_events ADD COLUMN origin_connection_id INTEGER",
            )
            connection.execute(
                """
                UPDATE internal_events
                SET origin_provider = COALESCE(NULLIF(TRIM(source_provider), ''), 'webapp')
                WHERE COALESCE(TRIM(origin_provider), '') = ''
                   OR (
                        origin_provider = 'webapp'
                        AND COALESCE(NULLIF(TRIM(source_provider), ''), 'webapp') <> 'webapp'
                   )
                """
            )
            connection.execute(
                """
                UPDATE internal_events
                SET origin_connection_id = source_connection_id
                WHERE origin_connection_id IS NULL AND source_connection_id IS NOT NULL
                """
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_column(self, connection: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        if any(str(row["name"]) == column for row in rows):
            return
        connection.execute(ddl)
