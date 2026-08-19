"""
SQLite connection/schema management for VulnVerify's persistence
layer.

A short-lived connection is opened per operation (see
get_connection()) rather than one long-lived global connection --
this is what makes access safe from multiple threads (the existing
automatic-verification background thread, see
backend/services/auto_verification_service.py, writes concurrently
with the main request-handling thread). SQLite's own file locking
handles the actual concurrency; WAL mode plus a busy_timeout keep
that safe and reasonably fast for this project's scale without
needing a connection pool or an async driver.
"""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


_DEFAULT_DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "vulnverify.db"
)


def get_db_path() -> Path:
    """
    The database file path in use.

    VULNVERIFY_DB_PATH overrides the default -- set by tests/conftest.py
    to an isolated per-test-session temp file so the test suite never
    reads or writes the real application database. Never ":memory:":
    an in-memory SQLite database is scoped to a single connection, and
    this module intentionally opens a fresh connection per operation
    (including from the automatic-verification background thread), so
    ":memory:" would silently give every caller its own empty,
    disconnected database.
    """

    override = os.environ.get("VULNVERIFY_DB_PATH")

    if override:
        return Path(override)

    return _DEFAULT_DB_PATH


@contextmanager
def get_connection():
    """
    Open one short-lived SQLite connection for a single unit of work.

    Commits on success, rolls back on any exception, always closes --
    every call site gets a real transaction without having to manage
    one by hand.
    """

    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(db_path),
        timeout=10,
        isolation_level=None,
    )

    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row

        conn.execute("BEGIN")
        yield conn

        # executescript() (used by initialize_schema() for the
        # CREATE TABLE statements) implicitly commits any pending
        # transaction before it runs, regardless of isolation_level --
        # so by the time control returns here, the BEGIN above may
        # already have been closed out from under us. Only commit if
        # a transaction is actually still open.
        if conn.in_transaction:
            conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    filename TEXT,
    content_type TEXT,
    scanner TEXT,
    status TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS normalized_findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    category TEXT,
    position INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_normalized_findings_scan_id
    ON normalized_findings(scan_id);

CREATE TABLE IF NOT EXISTS verified_findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    status TEXT,
    confidence REAL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verified_findings_scan_id
    ON verified_findings(scan_id);

CREATE TABLE IF NOT EXISTS ground_truth_labels (
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    expected_status TEXT,
    note TEXT,
    data TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
"""


def initialize_schema() -> None:
    """
    Create every table (idempotently) if it doesn't already exist.

    Called once, at import time, by backend/storage/repository.py --
    this is the whole "migration" mechanism this hackathon-scope
    project needs: there is exactly one schema version, so
    CREATE TABLE IF NOT EXISTS is sufficient and nothing more
    elaborate (Alembic, versioned migration files, ...) is warranted.
    """

    with get_connection() as conn:
        conn.executescript(_SCHEMA)
