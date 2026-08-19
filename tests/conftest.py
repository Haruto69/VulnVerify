"""
Points the backend's SQLite persistence layer (backend/storage/db.py)
at an isolated, per-test-session temp file before any test module
gets to import backend.storage.repository -- pytest always loads
conftest.py for a directory before collecting/importing the test
modules inside it, so this env var is guaranteed to be set first.

This is a real file, not ":memory:": an in-memory SQLite database is
scoped to a single connection, and backend/storage/db.py intentionally
opens a fresh connection per operation (including from the automatic-
verification background thread exercised by
tests/test_auto_verification_service.py), so ":memory:" would give
every caller an independent, disconnected database.

Per-test isolation itself continues to work exactly as it already
did with the old in-memory dicts: every existing test file clears the
relevant collections at the start of its own setup helper (e.g.
`scans.clear(); normalized_findings.clear(); verified_findings.clear()`).
Those calls now issue real DELETE statements against this temp
database instead of clearing a process-local dict, but the isolation
contract the test suite already relied on is unchanged.
"""

import os
import tempfile

_fd, _path = tempfile.mkstemp(
    prefix="vulnverify-test-", suffix=".db"
)
os.close(_fd)
os.environ["VULNVERIFY_DB_PATH"] = _path
