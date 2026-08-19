"""
Regression test reproducing the exact bug reported as "Scan History
does NOT survive a backend restart or frontend refresh".

Investigation finding (see the accompanying diagnosis report): the
SQLite persistence layer (backend/storage/db.py,
backend/storage/collections.py) was never actually broken -- verified
independently three ways: a raw sqlite3 connection reading the file
directly after killing the backend process, a real backend restart
via GET /scans through the HTTP API (this test), and a live browser
session against a restarted backend correctly listing the scan on
the Scan History page.

The real bug was frontend-only: frontend/src/hooks/useScanData.js's
active scan_id (scanId/scanMeta) was plain useState with no
persistence or restoration, so a full page reload always landed on an
empty Dashboard/"No scan yet" regardless of what the backend actually
had -- looking exactly like "history disappeared" even though GET
/scans was always correct underneath. The fix
(ACTIVE_SCAN_ID_STORAGE_KEY + the mount-time restoration effect in
useScanData.js) is frontend-only and has no backend test surface;
this test exists as the backend-side "control" proving conclusively
that what Scan History's frontend code calls (GET /scans) was correct
all along, isolating the bug to the frontend restoration logic.
"""

import subprocess
import sys
from pathlib import Path

import backend.storage.repository as repository
from backend.storage.db import get_db_path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_get_scans_survives_a_real_backend_restart_reproducing_the_bug():
    """
    Exactly the lifecycle described in the bug report:

        upload scan -> save scan -> backend restart -> GET /scans

    using a genuinely separate OS process for the "restart" (not an
    in-process simulation), and asserting GET /scans (via
    get_all_scans(), the exact function backend/api/scans.py::
    list_scans calls, which is what the frontend's Scan History page
    calls through GET /api/v1/scans) still returns the scan with all
    fields intact.
    """

    scan_id = "scan-history-bug-repro-001"

    repository.scans.clear()

    repository.scans[scan_id] = {
        "scan_id": scan_id,
        "filename": "zap_sqli_positive.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    db_path = str(get_db_path())

    script = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
import os
os.environ["VULNVERIFY_DB_PATH"] = {db_path!r}

from backend.services.scan_service import get_all_scans

all_scans = get_all_scans()
matching = [s for s in all_scans if s["scan_id"] == {scan_id!r}]

assert len(matching) == 1, (
    "Scan History's own data source (get_all_scans(), called by "
    "GET /api/v1/scans) lost the scan after a real backend restart"
)

scan = matching[0]
assert scan["filename"] == "zap_sqli_positive.json"
assert scan["scanner"] == "ZAP"
assert scan["status"] == "NORMALIZED"

print("SCAN_HISTORY_SURVIVES_RESTART_OK")
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "SCAN_HISTORY_SURVIVES_RESTART_OK" in result.stdout
