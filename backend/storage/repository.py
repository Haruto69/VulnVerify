"""
Backend persistence entry point.

scans, normalized_findings, verified_findings, and ground_truth are
now backed by a local SQLite database (see backend/storage/db.py and
backend/storage/collections.py) instead of plain in-process dicts, so
this data survives a backend restart. Every caller in this codebase
(backend/services/scan_service.py,
backend/services/ground_truth_service.py, and the existing test
suite) already only ever accessed these four names through ordinary
dict operations -- __getitem__/__setitem__/.get()/.clear()/"in"/
.values() -- which is exactly the collections.abc.MutableMapping
interface each *Store class below implements, so nothing about their
public shape changed here.
"""

from backend.storage.collections import (
    GroundTruthStore,
    NormalizedFindingsStore,
    ScanStore,
    VerifiedFindingsStore,
)
from backend.storage.db import initialize_schema

initialize_schema()

scans = ScanStore()

normalized_findings = NormalizedFindingsStore()

verified_findings = VerifiedFindingsStore()

# scan_id -> {finding_id: GroundTruthLabel}
ground_truth = GroundTruthStore()

# scan_id -> automatic-verification progress dict (see
# backend/services/auto_verification_service.py). Absent entry means
# automatic verification was never started for that scan (e.g. a
# scan loaded from Scan History rather than freshly uploaded).
#
# Deliberately kept as plain in-process state, NOT persisted to
# SQLite: it exists to answer "is a background verification thread
# genuinely running right now", which is only ever true within the
# current process. After a restart no such thread exists for any
# previously-RUNNING scan, so persisting and then reloading a stale
# RUNNING/COMPLETED snapshot across a restart would misrepresent
# real, current state rather than recover useful data -- it is
# exactly the "transient thread state" the persistence task
# explicitly says not to persist.
verification_progress = {}

# scan_ids for which automatic verification has already been queued,
# so a duplicate trigger (e.g. an accidental double dispatch) can
# never queue the same scan's findings twice. Finding-level dedup is
# separate and lives in auto_verification_service (it skips any
# finding that already has a verified_findings entry). Kept
# in-process for the same reason as verification_progress above: it
# guards a background thread that only exists within this process.
auto_verification_queued_scan_ids = set()