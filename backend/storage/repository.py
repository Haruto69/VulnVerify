scans = {}

normalized_findings = {}

verified_findings = {}

# scan_id -> {finding_id: GroundTruthLabel}
ground_truth = {}

# scan_id -> automatic-verification progress dict (see
# backend/services/auto_verification_service.py). Absent entry means
# automatic verification was never started for that scan (e.g. a
# scan loaded from Scan History rather than freshly uploaded).
verification_progress = {}

# scan_ids for which automatic verification has already been queued,
# so a duplicate trigger (e.g. an accidental double dispatch) can
# never queue the same scan's findings twice. Finding-level dedup is
# separate and lives in auto_verification_service (it skips any
# finding that already has a verified_findings entry).
auto_verification_queued_scan_ids = set()