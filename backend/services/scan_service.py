from uuid import uuid4

from backend.storage.repository import (
    auto_verification_queued_scan_ids,
    normalized_findings,
    scans,
    verification_progress,
    verified_findings,
)


def create_scan(
    filename: str,
    content_type: str,
    scanner: str,
):
    scan_id = str(uuid4())

    scan = {
        "scan_id": scan_id,
        "filename": filename,
        "content_type": content_type,
        "scanner": scanner,
        "status": "UPLOADED",
        "error": None,
    }

    scans[scan_id] = scan

    return scan


def get_all_scans():
    return list(scans.values())


def get_scan(scan_id: str):
    return scans.get(scan_id)


def update_scan_status(
    scan_id: str,
    status: str,
    error: str | None = None,
):
    scan = scans.get(scan_id)

    if scan is None:
        return None

    # Read-merge-write-back: the SQLite-backed ScanStore
    # (backend/storage/collections.py) returns a freshly-built dict
    # from each read, so mutating it in place would never persist --
    # the updated dict must be assigned back through __setitem__.
    updated = dict(scan)
    updated["status"] = status
    updated["error"] = error

    scans[scan_id] = updated

    return updated


def save_normalized_findings(
    scan_id: str,
    findings: list,
):
    normalized_findings[scan_id] = findings


def get_normalized_findings(
    scan_id: str,
):
    return normalized_findings.get(
        scan_id,
        [],
    )


def save_verified_finding(
    scan_id: str,
    finding,
):
    # Read-merge-write-back, for the same reason as
    # update_scan_status above -- VerifiedFindingsStore.__setitem__
    # replaces a scan's whole verified-findings collection in one
    # transaction, so the merged dict must be assigned back
    # explicitly rather than mutated through a stale reference.
    bucket = dict(verified_findings.get(scan_id, {}))
    bucket[finding.finding_id] = finding
    verified_findings[scan_id] = bucket


def get_verified_findings(
    scan_id: str,
):
    findings = verified_findings.get(
        scan_id,
        {},
    )

    return list(
        findings.values()
    )


def get_verified_finding(
    scan_id: str,
    finding_id: str,
):
    findings = verified_findings.get(
        scan_id,
        {},
    )

    return findings.get(
        finding_id
    )


def try_claim_scan_for_auto_verification(
    scan_id: str,
) -> bool:
    """
    Atomically claim a scan for automatic verification.

    Returns True the first time this is called for a given scan_id
    (the caller should proceed), and False on every subsequent call
    (the caller must not queue the same scan's findings again). This
    is the scan-level half of duplicate-verification protection --
    the finding-level half lives in auto_verification_service, which
    additionally skips any finding that already has a stored verified
    result.
    """

    if scan_id in auto_verification_queued_scan_ids:
        return False

    auto_verification_queued_scan_ids.add(scan_id)
    return True


def set_verification_progress(
    scan_id: str,
    progress: dict,
) -> None:
    verification_progress[scan_id] = progress


def get_verification_progress(
    scan_id: str,
) -> dict | None:
    return verification_progress.get(scan_id)