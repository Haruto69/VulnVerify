from uuid import uuid4

from backend.storage.repository import (
    normalized_findings,
    scans,
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

    scan["status"] = status
    scan["error"] = error

    return scan


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
    if scan_id not in verified_findings:
        verified_findings[scan_id] = {}

    verified_findings[scan_id][
        finding.finding_id
    ] = finding


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