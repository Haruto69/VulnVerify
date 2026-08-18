from fastapi import (
    APIRouter,
    HTTPException,
)

from backend.services.risk_service import assess_priorities
from backend.services.scan_service import (
    get_normalized_findings,
    get_scan,
    get_verified_findings,
)


router = APIRouter(
    prefix="/scans",
    tags=["risk"],
)


@router.get("/{scan_id}/risk-priorities")
async def list_risk_priorities(
    scan_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    paired_findings = (
        _pair_normalized_and_verified_findings(
            scan_id
        )
    )

    priorities = assess_priorities(
        findings=paired_findings
    )

    return {
        "scan_id": scan_id,
        "count": len(priorities),
        "priorities": priorities,
    }


def _pair_normalized_and_verified_findings(
    scan_id: str,
):
    """
    Join normalized and verified findings for one scan by
    finding_id, for use by the risk-priority endpoint.

    Normalized findings with no matching verified finding are
    silently excluded, matching the same semantics already used by
    the deduplication endpoint (backend/api/scans.py) and the
    existing /verified-findings endpoint: only explicitly verified
    findings are considered.

    Duplicated locally rather than imported from
    backend.api.scans._pair_normalized_and_verified_findings --
    that helper is module-private, and this project's established
    convention (see the XSS query-mutation helper vs. the SQLi one)
    is to duplicate small, family/endpoint-local helpers rather than
    introduce a shared abstraction across router modules.
    """

    normalized_findings = get_normalized_findings(
        scan_id
    )

    verified_findings = get_verified_findings(
        scan_id
    )

    verified_by_id = {
        finding.finding_id: finding
        for finding in verified_findings
    }

    pairs = []

    for normalized in normalized_findings:
        verified = verified_by_id.get(
            normalized.finding_id
        )

        if verified is None:
            continue

        pairs.append(
            (normalized, verified)
        )

    return pairs
