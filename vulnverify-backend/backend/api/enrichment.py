from fastapi import (
    APIRouter,
    HTTPException,
)

from backend.services.enrichment_service import enrich_findings
from backend.services.scan_service import (
    get_normalized_findings,
    get_scan,
)


router = APIRouter(
    prefix="/scans",
    tags=["enrichment"],
)


@router.get("/{scan_id}/enrichment")
async def list_enrichment(
    scan_id: str,
):
    """
    Return supplementary context for every normalized finding in a
    scan.

    Unlike /duplicate-groups and /risk-priorities, this endpoint does
    not require findings to have been verified first: enrichment is
    derived entirely from normalized (parser-supplied) data, so it is
    available immediately after upload.
    """

    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = get_normalized_findings(
        scan_id
    )

    enrichments = enrich_findings(
        findings=findings
    )

    return {
        "scan_id": scan_id,
        "count": len(enrichments),
        "enrichments": enrichments,
    }
