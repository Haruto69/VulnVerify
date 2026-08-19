from fastapi import (
    APIRouter,
    HTTPException,
)

from backend.models.report import ScanReport
from backend.services.report_service import build_scan_report


router = APIRouter(
    prefix="/scans",
    tags=["reports"],
)


@router.get(
    "/{scan_id}/report",
    response_model=ScanReport,
)
async def get_scan_report(
    scan_id: str,
):
    """
    Return a point-in-time structured report for one scan, built
    entirely from the existing pipeline's own data (see
    backend.services.report_service.build_scan_report).

    JSON is used deliberately rather than a PDF/binary format: it
    requires no new dependency, matches every other endpoint in this
    API, and the frontend downloads it directly as a file.
    """

    try:
        return build_scan_report(scan_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        ) from exc
