from pathlib import Path

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    UploadFile,
)

from backend.parsers import get_parser
from backend.services.normalization_service import normalize_scan
from backend.services.scan_service import (
    create_scan,
    get_all_scans,
    get_normalized_findings,
    get_scan,
    save_normalized_findings,
    update_scan_status,
)


router = APIRouter(
    prefix="/scans",
    tags=["scans"],
)


ALLOWED_EXTENSIONS = {
    ".json",
    ".xml",
}

ALLOWED_SCANNERS = {
    "ZAP",
    "BURP",
}


@router.post("")
async def upload_scan(
    scanner: str = Form(...),
    file: UploadFile = File(...),
):
    scanner_name = scanner.strip().upper()

    if scanner_name not in ALLOWED_SCANNERS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported scanner. "
                "Allowed values are ZAP and BURP."
            ),
        )

    extension = Path(
        file.filename or ""
    ).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                "Only .json and .xml files are allowed."
            ),
        )

    scan = create_scan(
        filename=file.filename or "",
        content_type=file.content_type or "",
        scanner=scanner_name,
    )

    scan_id = scan["scan_id"]

    try:
        content = await file.read()

        parser = get_parser(
            scanner_name
        )

        findings = normalize_scan(
            parser=parser,
            content=content,
            scan_id=scan_id,
        )

        save_normalized_findings(
            scan_id=scan_id,
            findings=findings,
        )

        update_scan_status(
            scan_id=scan_id,
            status="NORMALIZED",
        )

    except Exception as exc:
        update_scan_status(
            scan_id=scan_id,
            status="FAILED",
            error=str(exc),
        )

        raise HTTPException(
            status_code=400,
            detail=(
                f"Failed to normalize scan: {exc}"
            ),
        ) from exc

    return {
        "scan_id": scan_id,
        "filename": scan["filename"],
        "scanner": scanner_name,
        "status": "NORMALIZED",
        "finding_count": len(findings),
    }


@router.get("")
async def list_scans():
    return get_all_scans()


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return {
        "scan_id": scan["scan_id"],
        "status": scan["status"],
        "error": scan["error"],
    }


@router.get("/{scan_id}/findings")
async def list_normalized_findings(
    scan_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = get_normalized_findings(
        scan_id
    )

    return {
        "scan_id": scan_id,
        "count": len(findings),
        "findings": findings,
    }