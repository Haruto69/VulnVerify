from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.services.scan_service import (
    create_scan,
    get_all_scans,
    get_scan,
)


router = APIRouter(
    prefix="/scans",
    tags=["scans"]
)


ALLOWED_EXTENSIONS = {".json", ".xml"}


@router.post("")
async def upload_scan(file: UploadFile = File(...)):
    extension = Path(file.filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Only .json and .xml files are allowed."
        )

    scan = create_scan(
        filename=file.filename,
        content_type=file.content_type
    )

    return scan


@router.get("")
async def list_scans():
    return get_all_scans()


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return {
        "scan_id": scan["scan_id"],
        "status": scan["status"]
    }