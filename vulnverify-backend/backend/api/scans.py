from fastapi import APIRouter, UploadFile, File

router = APIRouter(
    prefix="/scans",
    tags=["scans"]
)


@router.post("")
async def upload_scan(file: UploadFile = File(...)):
    return {
        "filename": file.filename,
        "content_type": file.content_type
    }


@router.get("")
async def list_scans():
    return []