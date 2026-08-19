import threading
from pathlib import Path

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    UploadFile,
)

from backend.parsers import get_parser
from backend.services.auto_verification_service import (
    run_auto_verification,
)
from backend.services.deduplication_service import (
    group_duplicate_findings,
)
from backend.services.normalization_service import (
    normalize_scan,
)
from backend.services.scan_service import (
    create_scan,
    get_all_scans,
    get_normalized_findings,
    get_scan,
    get_verification_progress,
    get_verified_finding,
    get_verified_findings,
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

    # Dispatched on a detached daemon thread rather than FastAPI's
    # BackgroundTasks: run_auto_verification does blocking replay I/O
    # (httpx.Client, not an async client) that can take noticeable
    # time across several findings, and Starlette's BackgroundTasks
    # execute as part of the same request/response lifecycle -- under
    # a synchronous test client, or under real load, that would make
    # every upload block until every finding's replay finishes,
    # exactly what this feature exists to avoid. daemon=True also
    # means a still-running verification thread can never block
    # process/interpreter shutdown. This fire-and-forget dispatch
    # only ever happens for a fresh upload, never when a scan is
    # merely reloaded (e.g. from Scan History), since that path never
    # calls this endpoint.
    threading.Thread(
        target=run_auto_verification,
        args=(scan_id,),
        daemon=True,
    ).start()

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


@router.get("/{scan_id}/verification-progress")
async def get_scan_verification_progress(
    scan_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    progress = get_verification_progress(scan_id)

    if progress is None:
        # Automatic verification was never started for this scan
        # (e.g. it was loaded from Scan History rather than freshly
        # uploaded) -- a real, distinct state, not "running".
        return {
            "scan_id": scan_id,
            "status": "NOT_STARTED",
            "total": 0,
            "completed": 0,
            "current": None,
            "counts": {
                "TRUE_POSITIVE": 0,
                "FALSE_POSITIVE": 0,
                "INCONCLUSIVE": 0,
            },
            "errors": [],
        }

    return {
        "scan_id": scan_id,
        **progress,
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


@router.get("/{scan_id}/verified-findings")
async def list_verified_findings(
    scan_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = get_verified_findings(
        scan_id
    )

    return {
        "scan_id": scan_id,
        "count": len(findings),
        "findings": findings,
    }


@router.get(
    "/{scan_id}/verified-findings/{finding_id}"
)
async def read_verified_finding(
    scan_id: str,
    finding_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    finding = get_verified_finding(
        scan_id=scan_id,
        finding_id=finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Verified finding not found",
        )

    return finding


@router.get("/{scan_id}/duplicate-groups")
async def list_duplicate_groups(
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

    groups = group_duplicate_findings(
        findings=paired_findings
    )

    return {
        "scan_id": scan_id,
        "count": len(groups),
        "groups": groups,
    }


def _pair_normalized_and_verified_findings(
    scan_id: str,
):
    """
    Join normalized and verified findings for one scan by
    finding_id, for use by the deduplication endpoint.

    Normalized findings with no matching verified finding are
    silently excluded, matching the existing /verified-findings
    endpoint's semantics: only explicitly verified findings are
    considered.
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