from fastapi import (
    APIRouter,
    HTTPException,
)

from backend.models.evaluation import EvaluationMetrics
from backend.models.ground_truth import GroundTruthSubmission
from backend.services.evaluation_service import (
    compute_evaluation_metrics,
)
from backend.services.ground_truth_service import (
    get_ground_truth_labels,
    load_demo_ground_truth,
    save_ground_truth_labels,
)
from backend.services.scan_service import get_scan


router = APIRouter(
    prefix="/scans",
    tags=["evaluation"],
)


@router.get("/{scan_id}/ground-truth")
async def list_ground_truth(
    scan_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    labels = get_ground_truth_labels(scan_id)

    return {
        "scan_id": scan_id,
        "count": len(labels),
        "labels": labels,
    }


@router.post("/{scan_id}/ground-truth")
async def submit_ground_truth(
    scan_id: str,
    submission: GroundTruthSubmission,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    try:
        labels = save_ground_truth_labels(
            scan_id,
            submission.labels,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "scan_id": scan_id,
        "count": len(labels),
        "labels": labels,
    }


@router.post("/{scan_id}/ground-truth/demo")
async def submit_demo_ground_truth(
    scan_id: str,
):
    """
    Match the bundled demo ground-truth dataset
    (backend/data/demo_ground_truth_labels.json) against this scan's
    normalized findings and persist labels for whatever matches.

    Intended for the hackathon demo path only: it lets the dashboard
    show real, non-fabricated precision/recall/F1 for the bundled
    DVWA SQLi fixture without requiring manual label entry. It never
    invents a label for a finding the demo dataset doesn't recognize
    -- if nothing matches, it returns an empty list.
    """

    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    labels = load_demo_ground_truth(scan_id)

    return {
        "scan_id": scan_id,
        "count": len(labels),
        "labels": labels,
    }


@router.get(
    "/{scan_id}/metrics",
    response_model=EvaluationMetrics,
)
async def get_metrics(
    scan_id: str,
):
    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return compute_evaluation_metrics(scan_id)
