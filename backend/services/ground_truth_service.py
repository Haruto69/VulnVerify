import json
from pathlib import Path

from backend.models.ground_truth import GroundTruthLabel
from backend.services.scan_service import get_normalized_findings
from backend.storage.repository import ground_truth

DEMO_LABELS_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "demo_ground_truth_labels.json"
)


def save_ground_truth_labels(
    scan_id: str,
    labels: list[GroundTruthLabel],
) -> list[GroundTruthLabel]:
    """
    Persist explicit ground-truth labels for a scan.

    Each finding_id must belong to a normalized finding that already
    exists for this scan_id -- ground truth is scoped to real
    findings, never accepted blind, matching the same "does this
    finding_id exist for this scan" check the verify endpoint already
    performs (backend/api/findings.py).
    """

    known_ids = {
        finding.finding_id
        for finding in get_normalized_findings(scan_id)
    }

    unknown_ids = [
        label.finding_id
        for label in labels
        if label.finding_id not in known_ids
    ]

    if unknown_ids:
        raise ValueError(
            "Unknown finding_id(s) for this scan: "
            + ", ".join(unknown_ids)
        )

    bucket = ground_truth.setdefault(scan_id, {})

    for label in labels:
        bucket[label.finding_id] = label

    return list(bucket.values())


def get_ground_truth_labels(
    scan_id: str,
) -> list[GroundTruthLabel]:
    return list(
        ground_truth.get(scan_id, {}).values()
    )


def load_demo_ground_truth(
    scan_id: str,
) -> list[GroundTruthLabel]:
    """
    Match the bundled demo dataset (backend/data/demo_ground_truth_labels.json)
    against this scan's normalized findings by (scanner,
    scanner_finding_id, path, parameter), and persist ground-truth
    labels for whichever findings match.

    This is not a second persistence system: matches are converted
    into ordinary GroundTruthLabel entries and stored exactly like
    manually-submitted ones, keyed by this scan's own finding_id.

    Findings that don't match any demo entry simply receive no
    label -- this never fabricates a label for a finding the demo
    dataset doesn't recognize.
    """

    demo_entries = json.loads(
        DEMO_LABELS_PATH.read_text(encoding="utf-8")
    )

    matched_labels: list[GroundTruthLabel] = []

    for finding in get_normalized_findings(scan_id):
        for entry in demo_entries:
            if _matches(finding, entry):
                matched_labels.append(
                    GroundTruthLabel(
                        finding_id=finding.finding_id,
                        expected_status=entry["expected_status"],
                        note=entry.get("note"),
                    )
                )
                break

    if not matched_labels:
        return []

    return save_ground_truth_labels(
        scan_id,
        matched_labels,
    )


def _matches(finding, entry: dict) -> bool:
    return (
        (finding.source.scanner or "").strip().upper()
        == entry["scanner"].strip().upper()
        and finding.source.scanner_finding_id
        == entry["scanner_finding_id"]
        and finding.target.path == entry["path"]
        and finding.target.parameter == entry["parameter"]
    )
