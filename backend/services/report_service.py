from datetime import datetime, timezone

from backend.models.report import ReportFinding, ScanReport
from backend.services.deduplication_service import (
    group_duplicate_findings,
)
from backend.services.evaluation_service import (
    compute_evaluation_metrics,
)
from backend.services.risk_service import assess_priorities
from backend.services.scan_service import (
    get_normalized_findings,
    get_scan,
    get_verified_findings,
)


def build_scan_report(scan_id: str) -> ScanReport:
    """
    Assemble a ScanReport for one scan from the existing pipeline's
    own data -- normalized findings, verified findings, risk
    priorities (via the same pairing convention already used by
    backend/api/risks.py and backend/api/scans.py's duplicate-groups
    endpoint), deduplication groups, and evaluation metrics.

    Raises ValueError if the scan does not exist; callers translate
    that into an HTTP 404, matching every other endpoint in this
    project.
    """

    scan = get_scan(scan_id)

    if scan is None:
        raise ValueError(f"Scan not found: {scan_id}")

    normalized = get_normalized_findings(scan_id)
    verified = get_verified_findings(scan_id)

    verified_by_id = {
        finding.finding_id: finding
        for finding in verified
    }

    paired = [
        (item, verified_by_id[item.finding_id])
        for item in normalized
        if item.finding_id in verified_by_id
    ]

    priorities_by_id = {
        priority.finding_id: priority
        for priority in assess_priorities(findings=paired)
    }

    true_positive_count = 0
    false_positive_count = 0
    inconclusive_count = 0
    unverified_count = 0

    report_findings: list[ReportFinding] = []

    for item in normalized:
        finding_verified = verified_by_id.get(item.finding_id)
        finding_priority = priorities_by_id.get(item.finding_id)

        if finding_verified is None:
            unverified_count += 1
        elif finding_verified.classification.status == "TRUE_POSITIVE":
            true_positive_count += 1
        elif finding_verified.classification.status == "FALSE_POSITIVE":
            false_positive_count += 1
        else:
            inconclusive_count += 1

        report_findings.append(
            ReportFinding(
                finding_id=item.finding_id,
                original_name=item.source.original_name,
                category=item.vulnerability.category,
                scanner_severity=(
                    item.vulnerability.normalized_severity
                ),
                normalized_url=item.target.normalized_url,
                parameter=item.target.parameter,
                cwe=item.vulnerability.cwe,
                verification_status=(
                    finding_verified.classification.status
                    if finding_verified
                    else None
                ),
                verification_reason=(
                    finding_verified.classification.reason
                    if finding_verified
                    else None
                ),
                priority=(
                    finding_priority.priority
                    if finding_priority
                    else None
                ),
                priority_reason=(
                    finding_priority.reason
                    if finding_priority
                    else None
                ),
            )
        )

    dedup_groups = group_duplicate_findings(findings=paired)

    return ScanReport(
        scan_id=scan_id,
        filename=scan["filename"],
        scanner=scan["scanner"],
        generated_at=datetime.now(timezone.utc),
        raw_finding_count=len(normalized),
        verified_count=len(verified),
        true_positive_count=true_positive_count,
        false_positive_count=false_positive_count,
        inconclusive_count=inconclusive_count,
        unverified_count=unverified_count,
        unique_vulnerability_count=len(dedup_groups),
        findings=report_findings,
        evaluation=compute_evaluation_metrics(scan_id),
    )
