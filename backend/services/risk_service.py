from backend.models.normalized_finding import (
    NormalizedFinding,
    NormalizedSeverity,
)
from backend.models.risk_assessment import (
    FindingPriority,
    PriorityLevel,
)
from backend.models.verified_finding import (
    VerificationStatus,
    VerifiedFinding,
)

_SEVERITY_TO_PRIORITY: dict[NormalizedSeverity, PriorityLevel] = {
    NormalizedSeverity.CRITICAL: PriorityLevel.CRITICAL,
    NormalizedSeverity.HIGH: PriorityLevel.HIGH,
    NormalizedSeverity.MEDIUM: PriorityLevel.MEDIUM,
    NormalizedSeverity.LOW: PriorityLevel.LOW,
    NormalizedSeverity.INFORMATIONAL: PriorityLevel.INFORMATIONAL,
    # No scanner-reported severity is available. TRUE_POSITIVE/
    # INCONCLUSIVE both need a defined fallback; MEDIUM is used for
    # both, matching the approved V1 contract's explicit
    # UNKNOWN -> MEDIUM rule for TRUE_POSITIVE.
    NormalizedSeverity.UNKNOWN: PriorityLevel.MEDIUM,
}

_INCONCLUSIVE_CAP = PriorityLevel.MEDIUM

_PRIORITY_ORDER = [
    PriorityLevel.INFORMATIONAL,
    PriorityLevel.LOW,
    PriorityLevel.MEDIUM,
    PriorityLevel.HIGH,
    PriorityLevel.CRITICAL,
]


def assess_priorities(
    *,
    findings: list[tuple[NormalizedFinding, VerifiedFinding]],
) -> list[FindingPriority]:
    """
    Compute a deterministic PriorityLevel for each already-verified
    finding, from its VerificationStatus and the scanner's own
    NormalizedSeverity only.

    Pure function: no I/O, no repository access, no persistence.
    Never reads classification.confidence and never looks at
    deduplication group membership/size -- confidence is not
    comparable across verification families in this project (XSS
    currently reports a fixed 0.0 placeholder for every verdict), and
    no confidence-derived or CVSS-style score is invented here.

    Each entry in `findings` pairs a NormalizedFinding with the
    VerifiedFinding produced for it, mirroring
    backend.services.deduplication_service.group_duplicate_findings().
    Findings with no VerifiedFinding are the caller's concern to
    exclude before calling this function, exactly as the
    deduplication service does.
    """

    results: list[FindingPriority] = []

    for normalized, verified in findings:
        priority, reason = _assess_one(
            status=verified.classification.status,
            scanner_severity=(
                normalized.vulnerability.normalized_severity
            ),
        )

        results.append(
            FindingPriority(
                scan_id=normalized.scan_id,
                finding_id=verified.finding_id,
                priority=priority,
                reason=reason,
                verification_status=(
                    verified.classification.status
                ),
                scanner_severity=(
                    normalized.vulnerability.normalized_severity
                ),
            )
        )

    return results


def _assess_one(
    *,
    status: VerificationStatus,
    scanner_severity: NormalizedSeverity,
) -> tuple[PriorityLevel, str]:
    if status == VerificationStatus.FALSE_POSITIVE:
        return (
            PriorityLevel.INFORMATIONAL,
            "Verified FALSE_POSITIVE; priority is fixed at "
            "INFORMATIONAL regardless of scanner severity.",
        )

    mapped_priority = _SEVERITY_TO_PRIORITY[scanner_severity]

    if status == VerificationStatus.INCONCLUSIVE:
        capped_priority = _cap_priority(
            mapped_priority,
            _INCONCLUSIVE_CAP,
        )

        if capped_priority != mapped_priority:
            return (
                capped_priority,
                "Verified INCONCLUSIVE; scanner severity "
                f"{scanner_severity.value} was capped at "
                f"{capped_priority.value}.",
            )

        return (
            capped_priority,
            "Verified INCONCLUSIVE; scanner severity "
            f"{scanner_severity.value} preserved (at or below "
            "the INCONCLUSIVE cap).",
        )

    # TRUE_POSITIVE
    return (
        mapped_priority,
        "Verified TRUE_POSITIVE; priority follows scanner "
        f"severity {scanner_severity.value}.",
    )


def _cap_priority(
    priority: PriorityLevel,
    cap: PriorityLevel,
) -> PriorityLevel:
    if (
        _PRIORITY_ORDER.index(priority)
        > _PRIORITY_ORDER.index(cap)
    ):
        return cap

    return priority
