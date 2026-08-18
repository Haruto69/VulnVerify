from backend.models.deduplicated_finding import (
    DuplicateGroup,
    DuplicateGroupMember,
)
from backend.models.normalized_finding import (
    NormalizedFinding,
    VulnerabilityCategory,
)
from backend.models.verified_finding import VerifiedFinding

GroupKey = tuple[VulnerabilityCategory, str, str | None]


def group_duplicate_findings(
    *,
    findings: list[
        tuple[NormalizedFinding, VerifiedFinding]
    ],
) -> list[DuplicateGroup]:
    """
    Group verified findings from a single scan by
    (category, normalized_url, parameter).

    Pure grouping only: no I/O, no repository access, no persistence.
    Does not choose a representative finding, does not merge or adjust
    any member's existing VerificationClassification, and does not
    invent a confidence value. Inputs are read only, never mutated.

    Each entry in `findings` pairs a NormalizedFinding with the
    VerifiedFinding produced for it -- VerifiedFinding alone does not
    carry category/normalized_url/parameter/scan_id, so the
    NormalizedFinding is required to compute the grouping key.

    Deduplication is single-scan only in this slice: every finding
    must belong to the same scan_id (NormalizedFinding.scan_id), or a
    ValueError is raised rather than silently grouping across scans.
    """

    if not findings:
        return []

    scan_ids = {
        normalized.scan_id
        for normalized, _ in findings
    }

    if len(scan_ids) > 1:
        raise ValueError(
            "group_duplicate_findings() received findings from "
            f"multiple scans ({sorted(scan_ids)}); deduplication is "
            "single-scan only in this slice."
        )

    scan_id = next(iter(scan_ids))

    key_order: list[GroupKey] = []

    members_by_key: dict[
        GroupKey, list[DuplicateGroupMember]
    ] = {}

    for normalized, verified in findings:
        if normalized.finding_id != verified.finding_id:
            raise ValueError(
                "NormalizedFinding.finding_id "
                f"({normalized.finding_id!r}) does not match "
                "VerifiedFinding.finding_id "
                f"({verified.finding_id!r}); findings must be "
                "correctly paired"
            )

        key = (
            normalized.vulnerability.category,
            normalized.target.normalized_url,
            normalized.target.parameter,
        )

        if key not in members_by_key:
            members_by_key[key] = []
            key_order.append(key)

        members_by_key[key].append(
            DuplicateGroupMember(
                finding_id=verified.finding_id,
                classification=verified.classification,
            )
        )

    return [
        DuplicateGroup(
            scan_id=scan_id,
            category=key[0],
            normalized_url=key[1],
            parameter=key[2],
            members=members_by_key[key],
        )
        for key in key_order
    ]
