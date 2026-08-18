from enum import Enum
from typing import Literal

from pydantic import BaseModel

from backend.models.normalized_finding import NormalizedSeverity
from backend.models.verified_finding import VerificationStatus


class PriorityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingPriority(BaseModel):
    """
    A deterministic priority classification for one already-verified
    finding, derived only from its VerificationStatus and the
    scanner's own NormalizedSeverity.

    Never derived from classification.confidence (not comparable
    across verification families in this project) or from
    deduplication group membership/size. Not a CVSS score and not a
    numeric risk score -- priority is a closed, ordinal classification.
    """

    schema_version: Literal["1.0"] = "1.0"

    scan_id: str
    finding_id: str

    priority: PriorityLevel
    reason: str

    verification_status: VerificationStatus
    scanner_severity: NormalizedSeverity
