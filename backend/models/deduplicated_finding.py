from typing import Literal

from pydantic import BaseModel, Field

from backend.models.normalized_finding import VulnerabilityCategory
from backend.models.verified_finding import VerificationClassification


class DuplicateGroupMember(BaseModel):
    """
    One finding's identity and existing verification result within a
    DuplicateGroup.

    classification is the member's own, already-computed
    VerificationClassification, carried over unchanged. Grouping never
    creates, merges, or adjusts a classification or confidence value.
    """

    finding_id: str
    classification: VerificationClassification


class DuplicateGroup(BaseModel):
    """
    A set of findings from a single scan that share the same
    (category, normalized_url, parameter) grouping key.

    This model only records group membership. It does not choose a
    representative finding and does not combine member classifications
    into a single verdict -- each member's classification remains
    individually visible via `members`.
    """

    schema_version: Literal["1.0"] = "1.0"

    scan_id: str

    category: VulnerabilityCategory
    normalized_url: str
    parameter: str | None = None

    members: list[DuplicateGroupMember] = Field(
        default_factory=list
    )
