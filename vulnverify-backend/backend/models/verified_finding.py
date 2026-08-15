from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class VerificationStatus(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationClassification(BaseModel):
    status: VerificationStatus
    confidence: float
    reason: str


class VerificationEvidence(BaseModel):
    indicators: list[str] = Field(default_factory=list)

    request_reference: str | None = None
    response_reference: str | None = None


class VerifiedFinding(BaseModel):
    schema_version: Literal["1.0"] = "1.0"

    finding_id: str

    classification: VerificationClassification
    evidence: VerificationEvidence

    verification_method: str