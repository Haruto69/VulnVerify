from enum import Enum

from pydantic import BaseModel


class GroundTruthStatus(str, Enum):
    """
    A ground-truth label states a fact about the underlying
    application, independent of what any scanner or verifier
    concluded: is the reported finding a real, exploitable
    vulnerability or not.

    Deliberately binary (no INCONCLUSIVE) -- ground truth records
    a known fact supplied by whoever is labeling the dataset, not a
    verifier's confidence level. A label the labeler is unsure about
    should not be submitted.
    """

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class GroundTruthLabel(BaseModel):
    finding_id: str
    expected_status: GroundTruthStatus
    note: str | None = None


class GroundTruthSubmission(BaseModel):
    labels: list[GroundTruthLabel]
