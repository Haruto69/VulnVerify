from typing import Literal

from pydantic import BaseModel


class EvaluationMetrics(BaseModel):
    """
    Precision/recall/F1 computed only from findings that have both
    an explicit ground-truth label and a verification result for the
    same scan.

    evaluated_count is the number of findings actually included in
    the TP/FP/TN/FN matrix. It can be smaller than ground_truth_count
    when a labeled finding has not been verified yet
    (unverified_ground_truth_count) or was verified as INCONCLUSIVE
    (excluded_inconclusive_count) -- an INCONCLUSIVE verdict made no
    binary TRUE/FALSE decision, so it cannot be scored as correct or
    incorrect without fabricating one.

    precision/recall/f1 are null (never NaN/Infinity) whenever their
    denominator would be zero, per the project's "never fabricate
    metrics" rule.
    """

    schema_version: Literal["1.0"] = "1.0"

    scan_id: str

    ground_truth_count: int
    evaluated_count: int
    unverified_ground_truth_count: int
    excluded_inconclusive_count: int

    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    precision: float | None
    recall: float | None
    f1: float | None
