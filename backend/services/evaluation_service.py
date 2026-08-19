from backend.models.evaluation import EvaluationMetrics
from backend.models.ground_truth import GroundTruthStatus
from backend.models.verified_finding import VerificationStatus
from backend.services.ground_truth_service import get_ground_truth_labels
from backend.services.scan_service import get_verified_finding


def compute_evaluation_metrics(
    scan_id: str,
) -> EvaluationMetrics:
    """
    Compute TP/FP/TN/FN and precision/recall/F1 for one scan,
    scoped strictly to findings that have both an explicit
    ground-truth label and a verification result.

    Evaluation universe and TP/FP/TN/FN semantics:
      - "Positive" (predicted) means the verifier concluded
        TRUE_POSITIVE; "negative" means it concluded FALSE_POSITIVE.
        A verifier verdict of INCONCLUSIVE makes no binary decision,
        so those findings are excluded from the matrix entirely
        (counted separately in excluded_inconclusive_count) rather
        than being guessed into TP/FP/TN/FN.
      - "Actual" positive/negative comes only from an explicit
        GroundTruthLabel for that finding_id -- never inferred from
        scanner severity/confidence or from the verifier's own
        output. A labeled finding with no verification result yet
        is counted in unverified_ground_truth_count and excluded
        from the matrix, not silently treated as a negative.

    This project has no notion of "findings the scanner should have
    reported but didn't" -- the evaluation universe is exactly the
    set of scanner-reported findings that a human has explicitly
    labeled, so TN/FN are only ever derived from labeled findings,
    never fabricated from absent scanner coverage.
    """

    labels = get_ground_truth_labels(scan_id)

    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0
    excluded_inconclusive_count = 0
    unverified_ground_truth_count = 0

    for label in labels:
        verified = get_verified_finding(
            scan_id,
            label.finding_id,
        )

        if verified is None:
            unverified_ground_truth_count += 1
            continue

        predicted_status = verified.classification.status

        if predicted_status == VerificationStatus.INCONCLUSIVE:
            excluded_inconclusive_count += 1
            continue

        actual_positive = (
            label.expected_status
            == GroundTruthStatus.TRUE_POSITIVE
        )
        predicted_positive = (
            predicted_status
            == VerificationStatus.TRUE_POSITIVE
        )

        if actual_positive and predicted_positive:
            true_positive += 1
        elif not actual_positive and predicted_positive:
            false_positive += 1
        elif not actual_positive and not predicted_positive:
            true_negative += 1
        else:
            false_negative += 1

    evaluated_count = (
        true_positive
        + false_positive
        + true_negative
        + false_negative
    )

    precision = _safe_divide(
        true_positive,
        true_positive + false_positive,
    )
    recall = _safe_divide(
        true_positive,
        true_positive + false_negative,
    )
    f1 = _safe_f1(precision, recall)

    return EvaluationMetrics(
        scan_id=scan_id,
        ground_truth_count=len(labels),
        evaluated_count=evaluated_count,
        unverified_ground_truth_count=(
            unverified_ground_truth_count
        ),
        excluded_inconclusive_count=(
            excluded_inconclusive_count
        ),
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def _safe_divide(
    numerator: int,
    denominator: int,
) -> float | None:
    if denominator == 0:
        return None

    return numerator / denominator


def _safe_f1(
    precision: float | None,
    recall: float | None,
) -> float | None:
    if precision is None or recall is None:
        return None

    if precision + recall == 0:
        return None

    return 2 * precision * recall / (precision + recall)
