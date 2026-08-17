from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher

from backend.verification.sqli_contract import (
    SqliDecision,
    SqliReasonCode,
    SqliVerificationStatus,
    controlled_false_positive_confidence,
    inconclusive_decision,
    repeated_absence_false_positive_confidence,
    safe_handling_false_positive_confidence,
    true_positive_confidence,
)
from backend.verification.sqli_response import (
    BOOLEAN_MATERIAL_SIMILARITY_MAX,
    ResponseObservation,
    evaluate_non_time_baseline,
    normalize_response_body,
)


@dataclass(frozen=True)
class BooleanComparisonTrial:
    true_response: ResponseObservation
    false_response: ResponseObservation
    true_request_reference: str | None = None
    false_request_reference: str | None = None


@dataclass(frozen=True)
class BooleanTrialResult:
    similarity: float
    status_difference: bool
    true_marker_matched: bool
    false_marker_matched: bool
    material_difference: bool
    response_class: str | None


@dataclass(frozen=True)
class BooleanBasedEvidence:
    true_request: tuple[str | None, ...]
    true_response: tuple[str, ...]
    false_request: tuple[str | None, ...]
    false_response: tuple[str, ...]
    normalized_true_body: tuple[str, ...]
    normalized_false_body: tuple[str, ...]
    sequence_similarity: tuple[float, ...]
    status_difference: tuple[bool, ...]
    semantic_difference: tuple[bool, ...]
    response_class: tuple[str | None, ...]
    repetition_matrix: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class BooleanBasedEvaluation:
    decision: SqliDecision
    evidence: BooleanBasedEvidence


def evaluate_boolean_based_sqli(
    *,
    baseline_responses: list[ResponseObservation],
    comparisons: list[BooleanComparisonTrial],
    parameter_dependency_established: bool,
    scanner_true_marker: str | None = None,
    scanner_false_marker: str | None = None,
    scanner_evidence_agrees: bool = False,
    control_equivalence_established: bool = False,
    safe_parameter_handling_established: bool = False,
    safe_non_sql_explanation_established: bool = False,
) -> BooleanBasedEvaluation:
    baseline = evaluate_non_time_baseline(
        baseline_responses
    )

    valid_comparisons = [
        comparison
        for comparison in comparisons
        if (
            comparison.true_response.valid
            and comparison.false_response.valid
        )
    ][:3]

    trial_results = tuple(
        _evaluate_trial(
            comparison,
            scanner_true_marker=scanner_true_marker,
            scanner_false_marker=scanner_false_marker,
        )
        for comparison in valid_comparisons
    )

    evidence = _build_evidence(
        valid_comparisons,
        trial_results,
    )

    if not baseline.stable:
        return BooleanBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_UNSTABLE_BASELINE,
                "A stable non-time SQLi baseline could not be established.",
            ),
            evidence=evidence,
        )

    if not comparisons:
        return BooleanBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_INSUFFICIENT_SCANNER_EVIDENCE,
                "The scanner did not provide a usable TRUE/FALSE Boolean request pair. Backend must not generate the missing condition.",
            ),
            evidence=evidence,
        )

    if len(valid_comparisons) < 3:
        return BooleanBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS,
                "Fewer than three valid BOOLEAN_BASED TRUE/FALSE comparisons were available.",
            ),
            evidence=evidence,
        )

    if control_equivalence_established:
        return BooleanBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=controlled_false_positive_confidence(),
                reason_code=(
                    SqliReasonCode.FP_BOOLEAN_CONTROL_EQUIVALENCE
                ),
                reason=(
                    "Controlled baseline evidence establishes that the observed TRUE/FALSE relationship is normal and not SQL-dependent."
                ),
                indicators=("boolean_control_equivalence",),
            ),
            evidence=evidence,
        )

    material_count = sum(
        result.material_difference
        for result in trial_results
    )

    repeated_class = _repeated_response_class(
        trial_results
    )

    if (
        material_count >= 2
        and repeated_class is not None
        and parameter_dependency_established
    ):
        return BooleanBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.TRUE_POSITIVE,
                confidence=true_positive_confidence(
                    scanner_evidence_agrees=(
                        scanner_evidence_agrees
                    )
                ),
                reason_code=(
                    SqliReasonCode.TP_BOOLEAN_RESPONSE_DIFFERENCE
                ),
                reason=(
                    "A material TRUE/FALSE response-class difference was reproduced in at least two of three valid comparisons and is attributable to the tested parameter."
                ),
                indicators=(
                    "boolean_difference_reproduced_2_of_3",
                    "parameter_dependency_established",
                    repeated_class,
                ),
            ),
            evidence=evidence,
        )

    if safe_parameter_handling_established:
        return BooleanBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=safe_handling_false_positive_confidence(),
                reason_code=SqliReasonCode.FP_SAFE_PARAMETER_HANDLING,
                reason=(
                    "Deterministic safe or non-SQL parameter handling disproves the scanner's Boolean SQLi claim."
                ),
                indicators=("safe_parameter_handling_established",),
            ),
            evidence=evidence,
        )

    if (
        material_count == 0
        and safe_non_sql_explanation_established
    ):
        return BooleanBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=repeated_absence_false_positive_confidence(),
                reason_code=SqliReasonCode.FP_NO_BOOLEAN_DIFFERENCE,
                reason=(
                    "All required Boolean comparisons completed without a material SQL-dependent difference and a controlled safe or non-SQL explanation was established."
                ),
                indicators=("no_material_boolean_difference",),
            ),
            evidence=evidence,
        )

    return BooleanBasedEvaluation(
        decision=inconclusive_decision(
            SqliReasonCode.INC_AMBIGUOUS_BOOLEAN_RESPONSE,
            "The available Boolean response evidence does not satisfy the deterministic TRUE_POSITIVE or controlled FALSE_POSITIVE contract.",
        ),
        evidence=evidence,
    )


def _evaluate_trial(
    comparison: BooleanComparisonTrial,
    *,
    scanner_true_marker: str | None,
    scanner_false_marker: str | None,
) -> BooleanTrialResult:
    true_body = normalize_response_body(
        comparison.true_response.body
    )
    false_body = normalize_response_body(
        comparison.false_response.body
    )

    similarity = SequenceMatcher(
        None,
        true_body,
        false_body,
    ).ratio()

    status_difference = (
        comparison.true_response.status_code
        != comparison.false_response.status_code
    )

    true_marker_matched = bool(
        scanner_true_marker
        and scanner_true_marker in comparison.true_response.body
        and scanner_true_marker not in comparison.false_response.body
    )

    false_marker_matched = bool(
        scanner_false_marker
        and scanner_false_marker in comparison.false_response.body
        and scanner_false_marker not in comparison.true_response.body
    )

    response_class = None

    if true_marker_matched:
        response_class = "TRUE_MARKER_SPLIT"
    elif false_marker_matched:
        response_class = "FALSE_MARKER_SPLIT"
    elif status_difference:
        response_class = (
            "STATUS_SPLIT:"
            f"{comparison.true_response.status_code}:"
            f"{comparison.false_response.status_code}"
        )
    elif similarity < BOOLEAN_MATERIAL_SIMILARITY_MAX:
        response_class = "BODY_SIMILARITY_SPLIT"

    return BooleanTrialResult(
        similarity=similarity,
        status_difference=status_difference,
        true_marker_matched=true_marker_matched,
        false_marker_matched=false_marker_matched,
        material_difference=response_class is not None,
        response_class=response_class,
    )


def _repeated_response_class(
    trial_results: tuple[BooleanTrialResult, ...],
) -> str | None:
    counts = Counter(
        result.response_class
        for result in trial_results
        if result.response_class is not None
    )

    for response_class, count in counts.items():
        if count >= 2:
            return response_class

    return None


def _build_evidence(
    comparisons: list[BooleanComparisonTrial],
    trial_results: tuple[BooleanTrialResult, ...],
) -> BooleanBasedEvidence:
    class_counts = Counter(
        result.response_class
        for result in trial_results
        if result.response_class is not None
    )

    return BooleanBasedEvidence(
        true_request=tuple(
            comparison.true_request_reference
            for comparison in comparisons
        ),
        true_response=tuple(
            comparison.true_response.body
            for comparison in comparisons
        ),
        false_request=tuple(
            comparison.false_request_reference
            for comparison in comparisons
        ),
        false_response=tuple(
            comparison.false_response.body
            for comparison in comparisons
        ),
        normalized_true_body=tuple(
            normalize_response_body(
                comparison.true_response.body
            )
            for comparison in comparisons
        ),
        normalized_false_body=tuple(
            normalize_response_body(
                comparison.false_response.body
            )
            for comparison in comparisons
        ),
        sequence_similarity=tuple(
            result.similarity
            for result in trial_results
        ),
        status_difference=tuple(
            result.status_difference
            for result in trial_results
        ),
        semantic_difference=tuple(
            result.material_difference
            for result in trial_results
        ),
        response_class=tuple(
            result.response_class
            for result in trial_results
        ),
        repetition_matrix=tuple(
            sorted(class_counts.items())
        ),
    )
