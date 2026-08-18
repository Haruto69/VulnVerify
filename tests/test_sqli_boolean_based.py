from backend.verification.sqli_boolean_based import (
    BooleanComparisonTrial,
    evaluate_boolean_based_sqli,
)
from backend.verification.sqli_contract import (
    SqliReasonCode,
    SqliVerificationStatus,
)
from backend.verification.sqli_response import (
    BOOLEAN_MATERIAL_SIMILARITY_MAX,
    normalize_response_body,
)
from tests.sqli_helpers import (
    DIFFERENT_BODY,
    STABLE_BODY,
    observation,
    stable_baseline,
)


EMPTY_RESULT_BODY = (
    "<html><body><h1>Catalog</h1>No results found.</body></html>"
)

TRUE_REFLECTION_BODY = STABLE_BODY.replace(
    "Catalog",
    "Catalog for 1=1",
)

FALSE_REFLECTION_BODY = STABLE_BODY.replace(
    "Catalog",
    "Catalog for 1=2",
)


def body_split_trial(
    index: int = 0,
) -> BooleanComparisonTrial:
    """TRUE renders rows, FALSE renders an empty result page."""

    return BooleanComparisonTrial(
        true_response=observation(STABLE_BODY),
        false_response=observation(EMPTY_RESULT_BODY),
        true_request_reference=f"req-true-{index}",
        false_request_reference=f"req-false-{index}",
    )


def status_split_trial(
    index: int = 0,
) -> BooleanComparisonTrial:
    return BooleanComparisonTrial(
        true_response=observation(STABLE_BODY, status=200),
        false_response=observation(STABLE_BODY, status=404),
        true_request_reference=f"req-true-{index}",
        false_request_reference=f"req-false-{index}",
    )


def identical_trial(index: int = 0) -> BooleanComparisonTrial:
    return BooleanComparisonTrial(
        true_response=observation(STABLE_BODY),
        false_response=observation(STABLE_BODY),
        true_request_reference=f"req-true-{index}",
        false_request_reference=f"req-false-{index}",
    )


def reflection_only_trial(
    index: int = 0,
) -> BooleanComparisonTrial:
    return BooleanComparisonTrial(
        true_response=observation(TRUE_REFLECTION_BODY),
        false_response=observation(FALSE_REFLECTION_BODY),
        true_request_reference=f"req-true-{index}",
        false_request_reference=f"req-false-{index}",
    )


def invalid_trial(
    reason: str = "RATE_LIMITED",
    status: int | None = 429,
) -> BooleanComparisonTrial:
    blocked = observation(
        "",
        status=status,
        valid=False,
        failure_reasons=(reason,),
    )

    return BooleanComparisonTrial(
        true_response=blocked,
        false_response=blocked,
    )


def evaluate(**overrides):
    kwargs = {
        "baseline_responses": stable_baseline(),
        "comparisons": [
            body_split_trial(index)
            for index in range(3)
        ],
        "parameter_dependency_established": True,
    }
    kwargs.update(overrides)

    return evaluate_boolean_based_sqli(**kwargs)


# ---------------------------------------------------------------------
# TRUE_POSITIVE
# ---------------------------------------------------------------------


def test_material_true_false_body_difference_is_a_true_positive():
    result = evaluate()

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.TP_BOOLEAN_RESPONSE_DIFFERENCE
    )
    assert result.decision.confidence == 0.98


def test_status_code_split_is_a_material_difference():
    result = evaluate(
        comparisons=[
            status_split_trial(index)
            for index in range(3)
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        "STATUS_SPLIT:200:404"
        in result.decision.indicators
    )


def test_scanner_marker_split_is_a_material_difference():
    trial = BooleanComparisonTrial(
        true_response=observation(
            STABLE_BODY + "WELCOME_ADMIN"
        ),
        false_response=observation(STABLE_BODY),
    )

    result = evaluate(
        comparisons=[trial, trial, trial],
        scanner_true_marker="WELCOME_ADMIN",
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert "TRUE_MARKER_SPLIT" in result.decision.indicators


def test_true_positive_confidence_rises_when_scanner_agrees():
    result = evaluate(scanner_evidence_agrees=True)

    assert result.decision.confidence == 0.99


def test_two_of_three_comparisons_are_enough():
    result = evaluate(
        comparisons=[
            body_split_trial(0),
            identical_trial(1),
            body_split_trial(2),
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        "boolean_difference_reproduced_2_of_3"
        in result.decision.indicators
    )


def test_one_of_three_comparisons_is_not_enough():
    result = evaluate(
        comparisons=[
            body_split_trial(0),
            identical_trial(1),
            identical_trial(2),
        ]
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )


def test_two_different_response_classes_do_not_reproduce_each_other():
    result = evaluate(
        comparisons=[
            body_split_trial(0),
            status_split_trial(1),
            identical_trial(2),
        ]
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )


def test_without_parameter_dependency_there_is_no_true_positive():
    result = evaluate(
        parameter_dependency_established=False
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


# ---------------------------------------------------------------------
# Insufficient difference / reflection
# ---------------------------------------------------------------------


def test_identical_true_false_responses_are_not_a_true_positive():
    result = evaluate(
        comparisons=[
            identical_trial(index)
            for index in range(3)
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_AMBIGUOUS_BOOLEAN_RESPONSE
    )


def test_reflection_alone_does_not_prove_boolean_sqli():
    result = evaluate(
        comparisons=[
            reflection_only_trial(index)
            for index in range(3)
        ]
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )
    assert all(
        difference is False
        for difference in result.evidence.semantic_difference
    )


def test_reflection_only_similarity_stays_above_the_material_floor():
    similarity = evaluate(
        comparisons=[
            reflection_only_trial(index)
            for index in range(3)
        ]
    ).evidence.sequence_similarity

    assert all(
        value >= BOOLEAN_MATERIAL_SIMILARITY_MAX
        for value in similarity
    )


def test_similarity_below_the_material_floor_is_a_difference():
    result = evaluate()

    assert all(
        value < BOOLEAN_MATERIAL_SIMILARITY_MAX
        for value in result.evidence.sequence_similarity
    )
    assert all(result.evidence.semantic_difference)


def test_inability_to_reproduce_alone_is_not_a_false_positive():
    result = evaluate(
        comparisons=[
            identical_trial(index)
            for index in range(3)
        ]
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.FALSE_POSITIVE
    )


# ---------------------------------------------------------------------
# FALSE_POSITIVE
# ---------------------------------------------------------------------


def test_control_equivalence_is_a_controlled_false_positive():
    result = evaluate(
        control_equivalence_established=True
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.FP_BOOLEAN_CONTROL_EQUIVALENCE
    )
    assert result.decision.confidence == 0.97


def test_control_equivalence_outranks_a_reproduced_difference():
    result = evaluate(
        comparisons=[
            body_split_trial(index)
            for index in range(3)
        ],
        control_equivalence_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )


def test_safe_parameter_handling_is_a_false_positive():
    result = evaluate(
        comparisons=[
            identical_trial(index)
            for index in range(3)
        ],
        safe_parameter_handling_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.FP_SAFE_PARAMETER_HANDLING
    )
    assert result.decision.confidence == 0.96


def test_no_difference_plus_controlled_explanation_is_a_false_positive():
    result = evaluate(
        comparisons=[
            identical_trial(index)
            for index in range(3)
        ],
        safe_non_sql_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.FP_NO_BOOLEAN_DIFFERENCE
    )
    assert result.decision.confidence == 0.93


def test_controlled_explanation_needs_zero_material_differences():
    result = evaluate(
        comparisons=[
            body_split_trial(0),
            identical_trial(1),
            identical_trial(2),
        ],
        safe_non_sql_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


# ---------------------------------------------------------------------
# Failure contract and baseline -> INCONCLUSIVE
# ---------------------------------------------------------------------


def test_unstable_baseline_is_inconclusive():
    result = evaluate(
        baseline_responses=[
            observation(STABLE_BODY),
            observation(DIFFERENT_BODY),
            observation("<html><body>third variant</body></html>"),
            observation("<html><body>fourth variant x</body></html>"),
            observation("<html><body>fifth variant yz</body></html>"),
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_UNSTABLE_BASELINE
    )


def test_unstable_baseline_outranks_control_equivalence():
    result = evaluate(
        baseline_responses=[observation()],
        control_equivalence_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_missing_scanner_pair_is_inconclusive():
    result = evaluate(comparisons=[])

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_INSUFFICIENT_SCANNER_EVIDENCE
    )
    assert "must not generate" in result.decision.reason


def test_authentication_failure_is_inconclusive():
    result = evaluate(
        comparisons=[
            invalid_trial("AUTHENTICATION_REQUIRED", 401)
            for _ in range(3)
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS
    )


def test_session_expiry_is_inconclusive():
    result = evaluate(
        comparisons=[
            invalid_trial("SESSION_EXPIRED", 419)
            for _ in range(3)
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_waf_block_is_inconclusive():
    result = evaluate(
        comparisons=[
            invalid_trial("WAF_BLOCKED", 403)
            for _ in range(3)
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_rate_limiting_is_inconclusive():
    result = evaluate(
        comparisons=[invalid_trial() for _ in range(3)]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_connection_failure_is_inconclusive():
    result = evaluate(
        comparisons=[
            invalid_trial("CONNECTION_FAILURE", None)
            for _ in range(3)
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_a_half_invalid_comparison_is_not_a_valid_trial():
    partial = BooleanComparisonTrial(
        true_response=observation(STABLE_BODY),
        false_response=observation(
            "",
            status=429,
            valid=False,
            failure_reasons=("RATE_LIMITED",),
        ),
    )

    result = evaluate(
        comparisons=[
            body_split_trial(0),
            body_split_trial(1),
            partial,
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS
    )


def test_failure_contract_never_yields_a_false_positive():
    result = evaluate(
        comparisons=[invalid_trial() for _ in range(3)],
        safe_parameter_handling_established=True,
        safe_non_sql_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_invalid_comparisons_do_not_enter_the_decision_window():
    result = evaluate(
        comparisons=[
            invalid_trial(),
            body_split_trial(0),
            body_split_trial(1),
            body_split_trial(2),
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert len(result.evidence.sequence_similarity) == 3


# ---------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------


def test_evidence_records_request_references():
    result = evaluate()

    assert result.evidence.true_request == (
        "req-true-0",
        "req-true-1",
        "req-true-2",
    )
    assert result.evidence.false_request == (
        "req-false-0",
        "req-false-1",
        "req-false-2",
    )


def test_evidence_records_raw_and_normalized_bodies():
    result = evaluate()

    assert result.evidence.true_response[0] == STABLE_BODY
    assert result.evidence.false_response[0] == EMPTY_RESULT_BODY
    assert (
        result.evidence.normalized_true_body[0]
        == normalize_response_body(STABLE_BODY)
    )
    assert (
        result.evidence.normalized_false_body[0]
        == normalize_response_body(EMPTY_RESULT_BODY)
    )


def test_evidence_records_status_difference_per_trial():
    result = evaluate(
        comparisons=[
            status_split_trial(index)
            for index in range(3)
        ]
    )

    assert result.evidence.status_difference == (
        True,
        True,
        True,
    )


def test_evidence_records_no_status_difference_for_body_splits():
    result = evaluate()

    assert result.evidence.status_difference == (
        False,
        False,
        False,
    )


def test_evidence_records_the_response_class_repetition_matrix():
    result = evaluate()

    assert result.evidence.repetition_matrix == (
        ("BODY_SIMILARITY_SPLIT", 3),
    )


def test_evidence_repetition_matrix_is_empty_without_differences():
    result = evaluate(
        comparisons=[
            identical_trial(index)
            for index in range(3)
        ]
    )

    assert result.evidence.repetition_matrix == ()
    assert result.evidence.response_class == (
        None,
        None,
        None,
    )
