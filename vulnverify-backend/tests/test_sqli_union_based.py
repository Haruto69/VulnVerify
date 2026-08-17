import hashlib

from backend.verification.sqli_contract import (
    SqliReasonCode,
    SqliVerificationStatus,
)
from backend.verification.sqli_union_based import (
    MYSQL_COLUMN_COUNT_SIGNATURE,
    evaluate_union_based_sqli,
)
from tests.sqli_helpers import (
    DIFFERENT_BODY,
    MYSQL_COLUMN_COUNT_BODY,
    STABLE_BODY,
    observation,
    stable_baseline,
)


SCANNER_MARKER = "vv-union-marker-7f3a"

MARKER_BODY = STABLE_BODY.replace(
    "</body>",
    f"{SCANNER_MARKER}</body>",
)

DB_OUTPUT = "5.7.42-0ubuntu0.18.04.1"

DB_OUTPUT_BODY = STABLE_BODY.replace(
    "</body>",
    f"{DB_OUTPUT}</body>",
)


def marker_verification(count: int = 3) -> list:
    return [observation(MARKER_BODY) for _ in range(count)]


def clean_verification(count: int = 3) -> list:
    return [observation(STABLE_BODY) for _ in range(count)]


def invalid_verification(
    reason: str,
    status: int | None = 401,
    count: int = 3,
) -> list:
    return [
        observation(
            "",
            status=status,
            valid=False,
            failure_reasons=(reason,),
        )
        for _ in range(count)
    ]


def evaluate(**overrides):
    kwargs = {
        "baseline_responses": stable_baseline(),
        "verification_responses": marker_verification(),
        "union_technique_identified": True,
        "parameter_dependency_established": True,
        "scanner_marker": SCANNER_MARKER,
    }
    kwargs.update(overrides)

    return evaluate_union_based_sqli(**kwargs)


# ---------------------------------------------------------------------
# TRUE_POSITIVE via scanner marker
# ---------------------------------------------------------------------


def test_reproduced_scanner_marker_is_a_true_positive():
    result = evaluate()

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.TP_UNION_SCANNER_MARKER
    )
    assert result.decision.confidence == 0.98


def test_marker_true_positive_confidence_rises_when_scanner_agrees():
    result = evaluate(scanner_evidence_agrees=True)

    assert result.decision.confidence == 0.99


def test_marker_true_positive_indicators():
    result = evaluate()

    assert "scanner_union_marker" in result.decision.indicators
    assert (
        "union_marker_reproduced_2_of_3"
        in result.decision.indicators
    )
    assert (
        "parameter_dependency_established"
        in result.decision.indicators
    )


def test_baseline_must_not_contain_the_marker():
    result = evaluate(
        baseline_responses=stable_baseline(body=MARKER_BODY)
    )

    assert result.evidence.marker_present_baseline is True
    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )


def test_two_of_three_trials_are_enough():
    result = evaluate(
        verification_responses=[
            observation(MARKER_BODY),
            observation(STABLE_BODY),
            observation(MARKER_BODY),
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )


def test_one_of_three_trials_is_not_enough():
    result = evaluate(
        verification_responses=[
            observation(MARKER_BODY),
            observation(STABLE_BODY),
            observation(STABLE_BODY),
        ]
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )


def test_absent_marker_is_not_a_true_positive():
    result = evaluate(
        verification_responses=clean_verification()
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_AMBIGUOUS_UNION_OUTPUT
    )


def test_without_parameter_dependency_there_is_no_true_positive():
    result = evaluate(
        parameter_dependency_established=False
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )


# ---------------------------------------------------------------------
# TRUE_POSITIVE via database-derived output
# ---------------------------------------------------------------------


def test_reproduced_database_derived_output_is_a_true_positive():
    result = evaluate(
        verification_responses=[
            observation(DB_OUTPUT_BODY) for _ in range(3)
        ],
        scanner_marker=None,
        scanner_db_derived_output=DB_OUTPUT,
        scanner_establishes_db_origin=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.TP_UNION_DATABASE_DERIVED_OUTPUT
    )
    assert (
        "database_derived_union_output"
        in result.decision.indicators
    )


def test_database_origin_must_be_established_by_the_scanner():
    result = evaluate(
        verification_responses=[
            observation(DB_OUTPUT_BODY) for _ in range(3)
        ],
        scanner_marker=None,
        scanner_db_derived_output=DB_OUTPUT,
        scanner_establishes_db_origin=False,
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )


def test_database_output_already_in_baseline_is_not_a_true_positive():
    result = evaluate(
        baseline_responses=stable_baseline(body=DB_OUTPUT_BODY),
        verification_responses=[
            observation(DB_OUTPUT_BODY) for _ in range(3)
        ],
        scanner_marker=None,
        scanner_db_derived_output=DB_OUTPUT,
        scanner_establishes_db_origin=True,
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )
    assert result.evidence.output_difference is False


# ---------------------------------------------------------------------
# MYSQL_COLUMN_COUNT_ERROR is supporting evidence only
# ---------------------------------------------------------------------


def test_column_count_error_alone_is_not_a_true_positive():
    result = evaluate(
        verification_responses=[
            observation(MYSQL_COLUMN_COUNT_BODY, status=500)
            for _ in range(3)
        ],
        scanner_marker=None,
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_AMBIGUOUS_UNION_OUTPUT
    )


def test_column_count_error_is_recorded_as_supporting_evidence():
    result = evaluate(
        verification_responses=[
            observation(MYSQL_COLUMN_COUNT_BODY, status=500)
            for _ in range(3)
        ],
        scanner_marker=None,
    )

    assert (
        result.evidence.column_count_error_signature
        == MYSQL_COLUMN_COUNT_SIGNATURE
    )
    assert (
        MYSQL_COLUMN_COUNT_SIGNATURE
        in result.decision.indicators
    )


def test_column_count_error_reason_states_it_is_not_union_proof():
    result = evaluate(
        verification_responses=[
            observation(MYSQL_COLUMN_COUNT_BODY, status=500)
            for _ in range(3)
        ],
        scanner_marker=None,
    )

    assert (
        "does not prove successful UNION execution"
        in result.decision.reason
    )


def test_column_count_error_alongside_an_absent_marker_stays_non_tp():
    result = evaluate(
        verification_responses=[
            observation(MYSQL_COLUMN_COUNT_BODY, status=500)
            for _ in range(3)
        ]
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        result.evidence.column_count_error_signature
        == MYSQL_COLUMN_COUNT_SIGNATURE
    )


def test_clean_verification_records_no_column_count_signature():
    result = evaluate()

    assert result.evidence.column_count_error_signature is None


# ---------------------------------------------------------------------
# Scanner evidence requirements
# ---------------------------------------------------------------------


def test_union_technique_must_be_identified_by_the_scanner():
    result = evaluate(union_technique_identified=False)

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_INSUFFICIENT_SCANNER_EVIDENCE
    )


def test_no_marker_and_no_output_is_an_unsupported_confirmation_path():
    result = evaluate(
        verification_responses=clean_verification(),
        scanner_marker=None,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_UNSUPPORTED_CONFIRMATION_PATH
    )
    assert (
        "generated UNION confirmation is disabled"
        in result.decision.reason
    )


def test_no_payload_is_generated_when_scanner_evidence_is_missing():
    result = evaluate(
        verification_responses=clean_verification(),
        scanner_marker=None,
    )

    assert result.evidence.union_marker is None
    assert result.evidence.marker_source is None
    assert result.evidence.db_derived_output is None


def test_marker_source_is_always_the_scanner():
    result = evaluate()

    assert result.evidence.marker_source == "scanner"
    assert result.evidence.union_marker == SCANNER_MARKER


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


def test_authentication_failure_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_verification(
            "AUTHENTICATION_REQUIRED",
            401,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS
    )


def test_session_rejection_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_verification(
            "CSRF_OR_SESSION_REJECTED",
            419,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_waf_block_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_verification(
            "WAF_BLOCKED",
            403,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_rate_limiting_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_verification(
            "RATE_LIMITED",
            429,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_connection_failure_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_verification(
            "CONNECTION_FAILURE",
            None,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_failure_contract_never_yields_a_false_positive():
    result = evaluate(
        verification_responses=invalid_verification(
            "RATE_LIMITED",
            429,
        ),
        safe_parameter_handling_established=True,
        safe_non_union_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_invalid_trials_do_not_enter_the_decision_window():
    result = evaluate(
        verification_responses=[
            observation(
                "",
                status=429,
                valid=False,
                failure_reasons=("RATE_LIMITED",),
            ),
            *marker_verification(),
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert len(result.evidence.marker_present_verification) == 3


# ---------------------------------------------------------------------
# FALSE_POSITIVE
# ---------------------------------------------------------------------


def test_control_equivalence_is_a_controlled_false_positive():
    result = evaluate(control_equivalence_established=True)

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.FP_UNION_CONTROL_EQUIVALENCE
    )
    assert result.decision.confidence == 0.97


def test_safe_parameter_handling_is_a_false_positive():
    result = evaluate(
        verification_responses=clean_verification(),
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


def test_controlled_non_union_explanation_is_a_false_positive():
    result = evaluate(
        verification_responses=clean_verification(),
        safe_non_union_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.FP_NO_UNION_OUTPUT
    )
    assert result.decision.confidence == 0.93


def test_inability_to_reproduce_alone_is_not_a_false_positive():
    result = evaluate(
        verification_responses=clean_verification()
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.FALSE_POSITIVE
    )


def test_reproduced_marker_outranks_a_controlled_explanation_flag():
    result = evaluate(
        safe_parameter_handling_established=True,
        safe_non_union_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )


# ---------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------


def test_evidence_records_marker_presence_per_trial():
    result = evaluate(
        verification_responses=[
            observation(MARKER_BODY),
            observation(STABLE_BODY),
            observation(MARKER_BODY),
        ]
    )

    assert result.evidence.marker_present_baseline is False
    assert result.evidence.marker_present_verification == (
        True,
        False,
        True,
    )


def test_evidence_fingerprints_the_database_derived_output():
    result = evaluate(
        verification_responses=[
            observation(DB_OUTPUT_BODY) for _ in range(3)
        ],
        scanner_marker=None,
        scanner_db_derived_output=DB_OUTPUT,
        scanner_establishes_db_origin=True,
    )

    assert (
        result.evidence.output_fingerprint
        == hashlib.sha256(
            DB_OUTPUT.encode("utf-8")
        ).hexdigest()
    )
    assert (
        result.evidence.db_derived_output_location
        == "response_body"
    )
    assert result.evidence.output_difference is True


def test_evidence_leaves_marker_fields_unset_without_a_marker():
    result = evaluate(
        verification_responses=clean_verification(),
        scanner_marker=None,
    )

    assert result.evidence.marker_present_baseline is None
    assert result.evidence.marker_present_verification == ()
    assert result.evidence.output_fingerprint is None
    assert result.evidence.output_difference is None


def test_evidence_is_built_even_when_the_baseline_is_unstable():
    result = evaluate(
        baseline_responses=[observation()]
    )

    assert result.evidence.union_marker == SCANNER_MARKER
    assert result.evidence.marker_present_baseline is False
