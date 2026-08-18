from backend.verification.sqli_contract import (
    SqliReasonCode,
    SqliVerificationStatus,
)
from backend.verification.sqli_error_based import (
    evaluate_error_based_sqli,
)
from tests.sqli_helpers import (
    DIFFERENT_BODY,
    GENERIC_APPLICATION_ERROR_BODY,
    MYSQL_ERROR_BODY,
    STABLE_BODY,
    observation,
    stable_baseline,
)


ORACLE_ERROR_BODY = (
    "<html><body>ORA-01756: quoted string not properly terminated"
    "</body></html>"
)


def error_verification(
    count: int = 3,
    body: str = MYSQL_ERROR_BODY,
    *,
    status: int = 500,
) -> list:
    return [
        observation(body, status=status)
        for _ in range(count)
    ]


def evaluate(**overrides):
    kwargs = {
        "baseline_responses": stable_baseline(),
        "verification_responses": error_verification(),
        "parameter_dependency_established": True,
    }
    kwargs.update(overrides)

    return evaluate_error_based_sqli(**kwargs)


# ---------------------------------------------------------------------
# TRUE_POSITIVE
# ---------------------------------------------------------------------


def test_reproduced_database_error_is_a_true_positive():
    result = evaluate()

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.TP_DATABASE_ERROR
    )


def test_true_positive_confidence_is_0_98_by_default():
    assert evaluate().decision.confidence == 0.98


def test_true_positive_confidence_is_0_99_when_scanner_agrees():
    result = evaluate(scanner_evidence_agrees=True)

    assert result.decision.confidence == 0.99


def test_true_positive_indicators_name_the_reproduced_signature():
    result = evaluate()

    assert "MYSQL_SYNTAX_001" in result.decision.indicators
    assert (
        "database_error_absent_from_baseline"
        in result.decision.indicators
    )
    assert (
        "database_error_reproduced_2_of_3"
        in result.decision.indicators
    )
    assert (
        "parameter_dependency_established"
        in result.decision.indicators
    )


def test_two_of_three_trials_are_enough_for_a_true_positive():
    result = evaluate(
        verification_responses=[
            observation(MYSQL_ERROR_BODY, status=500),
            observation(GENERIC_APPLICATION_ERROR_BODY, status=500),
            observation(MYSQL_ERROR_BODY, status=500),
        ]
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )


def test_one_of_three_trials_is_not_enough_for_a_true_positive():
    result = evaluate(
        verification_responses=[
            observation(MYSQL_ERROR_BODY, status=500),
            observation(GENERIC_APPLICATION_ERROR_BODY, status=500),
            observation(GENERIC_APPLICATION_ERROR_BODY, status=500),
        ]
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
    )


def test_two_different_signatures_do_not_reproduce_each_other():
    result = evaluate(
        verification_responses=[
            observation(MYSQL_ERROR_BODY, status=500),
            observation(ORACLE_ERROR_BODY, status=500),
            observation(GENERIC_APPLICATION_ERROR_BODY, status=500),
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
        != SqliVerificationStatus.TRUE_POSITIVE
    )
    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_database_error_inside_a_repeated_5xx_body_is_a_true_positive():
    result = evaluate(
        verification_responses=error_verification(status=500)
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )


# ---------------------------------------------------------------------
# Non-TRUE_POSITIVE outcomes
# ---------------------------------------------------------------------


def test_no_database_error_is_not_a_true_positive():
    result = evaluate(
        verification_responses=error_verification(
            body=STABLE_BODY,
            status=200,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_AMBIGUOUS_DATABASE_ERROR
    )


def test_generic_application_error_is_not_sql_evidence():
    result = evaluate(
        verification_responses=error_verification(
            body=GENERIC_APPLICATION_ERROR_BODY,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert result.evidence.error_signature_id is None
    assert result.evidence.error_match_count == 0


def test_repeated_5xx_without_sql_evidence_is_inconclusive():
    result = evaluate(
        baseline_responses=stable_baseline(
            body=GENERIC_APPLICATION_ERROR_BODY,
            status=500,
        ),
        verification_responses=error_verification(
            body=GENERIC_APPLICATION_ERROR_BODY,
            status=500,
        ),
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_could_not_reproduce_alone_is_not_a_false_positive():
    result = evaluate(
        verification_responses=error_verification(
            body=STABLE_BODY,
            status=200,
        )
    )

    assert (
        result.decision.status
        != SqliVerificationStatus.FALSE_POSITIVE
    )


# ---------------------------------------------------------------------
# Failure contract -> INCONCLUSIVE
# ---------------------------------------------------------------------


def invalid_responses(reason: str, status: int | None = 401) -> list:
    return [
        observation(
            "",
            status=status,
            valid=False,
            failure_reasons=(reason,),
        )
        for _ in range(5)
    ]


def test_authentication_failure_in_baseline_is_inconclusive():
    result = evaluate(
        baseline_responses=invalid_responses(
            "AUTHENTICATION_REQUIRED"
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_UNSTABLE_BASELINE
    )


def test_session_expiry_in_verification_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_responses(
            "SESSION_EXPIRED",
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


def test_waf_block_in_verification_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_responses(
            "WAF_BLOCKED",
            status=403,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_rate_limiting_in_verification_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_responses(
            "RATE_LIMITED",
            status=429,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_connection_failure_is_inconclusive():
    result = evaluate(
        verification_responses=invalid_responses(
            "CONNECTION_FAILURE",
            status=None,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_dns_failure_is_inconclusive():
    result = evaluate(
        baseline_responses=invalid_responses(
            "DNS_FAILURE",
            status=None,
        ),
        verification_responses=invalid_responses(
            "DNS_FAILURE",
            status=None,
        ),
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )


def test_failure_contract_never_yields_a_false_positive():
    for reason, status in [
        ("AUTHENTICATION_REQUIRED", 401),
        ("FORBIDDEN", 403),
        ("CSRF_OR_SESSION_REJECTED", 419),
        ("RATE_LIMITED", 429),
        ("CONNECTION_FAILURE", None),
    ]:
        result = evaluate(
            verification_responses=invalid_responses(
                reason,
                status,
            ),
            safe_parameter_handling_established=True,
            controlled_non_sql_explanation_established=True,
        )

        assert (
            result.decision.status
            == SqliVerificationStatus.INCONCLUSIVE
        )


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
    assert result.decision.confidence == 0.20


def test_fewer_than_three_valid_trials_is_inconclusive():
    result = evaluate(
        verification_responses=error_verification(count=2)
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS
    )


# ---------------------------------------------------------------------
# Baseline already contains the database error
# ---------------------------------------------------------------------


def test_database_error_already_in_baseline_is_ambiguous():
    result = evaluate(
        baseline_responses=stable_baseline(
            body=MYSQL_ERROR_BODY,
            status=500,
        )
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.INCONCLUSIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.INC_AMBIGUOUS_DATABASE_ERROR
    )
    assert (
        "database_error_present_in_baseline"
        in result.decision.indicators
    )


def test_baseline_database_error_that_explains_the_signal_is_a_false_positive():
    result = evaluate(
        baseline_responses=stable_baseline(
            body=MYSQL_ERROR_BODY,
            status=500,
        ),
        baseline_db_error_explains_signal=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.FP_BASELINE_DB_ERROR
    )
    assert result.decision.confidence == 0.97


# ---------------------------------------------------------------------
# Controlled FALSE_POSITIVE paths
# ---------------------------------------------------------------------


def test_safe_parameter_handling_is_a_false_positive():
    result = evaluate(
        verification_responses=error_verification(
            body=STABLE_BODY,
            status=200,
        ),
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


def test_controlled_non_sql_explanation_is_a_false_positive():
    result = evaluate(
        verification_responses=error_verification(
            body=GENERIC_APPLICATION_ERROR_BODY,
            status=500,
        ),
        controlled_non_sql_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.FALSE_POSITIVE
    )
    assert (
        result.decision.reason_code
        == SqliReasonCode.FP_NO_SQL_DATABASE_ERROR
    )
    assert result.decision.confidence == 0.93


def test_true_positive_outranks_a_controlled_false_positive_flag():
    result = evaluate(
        safe_parameter_handling_established=True,
        controlled_non_sql_explanation_established=True,
    )

    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )


# ---------------------------------------------------------------------
# Evidence propagation
# ---------------------------------------------------------------------


def test_evidence_propagates_the_signature_id_and_family():
    result = evaluate()

    assert (
        result.evidence.error_signature_id
        == "MYSQL_SYNTAX_001"
    )
    assert result.evidence.error_db_family == "MYSQL"
    assert (
        result.evidence.error_match_location
        == "response_body"
    )
    assert (
        "You have an error in your SQL syntax"
        in result.evidence.error_match_text
    )


def test_evidence_counts_matches_across_trials():
    result = evaluate()

    assert result.evidence.error_match_count == 3
    assert len(result.evidence.verification_matches) == 3


def test_evidence_counts_baseline_matches():
    result = evaluate(
        baseline_responses=stable_baseline(
            body=MYSQL_ERROR_BODY,
            status=500,
        )
    )

    assert result.evidence.baseline_match_count == 3


def test_evidence_baseline_match_count_is_zero_for_a_clean_baseline():
    assert evaluate().evidence.baseline_match_count == 0


def test_evidence_is_built_even_when_the_baseline_is_unstable():
    result = evaluate(
        baseline_responses=[observation()]
    )

    assert result.evidence is not None
    assert result.evidence.baseline_match_count == 0


def test_only_the_first_three_valid_trials_are_scored():
    result = evaluate(
        verification_responses=[
            observation(GENERIC_APPLICATION_ERROR_BODY, status=500),
            observation(GENERIC_APPLICATION_ERROR_BODY, status=500),
            observation(GENERIC_APPLICATION_ERROR_BODY, status=500),
            observation(MYSQL_ERROR_BODY, status=500),
            observation(MYSQL_ERROR_BODY, status=500),
        ]
    )

    assert len(result.evidence.verification_matches) == 3
    assert (
        result.decision.status
        != SqliVerificationStatus.TRUE_POSITIVE
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
            observation(MYSQL_ERROR_BODY, status=500),
            observation(MYSQL_ERROR_BODY, status=500),
            observation(MYSQL_ERROR_BODY, status=500),
        ]
    )

    assert len(result.evidence.verification_matches) == 3
    assert (
        result.decision.status
        == SqliVerificationStatus.TRUE_POSITIVE
    )
