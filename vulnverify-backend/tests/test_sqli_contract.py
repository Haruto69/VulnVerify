import pytest

from backend.models.verified_finding import (
    VerificationStatus,
    VerifiedFinding,
)
from backend.verification.sqli_contract import (
    SqliDecision,
    SqliEvidenceStrength,
    SqliReasonCode,
    SqliVerificationStatus,
    build_verified_finding,
    controlled_false_positive_confidence,
    inconclusive_confidence,
    inconclusive_decision,
    repeated_absence_false_positive_confidence,
    safe_handling_false_positive_confidence,
    true_positive_confidence,
)
from tests.sqli_helpers import make_sqli_finding


# ---------------------------------------------------------------------
# Status / strength enums
# ---------------------------------------------------------------------


def test_sqli_status_values_match_frozen_verified_finding_statuses():
    assert {
        status.value
        for status in SqliVerificationStatus
    } == {
        status.value
        for status in VerificationStatus
    }


def test_only_three_sqli_statuses_exist():
    assert [
        status.value
        for status in SqliVerificationStatus
    ] == [
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "INCONCLUSIVE",
    ]


def test_evidence_strength_values():
    assert [
        strength.value
        for strength in SqliEvidenceStrength
    ] == [
        "STRONG",
        "SUPPORTING",
        "NONE",
    ]


def test_reason_code_prefixes_match_their_status_family():
    for reason_code in SqliReasonCode:
        assert reason_code.value.startswith(
            ("TP_", "FP_", "INC_")
        )


# ---------------------------------------------------------------------
# Deterministic confidence policy
# ---------------------------------------------------------------------


def test_true_positive_confidence_defaults_to_0_98():
    assert true_positive_confidence() == 0.98


def test_true_positive_confidence_rises_when_scanner_agrees():
    assert (
        true_positive_confidence(
            scanner_evidence_agrees=True
        )
        == 0.99
    )


def test_weakened_supporting_signal_lowers_true_positive_confidence():
    assert (
        true_positive_confidence(
            scanner_evidence_agrees=True,
            supporting_signal_weakened=True,
        )
        == 0.95
    )


def test_controlled_false_positive_confidence_is_0_97():
    assert controlled_false_positive_confidence() == 0.97


def test_safe_handling_false_positive_confidence_is_0_96():
    assert safe_handling_false_positive_confidence() == 0.96


def test_repeated_absence_false_positive_confidence_is_0_93():
    assert repeated_absence_false_positive_confidence() == 0.93


@pytest.mark.parametrize(
    "reason_code,expected",
    [
        (SqliReasonCode.INC_AUTHENTICATION_FAILED, 0.25),
        (SqliReasonCode.INC_SESSION_EXPIRED, 0.25),
        (SqliReasonCode.INC_WAF_BLOCKED, 0.20),
        (SqliReasonCode.INC_RATE_LIMITED, 0.20),
        (SqliReasonCode.INC_UNSTABLE_BASELINE, 0.20),
        (SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS, 0.20),
        (SqliReasonCode.INC_ENDPOINT_UNAVAILABLE, 0.15),
        (SqliReasonCode.INC_UNSTABLE_TIMING, 0.15),
        (SqliReasonCode.INC_AMBIGUOUS_DATABASE_ERROR, 0.15),
        (SqliReasonCode.INC_AMBIGUOUS_BOOLEAN_RESPONSE, 0.15),
        (SqliReasonCode.INC_AMBIGUOUS_UNION_OUTPUT, 0.15),
        (SqliReasonCode.INC_EXTERNAL_TIMING_EXPLANATION, 0.15),
        (SqliReasonCode.INC_NETWORK_FAILURE, 0.15),
        (SqliReasonCode.INC_TIMEOUT, 0.15),
        (SqliReasonCode.INC_INSUFFICIENT_SCANNER_EVIDENCE, 0.15),
        (SqliReasonCode.INC_PARAMETER_UNKNOWN, 0.10),
        (SqliReasonCode.INC_UNSUPPORTED_CONFIRMATION_PATH, 0.10),
    ],
)
def test_inconclusive_confidence_tiers(reason_code, expected):
    assert inconclusive_confidence(reason_code) == expected


def test_inconclusive_confidence_is_deterministic():
    for reason_code in SqliReasonCode:
        assert (
            inconclusive_confidence(reason_code)
            == inconclusive_confidence(reason_code)
        )


def test_no_confidence_value_exceeds_one():
    values = [
        true_positive_confidence(),
        true_positive_confidence(
            scanner_evidence_agrees=True
        ),
        true_positive_confidence(
            supporting_signal_weakened=True
        ),
        controlled_false_positive_confidence(),
        safe_handling_false_positive_confidence(),
        repeated_absence_false_positive_confidence(),
        *[
            inconclusive_confidence(reason_code)
            for reason_code in SqliReasonCode
        ],
    ]

    for value in values:
        assert 0.0 <= value <= 1.0


def test_no_confidence_value_is_negative():
    for reason_code in SqliReasonCode:
        assert inconclusive_confidence(reason_code) >= 0.0


def test_inconclusive_confidence_never_reaches_positive_band():
    for reason_code in SqliReasonCode:
        assert inconclusive_confidence(reason_code) < 0.5


# ---------------------------------------------------------------------
# inconclusive_decision()
# ---------------------------------------------------------------------


def test_inconclusive_decision_uses_policy_confidence():
    decision = inconclusive_decision(
        SqliReasonCode.INC_WAF_BLOCKED,
        "WAF interference.",
    )

    assert decision.status == SqliVerificationStatus.INCONCLUSIVE
    assert decision.confidence == 0.20
    assert decision.reason_code == SqliReasonCode.INC_WAF_BLOCKED
    assert decision.reason == "WAF interference."
    assert decision.indicators == ()


def test_inconclusive_decision_preserves_indicators():
    decision = inconclusive_decision(
        SqliReasonCode.INC_AMBIGUOUS_UNION_OUTPUT,
        "Ambiguous.",
        indicators=("MYSQL_COLUMN_COUNT_ERROR",),
    )

    assert decision.indicators == ("MYSQL_COLUMN_COUNT_ERROR",)


def test_sqli_decision_is_immutable():
    decision = inconclusive_decision(
        SqliReasonCode.INC_TIMEOUT,
        "Timed out.",
    )

    with pytest.raises(Exception):
        decision.confidence = 0.99


# ---------------------------------------------------------------------
# build_verified_finding()
# ---------------------------------------------------------------------


def true_positive_decision() -> SqliDecision:
    return SqliDecision(
        status=SqliVerificationStatus.TRUE_POSITIVE,
        confidence=true_positive_confidence(),
        reason_code=SqliReasonCode.TP_DATABASE_ERROR,
        reason="Reproduced database error.",
        indicators=("database_error_absent_from_baseline",),
    )


def test_build_verified_finding_returns_frozen_model():
    verified = build_verified_finding(
        finding=make_sqli_finding(),
        decision=true_positive_decision(),
        verification_method="sqli_error_based_rule_v1",
    )

    assert isinstance(verified, VerifiedFinding)
    assert verified.schema_version == "1.0"


def test_build_verified_finding_propagates_finding_id():
    verified = build_verified_finding(
        finding=make_sqli_finding(
            finding_id="F-PROPAGATED"
        ),
        decision=true_positive_decision(),
        verification_method="sqli_error_based_rule_v1",
    )

    assert verified.finding_id == "F-PROPAGATED"


def test_build_verified_finding_propagates_verification_method():
    verified = build_verified_finding(
        finding=make_sqli_finding(),
        decision=true_positive_decision(),
        verification_method="sqli_union_based_rule_v1",
    )

    assert (
        verified.verification_method
        == "sqli_union_based_rule_v1"
    )


def test_build_verified_finding_maps_classification():
    decision = true_positive_decision()

    verified = build_verified_finding(
        finding=make_sqli_finding(),
        decision=decision,
        verification_method="sqli_error_based_rule_v1",
    )

    assert (
        verified.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )
    assert verified.classification.confidence == 0.98
    assert (
        verified.classification.reason
        == "Reproduced database error."
    )


def test_build_verified_finding_puts_reason_code_first_in_indicators():
    verified = build_verified_finding(
        finding=make_sqli_finding(),
        decision=true_positive_decision(),
        verification_method="sqli_error_based_rule_v1",
    )

    assert verified.evidence.indicators == [
        "TP_DATABASE_ERROR",
        "database_error_absent_from_baseline",
    ]


def test_build_verified_finding_builds_evidence_references():
    verified = build_verified_finding(
        finding=make_sqli_finding(
            finding_id="F-REF"
        ),
        decision=true_positive_decision(),
        verification_method="sqli_error_based_rule_v1",
    )

    assert (
        verified.evidence.request_reference
        == "F-REF:sqli_error_based_rule_v1:request"
    )
    assert (
        verified.evidence.response_reference
        == "F-REF:sqli_error_based_rule_v1:response"
    )


def test_build_verified_finding_omits_response_reference_when_absent():
    verified = build_verified_finding(
        finding=make_sqli_finding(),
        decision=true_positive_decision(),
        verification_method="sqli_error_based_rule_v1",
        response_available=False,
    )

    assert verified.evidence.response_reference is None
    assert verified.evidence.request_reference is not None


def test_build_verified_finding_supports_false_positive_status():
    decision = SqliDecision(
        status=SqliVerificationStatus.FALSE_POSITIVE,
        confidence=controlled_false_positive_confidence(),
        reason_code=SqliReasonCode.FP_BASELINE_DB_ERROR,
        reason="Baseline already errors.",
    )

    verified = build_verified_finding(
        finding=make_sqli_finding(),
        decision=decision,
        verification_method="sqli_error_based_rule_v1",
    )

    assert (
        verified.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )
    assert verified.classification.confidence == 0.97
    assert verified.evidence.indicators == [
        "FP_BASELINE_DB_ERROR"
    ]


def test_build_verified_finding_supports_inconclusive_status():
    verified = build_verified_finding(
        finding=make_sqli_finding(),
        decision=inconclusive_decision(
            SqliReasonCode.INC_RATE_LIMITED,
            "Rate limited.",
        ),
        verification_method="sqli_boolean_based_rule_v1",
    )

    assert (
        verified.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert verified.classification.confidence == 0.20


def test_build_verified_finding_confidence_stays_within_bounds():
    for reason_code in SqliReasonCode:
        verified = build_verified_finding(
            finding=make_sqli_finding(),
            decision=inconclusive_decision(
                reason_code,
                "reason",
            ),
            verification_method="sqli_error_based_rule_v1",
        )

        assert 0.0 <= verified.classification.confidence <= 1.0
