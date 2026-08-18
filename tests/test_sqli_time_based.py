"""
Decision-level tests for the TIME_BASED SQLi verifier.

Timing statistics themselves (median, MAD, per-trial delay, validity)
are covered by tests/test_sqli_timing.py and
tests/test_sqli_time_based_context.py. This module covers the
classification contract in backend/verification/sqli_time_based.py and
uses injected TimingSample values only, never real elapsed time.
"""

import pytest

from backend.models.verified_finding import VerificationStatus
from backend.models.normalized_finding import VulnerabilityCategory
from backend.verification.sqli_contract import SqliReasonCode
from backend.verification.sqli_failure import SqliFailureReason
from backend.verification.sqli_time_based import (
    verify_sqli_time_based,
)
from backend.verification.sqli_time_based_context import (
    build_sqli_time_based_context,
)
from tests.sqli_helpers import (
    delayed_verification_trials,
    make_replay_result,
    make_sqli_finding,
    stable_timing_baseline,
    timing_sample,
    undelayed_verification_trials,
    unstable_timing_baseline,
)


def build_context(
    baseline_samples=None,
    verification_samples=None,
    *,
    credible_network_or_server_explanation: bool = False,
):
    return build_sqli_time_based_context(
        baseline_samples=(
            stable_timing_baseline()
            if baseline_samples is None
            else baseline_samples
        ),
        verification_samples=(
            delayed_verification_trials()
            if verification_samples is None
            else verification_samples
        ),
        credible_network_or_server_explanation=(
            credible_network_or_server_explanation
        ),
        verification_confidence=0.0,
    )


def verify(context, **overrides):
    return verify_sqli_time_based(
        finding=overrides.pop(
            "finding",
            make_sqli_finding(subtype="TIME_BASED"),
        ),
        replay_result=overrides.pop(
            "replay_result",
            make_replay_result(),
        ),
        context=context,
        **overrides,
    )


def reason_code(result) -> str:
    return result.evidence.indicators[0]


# ---------------------------------------------------------------------
# Baseline requirements
# ---------------------------------------------------------------------


def test_five_valid_baseline_samples_are_required():
    context = build_context(
        baseline_samples=stable_timing_baseline()[:4]
    )

    assert context.valid_baseline_sample_count == 4
    assert context.baseline_stability.stable is False

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.INC_UNSTABLE_BASELINE.value
    )


def test_exactly_five_valid_baseline_samples_are_enough():
    context = build_context()

    assert context.valid_baseline_sample_count == 5
    assert context.baseline_stability.stable is True


def test_baseline_mad_ratio_at_or_below_0_20_is_stable():
    context = build_context(
        baseline_samples=[
            timing_sample(1, 100.0),
            timing_sample(2, 120.0),
            timing_sample(3, 80.0),
            timing_sample(4, 100.0),
            timing_sample(5, 100.0),
        ]
    )

    assert context.baseline_statistics.mad_ms == 0.0
    assert context.baseline_stability.stable is True


def test_baseline_mad_ratio_above_0_20_is_unstable():
    context = build_context(
        baseline_samples=unstable_timing_baseline()
    )

    assert context.baseline_statistics.variation_ratio > 0.20
    assert context.baseline_stability.stable is False

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        "unstable_time_based_baseline"
        in result.evidence.indicators
    )


def test_unstable_baseline_confidence_is_0_20():
    result = verify(
        build_context(
            baseline_samples=unstable_timing_baseline()
        )
    )

    assert result.classification.confidence == 0.20


# ---------------------------------------------------------------------
# Verification trial requirements
# ---------------------------------------------------------------------


def test_three_valid_verification_trials_are_required():
    context = build_context(
        verification_samples=delayed_verification_trials()[:2]
    )

    assert context.valid_verification_trial_count == 2

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS.value
    )


def test_two_of_the_first_three_trials_passing_is_enough():
    context = build_context(
        verification_samples=[
            timing_sample(1, 2500.0),
            timing_sample(2, 110.0),
            timing_sample(3, 2600.0),
        ]
    )

    assert context.delayed_trial_count == 2

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )
    assert (
        "timing_delay_reproduced_2_of_3"
        in result.evidence.indicators
    )


def test_one_of_three_trials_passing_is_not_enough():
    context = build_context(
        verification_samples=[
            timing_sample(1, 2500.0),
            timing_sample(2, 110.0),
            timing_sample(3, 120.0),
        ]
    )

    assert context.delayed_trial_count == 1

    result = verify(context)

    assert (
        result.classification.status
        != VerificationStatus.TRUE_POSITIVE
    )


def test_only_the_first_three_valid_trials_form_the_decision_window():
    context = build_context(
        verification_samples=[
            timing_sample(1, 110.0),
            timing_sample(2, 105.0),
            timing_sample(3, 115.0),
            timing_sample(4, 2500.0),
            timing_sample(5, 2600.0),
        ]
    )

    assert context.decision_trial_count == 3
    assert context.delayed_trial_count == 0

    result = verify(context)

    assert (
        result.classification.status
        != VerificationStatus.TRUE_POSITIVE
    )


# ---------------------------------------------------------------------
# Per-trial and aggregate thresholds
# ---------------------------------------------------------------------


def test_trial_delay_threshold_is_max_of_2000ms_and_five_mad():
    """
    baseline median 100 ms, MAD 0 ms -> threshold is the 2000 ms floor.
    A 1900 ms trial is below the floor even though its ratio is huge.
    """

    context = build_context(
        verification_samples=[
            timing_sample(1, 1900.0),
            timing_sample(2, 1900.0),
            timing_sample(3, 1900.0),
        ]
    )

    assert context.aggregate_delay_threshold_ms == 2000.0
    assert context.delayed_trial_count == 0

    result = verify(context)

    assert (
        result.classification.status
        != VerificationStatus.TRUE_POSITIVE
    )


def test_five_mad_replaces_the_floor_when_the_baseline_is_noisier():
    """
    baseline median 3000 ms, MAD 600 ms (ratio 0.20, still stable) ->
    threshold is 5 x MAD = 3000 ms, not the 2000 ms floor. A trial
    2500 ms above the median would have cleared the floor but does not
    clear 5 x MAD.
    """

    baseline = [
        timing_sample(1, 2400.0),
        timing_sample(2, 2400.0),
        timing_sample(3, 3000.0),
        timing_sample(4, 3600.0),
        timing_sample(5, 3600.0),
    ]

    context = build_context(
        baseline_samples=baseline,
        verification_samples=[
            timing_sample(1, 5500.0),
            timing_sample(2, 5500.0),
            timing_sample(3, 5500.0),
        ],
    )

    assert context.baseline_statistics.median_ms == 3000.0
    assert context.baseline_statistics.mad_ms == 600.0
    assert context.baseline_stability.stable is True
    assert context.aggregate_delay_threshold_ms == 3000.0
    assert context.delayed_trial_count == 0

    result = verify(context)

    assert (
        result.classification.status
        != VerificationStatus.TRUE_POSITIVE
    )


def test_trial_ratio_below_two_is_not_a_delay():
    """
    baseline median 3000 ms; a 5500 ms trial clears the 2000 ms delta
    floor but its ratio (1.83) is below the required 2.0.
    """

    baseline = [
        timing_sample(number, 3000.0)
        for number in range(1, 6)
    ]

    context = build_context(
        baseline_samples=baseline,
        verification_samples=[
            timing_sample(1, 5500.0),
            timing_sample(2, 5500.0),
            timing_sample(3, 5500.0),
        ],
    )

    assert context.delayed_trial_count == 0
    assert context.aggregate_delay_passed is True
    assert context.aggregate_ratio_passed is False

    result = verify(context)

    assert (
        result.classification.status
        != VerificationStatus.TRUE_POSITIVE
    )


def test_aggregate_delay_and_ratio_must_both_pass():
    context = build_context()

    assert context.aggregate_delay_passed is True
    assert context.aggregate_ratio_passed is True

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )
    assert (
        "aggregate_delay_passed"
        in result.evidence.indicators
    )
    assert (
        "aggregate_ratio_passed"
        in result.evidence.indicators
    )


def test_aggregate_ratio_failure_blocks_a_true_positive():
    baseline = [
        timing_sample(number, 3000.0)
        for number in range(1, 6)
    ]

    context = build_context(
        baseline_samples=baseline,
        verification_samples=[
            timing_sample(1, 5900.0),
            timing_sample(2, 5900.0),
            timing_sample(3, 5900.0),
        ],
    )

    assert context.aggregate_ratio_passed is False

    result = verify(context)

    assert (
        result.classification.status
        != VerificationStatus.TRUE_POSITIVE
    )


# ---------------------------------------------------------------------
# TRUE_POSITIVE and confidence
# ---------------------------------------------------------------------


def test_reproducible_delay_is_a_true_positive():
    result = verify(build_context())

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.TP_REPRODUCIBLE_TIMING_DIFFERENCE.value
    )


def test_true_positive_confidence_is_0_98_by_default():
    assert (
        verify(build_context()).classification.confidence
        == 0.98
    )


def test_true_positive_confidence_is_0_99_when_scanner_agrees():
    result = verify(
        build_context(),
        scanner_evidence_agrees=True,
    )

    assert result.classification.confidence == 0.99


def test_true_positive_confidence_ignores_the_context_field():
    """
    context.verification_confidence is legacy and must not influence
    the classification confidence.
    """

    context = build_sqli_time_based_context(
        baseline_samples=stable_timing_baseline(),
        verification_samples=delayed_verification_trials(),
        verification_confidence=0.10,
    )

    assert context.verification_confidence == 0.10
    assert verify(context).classification.confidence == 0.98


def test_missing_telemetry_alone_does_not_block_a_true_positive():
    """
    Nothing about infrastructure telemetry is supplied here. The only
    inputs are timing samples, and the result is still TRUE_POSITIVE.
    """

    context = build_context(
        credible_network_or_server_explanation=False
    )

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )
    assert (
        "no_observed_external_interference"
        in result.evidence.indicators
    )


def test_true_positive_evidence_references_are_populated():
    result = verify(build_context())

    assert (
        result.evidence.request_reference
        == "F-SQLI-TEST:sqli_time_based_rule_v1:request"
    )
    assert (
        result.evidence.response_reference
        == "F-SQLI-TEST:sqli_time_based_rule_v1:response"
    )


def test_verification_method_is_propagated():
    result = verify(build_context())

    assert (
        result.verification_method
        == "sqli_time_based_rule_v1"
    )


def test_finding_id_is_propagated():
    result = verify(
        build_context(),
        finding=make_sqli_finding(
            finding_id="F-TIME-42",
            subtype="TIME_BASED",
        ),
    )

    assert result.finding_id == "F-TIME-42"


# ---------------------------------------------------------------------
# FALSE_POSITIVE
# ---------------------------------------------------------------------


def test_absent_delay_with_a_completed_run_is_a_false_positive():
    result = verify(
        build_context(
            verification_samples=undelayed_verification_trials()
        )
    )

    assert (
        result.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.FP_NO_TIMING_DIFFERENCE.value
    )
    assert result.classification.confidence == 0.93


def test_false_positive_indicators_state_the_controlled_conditions():
    result = verify(
        build_context(
            verification_samples=undelayed_verification_trials()
        )
    )

    assert (
        "stable_timing_baseline"
        in result.evidence.indicators
    )
    assert (
        "required_timing_trials_completed"
        in result.evidence.indicators
    )
    assert (
        "reproducible_delay_pattern_absent"
        in result.evidence.indicators
    )


# ---------------------------------------------------------------------
# External interference and failure contract
# ---------------------------------------------------------------------


def test_observed_external_interference_is_inconclusive():
    context = build_context(
        credible_network_or_server_explanation=True
    )

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.INC_EXTERNAL_TIMING_EXPLANATION.value
    )
    assert result.classification.confidence == 0.15


def test_external_interference_outranks_a_reproducible_delay():
    result = verify(
        build_context(
            verification_samples=delayed_verification_trials(),
            credible_network_or_server_explanation=True,
        )
    )

    assert (
        result.classification.status
        != VerificationStatus.TRUE_POSITIVE
    )


def test_timeout_makes_trials_invalid_and_yields_inconclusive():
    """
    A timed-out replay carries status=None, which the failure contract
    treats as a connection failure, so the trial never becomes valid.
    """

    context = build_context(
        verification_samples=[
            timing_sample(1, 10000.0, status=None),
            timing_sample(2, 10000.0, status=None),
            timing_sample(3, 10000.0, status=None),
        ]
    )

    assert context.valid_verification_trial_count == 0

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_connection_failure_in_the_baseline_is_inconclusive():
    context = build_context(
        baseline_samples=[
            timing_sample(number, 100.0, status=None)
            for number in range(1, 6)
        ]
    )

    assert context.baseline_statistics is None

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_authentication_failure_is_inconclusive():
    context = build_context(
        baseline_samples=[
            timing_sample(number, 100.0, status=401)
            for number in range(1, 6)
        ]
    )

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_rate_limited_trials_do_not_count_toward_the_required_three():
    context = build_context(
        verification_samples=[
            timing_sample(1, 2500.0),
            timing_sample(2, 2600.0),
            timing_sample(3, 50.0, status=429),
        ]
    )

    assert context.valid_verification_trial_count == 2

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_rate_limiting_must_never_produce_a_false_positive():
    """
    Regression test for a fixed defect: _failure_decision() used to
    compare SqliFailureReason members against context.failure_reasons,
    which holds strings pre-formatted as
    '<phase> request <n>: <REASON>'. That comparison never matched, so
    the whole failure-contract branch was dead and a run with an
    observed 429 could still be classified FALSE_POSITIVE. The fix
    adds context.failure_reason_codes, a structured
    tuple[SqliFailureReason, ...], which _failure_decision() now
    checks directly instead of string-parsing.
    """

    context = build_context(
        verification_samples=[
            timing_sample(1, 110.0),
            timing_sample(2, 105.0),
            timing_sample(3, 115.0),
            timing_sample(4, 50.0, status=429),
            timing_sample(5, 50.0, status=429),
        ]
    )

    assert context.failure_reasons
    assert (
        SqliFailureReason.RATE_LIMITED
        in context.failure_reason_codes
    )

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.INC_RATE_LIMITED.value
    )


def test_waf_block_must_never_produce_a_false_positive():
    """
    Regression test for the same fixed defect: a WAF/403 block
    observed anywhere in the verification run must force INCONCLUSIVE
    rather than allowing a definitive FALSE_POSITIVE.
    """

    context = build_context(
        verification_samples=[
            timing_sample(1, 110.0),
            timing_sample(2, 105.0),
            timing_sample(3, 115.0),
            timing_sample(4, 50.0, status=403),
        ]
    )

    assert (
        SqliFailureReason.FORBIDDEN
        in context.failure_reason_codes
    )

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_authentication_failure_must_never_produce_a_false_positive():
    context = build_context(
        verification_samples=[
            timing_sample(1, 110.0),
            timing_sample(2, 105.0),
            timing_sample(3, 115.0),
            timing_sample(4, 50.0, status=401),
        ]
    )

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.INC_AUTHENTICATION_FAILED.value
    )


def test_session_expiry_must_never_produce_a_false_positive():
    """
    Session expiry is reported via SqliFailureContext.session_expired,
    which timing samples cannot express (only an HTTP status code is
    mechanically knowable from a TimingSample). This is exercised at
    the failure-contract level instead, via SqliFailureContext
    directly, to prove the structured-reason plumbing that
    _failure_decision() relies on covers SESSION_EXPIRED too.
    """

    from backend.verification.sqli_failure import (
        SqliFailureContext,
        evaluate_sqli_failure,
    )

    evaluation = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=200,
            session_expired=True,
        )
    )

    assert (
        SqliFailureReason.SESSION_EXPIRED
        in evaluation.reasons
    )


def test_timeout_or_connection_failure_must_never_produce_a_false_positive():
    """
    A timed-out/unreachable trial surfaces as status=None, which the
    failure contract maps to CONNECTION_FAILURE. That must force
    INCONCLUSIVE, never a definitive FALSE_POSITIVE.
    """

    context = build_context(
        verification_samples=[
            timing_sample(1, 110.0),
            timing_sample(2, 105.0),
            timing_sample(3, 115.0),
            timing_sample(4, 10000.0, status=None),
        ]
    )

    assert (
        SqliFailureReason.CONNECTION_FAILURE
        in context.failure_reason_codes
    )

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        reason_code(result)
        == SqliReasonCode.INC_NETWORK_FAILURE.value
    )


def test_missing_telemetry_does_not_force_inconclusive_on_a_false_positive_run():
    """
    Companion to test_missing_telemetry_alone_does_not_block_a_true_positive:
    the absence of any external-interference signal must not force
    INCONCLUSIVE on a clean, non-delayed run either. No failure-contract
    condition and no interference flag means the normal FALSE_POSITIVE
    rule applies.
    """

    context = build_context(
        verification_samples=undelayed_verification_trials(),
        credible_network_or_server_explanation=False,
    )

    assert context.failure_reason_codes == ()

    result = verify(context)

    assert (
        result.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )


def test_invalid_attempts_are_excluded_from_the_valid_trial_count():
    context = build_context(
        verification_samples=[
            timing_sample(1, 50.0, status=429),
            timing_sample(2, 2500.0),
            timing_sample(3, 2600.0),
            timing_sample(4, 2700.0),
        ]
    )

    assert context.valid_verification_trial_count == 3
    assert context.decision_trial_count == 3


def test_valid_replacement_trials_still_satisfy_the_three_trial_requirement():
    """
    backend.verification.sqli_timing.collect_verification_trials
    intentionally retries past an invalid attempt until it has
    verification_attempts_min (3) valid trials, up to
    max_attempts_per_condition (5) total attempts. A single invalid
    attempt followed by three valid, delayed replacement trials must
    still satisfy the >=3 valid-trial requirement: it must not be
    downgraded to INC_INSUFFICIENT_VALID_TRIALS.
    """

    context = build_context(
        verification_samples=[
            timing_sample(1, 50.0, status=429),
            timing_sample(2, 2500.0),
            timing_sample(3, 2600.0),
            timing_sample(4, 2700.0),
        ]
    )

    assert context.valid_verification_trial_count == 3
    assert context.decision_trial_count == 3
    assert context.delayed_trial_count == 3

    result = verify(context)

    assert (
        result.classification.status
        != VerificationStatus.INCONCLUSIVE
        or reason_code(result)
        != SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS.value
    )


# ---------------------------------------------------------------------
# Guard rails
# ---------------------------------------------------------------------


def test_non_sqli_finding_is_rejected():
    with pytest.raises(ValueError, match="non-SQLI"):
        verify(
            build_context(),
            finding=make_sqli_finding(
                category=VulnerabilityCategory.XSS,
                subtype="TIME_BASED",
            ),
        )


def test_a_transport_failed_replay_still_produces_a_verified_finding():
    context = build_context(
        baseline_samples=[
            timing_sample(number, 100.0, status=401)
            for number in range(1, 6)
        ]
    )

    result = verify(
        context,
        replay_result=make_replay_result(
            status=None,
            body=None,
            executed=False,
            errors=["connection failure"],
        ),
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert result.finding_id == "F-SQLI-TEST"
    assert result.evidence.request_reference is not None
    assert 0.0 <= result.classification.confidence <= 1.0
