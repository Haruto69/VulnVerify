from datetime import datetime, timezone

from backend.verification.sqli_time_based_context import (
    build_sqli_time_based_context,
)
from backend.verification.sqli_timing import TimingSample


def sample(
    number: int,
    response_time_ms: float,
    status: int | None = 200,
) -> TimingSample:
    return TimingSample(
        request_number=number,
        timestamp=datetime.now(timezone.utc),
        status=status,
        response_time_ms=response_time_ms,
        response_length=2,
        body_fingerprint="test",
        headers={},
        errors=(),
    )


def stable_baseline():
    return [
        sample(1, 100.0),
        sample(2, 105.0),
        sample(3, 95.0),
        sample(4, 100.0),
        sample(5, 100.0),
    ]


def unstable_baseline():
    return [
        sample(1, 60.0),
        sample(2, 100.0),
        sample(3, 140.0),
        sample(4, 100.0),
        sample(5, 160.0),
    ]


def test_context_detects_reproducible_delay():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 150.0),
        ],
        verification_confidence=0.95,
    )

    assert context.baseline_stability.stable is True
    assert context.valid_verification_trial_count == 3
    assert context.decision_trial_count == 3
    assert context.delayed_trial_count == 2
    assert context.aggregate_delay_passed is True
    assert context.aggregate_ratio_passed is True


def test_invalid_trial_does_not_enter_decision_window():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 50.0, status=401),
            sample(2, 2500.0),
            sample(3, 2600.0),
            sample(4, 2700.0),
        ],
        verification_confidence=0.95,
    )

    assert context.valid_verification_trial_count == 3
    assert context.decision_trial_count == 3
    assert context.delayed_trial_count == 3

    assert any(
        "AUTHENTICATION_REQUIRED" in reason
        for reason in context.failure_reasons
    )


def test_fewer_than_three_valid_trials_is_preserved():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 50.0, status=429),
        ],
        verification_confidence=0.40,
    )

    assert context.valid_verification_trial_count == 2
    assert context.decision_trial_count == 2


def test_unstable_baseline_is_detected():
    context = build_sqli_time_based_context(
        baseline_samples=unstable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        verification_confidence=0.40,
    )

    assert context.baseline_statistics is not None
    assert context.baseline_statistics.median_ms == 100.0
    assert context.baseline_statistics.mad_ms == 40.0
    assert context.baseline_statistics.variation_ratio == 0.40

    assert context.baseline_stability.stable is False


def test_network_explanation_is_preserved():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        credible_network_or_server_explanation=True,
        verification_confidence=0.40,
    )

    assert (
        context.credible_network_or_server_explanation
        is True
    )