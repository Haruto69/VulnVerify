from dataclasses import dataclass

from backend.verification.sqli_profiles import (
    SqliReplayProfile,
    SqliSubtype,
    get_sqli_replay_profile,
)
from backend.verification.sqli_timing import (
    BaselineStabilityResult,
    BaselineStatistics,
    TimingSample,
    VerificationStatistics,
    compute_baseline_statistics,
    compute_verification_statistics,
    evaluate_baseline_stability,
    evaluate_trial_delay,
    evaluate_trial_validity,
)


@dataclass(frozen=True)
class SqliTimeBasedContext:
    baseline_statistics: BaselineStatistics | None
    baseline_stability: BaselineStabilityResult

    verification_statistics: VerificationStatistics | None

    valid_baseline_sample_count: int
    valid_verification_trial_count: int

    decision_trial_count: int
    delayed_trial_count: int

    required_delayed_trials: int
    required_verification_trials: int

    aggregate_delay_threshold_ms: float | None
    aggregate_delay_passed: bool
    aggregate_ratio_passed: bool

    credible_network_or_server_explanation: bool

    verification_confidence: float

    failure_reasons: tuple[str, ...]


def build_sqli_time_based_context(
    *,
    baseline_samples: list[TimingSample],
    verification_samples: list[TimingSample],
    verification_confidence: float,
    credible_network_or_server_explanation: bool = False,
    profile: SqliReplayProfile | None = None,
) -> SqliTimeBasedContext:
    if not 0.0 <= verification_confidence <= 1.0:
        raise ValueError(
            "verification_confidence must be between 0.0 and 1.0"
        )

    if profile is None:
        profile = get_sqli_replay_profile(
            SqliSubtype.TIME_BASED
        )

    if profile.subtype != SqliSubtype.TIME_BASED:
        raise ValueError(
            "TIME_BASED context requires the TIME_BASED replay profile"
        )

    valid_baseline_samples = [
        sample
        for sample in baseline_samples
        if evaluate_trial_validity(sample).valid
    ]

    valid_verification_samples = [
        sample
        for sample in verification_samples
        if evaluate_trial_validity(sample).valid
    ]

    failure_reasons = _collect_failure_reasons(
        baseline_samples=baseline_samples,
        verification_samples=verification_samples,
    )

    if valid_baseline_samples:
        baseline_statistics = compute_baseline_statistics(
            [
                sample.response_time_ms
                for sample in valid_baseline_samples
            ]
        )

        baseline_stability = evaluate_baseline_stability(
            baseline_statistics,
            profile,
        )
    else:
        baseline_statistics = None
        baseline_stability = BaselineStabilityResult(
            stable=False,
            reasons=(
                "No valid baseline timing samples were available.",
            ),
        )

    decision_samples = valid_verification_samples[
        : profile.reproduction_trial_count
    ]

    verification_statistics = None
    delayed_trial_count = 0
    aggregate_delay_threshold_ms = None
    aggregate_delay_passed = False
    aggregate_ratio_passed = False

    if baseline_statistics is not None:
        for sample in decision_samples:
            trial_result = evaluate_trial_delay(
                sample=sample,
                baseline_median_ms=baseline_statistics.median_ms,
                baseline_mad_ms=baseline_statistics.mad_ms,
                profile=profile,
            )

            if trial_result.delayed:
                delayed_trial_count += 1

        if decision_samples:
            verification_statistics = (
                compute_verification_statistics(
                    [
                        sample.response_time_ms
                        for sample in decision_samples
                    ],
                    baseline_median_ms=(
                        baseline_statistics.median_ms
                    ),
                )
            )

        if (
            profile.timing_delta_floor_ms is not None
            and profile.timing_mad_multiplier is not None
        ):
            aggregate_delay_threshold_ms = max(
                profile.timing_delta_floor_ms,
                (
                    profile.timing_mad_multiplier
                    * baseline_statistics.mad_ms
                ),
            )

        if (
            verification_statistics is not None
            and aggregate_delay_threshold_ms is not None
        ):
            aggregate_delay_passed = (
                verification_statistics.timing_delta_ms
                >= aggregate_delay_threshold_ms
            )

        if (
            verification_statistics is not None
            and profile.verification_median_ratio is not None
        ):
            aggregate_ratio_passed = (
                verification_statistics.timing_ratio
                >= profile.verification_median_ratio
            )

    return SqliTimeBasedContext(
        baseline_statistics=baseline_statistics,
        baseline_stability=baseline_stability,
        verification_statistics=verification_statistics,

        valid_baseline_sample_count=len(
            valid_baseline_samples
        ),
        valid_verification_trial_count=len(
            valid_verification_samples
        ),

        decision_trial_count=len(decision_samples),
        delayed_trial_count=delayed_trial_count,

        required_delayed_trials=(
            profile.reproduction_required_successes
        ),
        required_verification_trials=(
            profile.verification_attempts_min
        ),

        aggregate_delay_threshold_ms=(
            aggregate_delay_threshold_ms
        ),
        aggregate_delay_passed=aggregate_delay_passed,
        aggregate_ratio_passed=aggregate_ratio_passed,

        credible_network_or_server_explanation=(
            credible_network_or_server_explanation
        ),

        verification_confidence=verification_confidence,

        failure_reasons=failure_reasons,
    )


def _collect_failure_reasons(
    *,
    baseline_samples: list[TimingSample],
    verification_samples: list[TimingSample],
) -> tuple[str, ...]:
    reasons: list[str] = []

    for phase, samples in (
        ("baseline", baseline_samples),
        ("verification", verification_samples),
    ):
        for sample in samples:
            validity = evaluate_trial_validity(sample)

            for reason in validity.failure_evaluation.reasons:
                text = (
                    f"{phase} request "
                    f"{sample.request_number}: {reason.value}"
                )

                if text not in reasons:
                    reasons.append(text)

    return tuple(reasons)