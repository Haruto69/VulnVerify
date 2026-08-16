from backend.models.normalized_finding import (
    NormalizedFinding,
    VulnerabilityCategory,
)
from backend.models.verified_finding import (
    VerificationClassification,
    VerificationEvidence,
    VerificationStatus,
    VerifiedFinding,
)
from backend.verification.sqli_time_based_context import (
    SqliTimeBasedContext,
)


def classify_time_based_sqli(
    context: SqliTimeBasedContext,
) -> tuple[VerificationStatus, str]:
    if not context.baseline_stability.stable:
        return (
            VerificationStatus.INCONCLUSIVE,
            (
                "TIME_BASED SQLi verification could not establish "
                "a stable baseline."
            ),
        )

    if (
        context.valid_verification_trial_count
        < context.required_verification_trials
    ):
        return (
            VerificationStatus.INCONCLUSIVE,
            (
                "TIME_BASED SQLi verification did not obtain enough "
                "valid verification trials after retries."
            ),
        )

    if (
        context.decision_trial_count
        < context.required_verification_trials
    ):
        return (
            VerificationStatus.INCONCLUSIVE,
            (
                "TIME_BASED SQLi verification does not have enough "
                "valid trials for the configured decision window."
            ),
        )

    if context.credible_network_or_server_explanation:
        return (
            VerificationStatus.INCONCLUSIVE,
            (
                "The observed timing difference has a credible "
                "network or server-side explanation."
            ),
        )

    reproducible_delay = (
        context.delayed_trial_count
        >= context.required_delayed_trials
    )

    if (
        reproducible_delay
        and context.aggregate_delay_passed
        and context.aggregate_ratio_passed
    ):
        return (
            VerificationStatus.TRUE_POSITIVE,
            (
                "TIME_BASED SQLi timing behavior was reproduced "
                "across the required valid trials and satisfied "
                "the aggregate delay and timing-ratio thresholds."
            ),
        )

    return (
        VerificationStatus.FALSE_POSITIVE,
        (
            "A stable baseline and sufficient valid verification "
            "trials were obtained, but the required TIME_BASED "
            "SQLi delay pattern was not reproduced."
        ),
    )


def verify_time_based_sqli(
    *,
    finding: NormalizedFinding,
    context: SqliTimeBasedContext,
) -> VerifiedFinding:
    if (
        finding.vulnerability.category
        != VulnerabilityCategory.SQLI
    ):
        raise ValueError(
            "verify_time_based_sqli() only accepts SQLI findings"
        )

    status, reason = classify_time_based_sqli(
        context
    )

    return VerifiedFinding(
        finding_id=finding.finding_id,
        classification=VerificationClassification(
            status=status,
            confidence=context.verification_confidence,
            reason=reason,
        ),
        evidence=VerificationEvidence(
            indicators=_build_indicators(context),
            request_reference=None,
            response_reference=None,
        ),
        verification_method="sqli_time_based_rule_v1",
    )


def _build_indicators(
    context: SqliTimeBasedContext,
) -> list[str]:
    indicators: list[str] = []

    if context.baseline_statistics is not None:
        indicators.extend(
            [
                (
                    "baseline_median_ms:"
                    f"{context.baseline_statistics.median_ms:.3f}"
                ),
                (
                    "baseline_mad_ms:"
                    f"{context.baseline_statistics.mad_ms:.3f}"
                ),
                (
                    "baseline_variation_ratio:"
                    f"{context.baseline_statistics.variation_ratio:.6f}"
                ),
            ]
        )

    indicators.append(
        f"baseline_stable:{context.baseline_stability.stable}"
    )

    indicators.append(
        "valid_verification_trials:"
        f"{context.valid_verification_trial_count}"
    )

    indicators.append(
        "delayed_trials:"
        f"{context.delayed_trial_count}/"
        f"{context.decision_trial_count}"
    )

    if context.verification_statistics is not None:
        indicators.extend(
            [
                (
                    "verification_median_ms:"
                    f"{context.verification_statistics.median_ms:.3f}"
                ),
                (
                    "timing_delta_ms:"
                    f"{context.verification_statistics.timing_delta_ms:.3f}"
                ),
                (
                    "timing_ratio:"
                    f"{context.verification_statistics.timing_ratio:.6f}"
                ),
            ]
        )

    indicators.append(
        f"aggregate_delay_passed:{context.aggregate_delay_passed}"
    )
    indicators.append(
        f"aggregate_ratio_passed:{context.aggregate_ratio_passed}"
    )

    if context.credible_network_or_server_explanation:
        indicators.append(
            "credible_network_or_server_explanation"
        )

    indicators.extend(
        f"failure:{reason}"
        for reason in context.failure_reasons
    )

    return indicators