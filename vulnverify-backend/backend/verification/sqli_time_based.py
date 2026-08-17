from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.models.verified_finding import VerifiedFinding
from backend.verification.sqli_contract import (
    SqliDecision,
    SqliReasonCode,
    SqliVerificationStatus,
    build_verified_finding,
    inconclusive_decision,
    repeated_absence_false_positive_confidence,
    true_positive_confidence,
)
from backend.verification.sqli_failure import SqliFailureReason
from backend.verification.sqli_time_based_context import (
    SqliTimeBasedContext,
)


def verify_sqli_time_based(
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    context: SqliTimeBasedContext,
    *,
    scanner_evidence_agrees: bool = False,
) -> VerifiedFinding:
    """
    Classify TIME_BASED SQLi from deterministic timing evidence.

    Numeric verification confidence is derived here from the frozen
    SQLi confidence policy. context.verification_confidence is kept
    only for compatibility with the existing context model and is not
    trusted as a classification input.

    Mahita's final clarification also means missing infrastructure
    telemetry is not itself INCONCLUSIVE. The existing context flag
    credible_network_or_server_explanation is treated as evidence that
    external timing interference was actually observed.
    """

    if finding.vulnerability.category != "SQLI":
        raise ValueError(
            "TIME_BASED SQLi verifier received a non-SQLI finding"
        )

    failure_decision = _failure_decision(
        context
    )

    if failure_decision is not None:
        return build_verified_finding(
            finding=finding,
            decision=failure_decision,
            verification_method="sqli_time_based_rule_v1",
            response_available=(
                replay_result.replay.response.status
                is not None
            ),
        )

    if not context.baseline_stability.stable:
        decision = inconclusive_decision(
            SqliReasonCode.INC_UNSTABLE_BASELINE,
            "The TIME_BASED baseline is not stable under the approved MAD-to-median rule.",
            indicators=("unstable_time_based_baseline",),
        )

        return build_verified_finding(
            finding=finding,
            decision=decision,
            verification_method="sqli_time_based_rule_v1",
            response_available=True,
        )

    if (
        context.valid_verification_trial_count
        < context.required_verification_trials
    ):
        decision = inconclusive_decision(
            SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS,
            "Fewer than three valid TIME_BASED verification trials were obtained after the allowed attempts.",
            indicators=("insufficient_valid_timing_trials",),
        )

        return build_verified_finding(
            finding=finding,
            decision=decision,
            verification_method="sqli_time_based_rule_v1",
            response_available=True,
        )

    if context.credible_network_or_server_explanation:
        decision = inconclusive_decision(
            SqliReasonCode.INC_EXTERNAL_TIMING_EXPLANATION,
            "Available observations show an external timing explanation that prevents reliable attribution to the tested SQL condition.",
            indicators=("external_timing_interference_observed",),
        )

        return build_verified_finding(
            finding=finding,
            decision=decision,
            verification_method="sqli_time_based_rule_v1",
            response_available=True,
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
        decision = SqliDecision(
            status=SqliVerificationStatus.TRUE_POSITIVE,
            confidence=true_positive_confidence(
                scanner_evidence_agrees=(
                    scanner_evidence_agrees
                )
            ),
            reason_code=(
                SqliReasonCode.TP_REPRODUCIBLE_TIMING_DIFFERENCE
            ),
            reason=(
                "A stable baseline was established, at least two of the first three valid verification trials independently satisfied the approved delay rule, and both aggregate timing checks passed without observed external interference."
            ),
            indicators=(
                "stable_timing_baseline",
                "timing_delay_reproduced_2_of_3",
                "aggregate_delay_passed",
                "aggregate_ratio_passed",
                "no_observed_external_interference",
            ),
        )

        return build_verified_finding(
            finding=finding,
            decision=decision,
            verification_method="sqli_time_based_rule_v1",
            response_available=True,
        )

    decision = SqliDecision(
        status=SqliVerificationStatus.FALSE_POSITIVE,
        confidence=repeated_absence_false_positive_confidence(),
        reason_code=SqliReasonCode.FP_NO_TIMING_DIFFERENCE,
        reason=(
            "The baseline was stable and the required valid verification trials completed, but the approved reproducible TIME_BASED delay pattern was absent."
        ),
        indicators=(
            "stable_timing_baseline",
            "required_timing_trials_completed",
            "reproducible_delay_pattern_absent",
        ),
    )

    return build_verified_finding(
        finding=finding,
        decision=decision,
        verification_method="sqli_time_based_rule_v1",
        response_available=True,
    )


def _failure_decision(
    context: SqliTimeBasedContext,
) -> SqliDecision | None:
    reasons = set(context.failure_reason_codes)

    if (
        SqliFailureReason.AUTHENTICATION_REQUIRED in reasons
        or SqliFailureReason.FORBIDDEN in reasons
    ):
        return inconclusive_decision(
            SqliReasonCode.INC_AUTHENTICATION_FAILED,
            "Authentication or authorization state prevented reliable TIME_BASED verification.",
        )

    if SqliFailureReason.SESSION_EXPIRED in reasons:
        return inconclusive_decision(
            SqliReasonCode.INC_SESSION_EXPIRED,
            "The application session expired during TIME_BASED verification.",
        )

    if SqliFailureReason.WAF_BLOCKED in reasons:
        return inconclusive_decision(
            SqliReasonCode.INC_WAF_BLOCKED,
            "WAF interference prevented reliable TIME_BASED verification.",
        )

    if SqliFailureReason.RATE_LIMITED in reasons:
        return inconclusive_decision(
            SqliReasonCode.INC_RATE_LIMITED,
            "Rate limiting prevented reliable TIME_BASED verification.",
        )

    if (
        SqliFailureReason.TARGET_UNREACHABLE in reasons
        or SqliFailureReason.DNS_FAILURE in reasons
        or SqliFailureReason.CONNECTION_FAILURE in reasons
    ):
        return inconclusive_decision(
            SqliReasonCode.INC_NETWORK_FAILURE,
            "Target, DNS, or connection failure prevented reliable TIME_BASED verification.",
        )

    if SqliFailureReason.CSRF_OR_SESSION_REJECTED in reasons:
        return inconclusive_decision(
            SqliReasonCode.INC_SESSION_EXPIRED,
            "Session or request-state rejection prevented reliable TIME_BASED verification.",
        )

    if SqliFailureReason.LOGIN_REDIRECT in reasons:
        return inconclusive_decision(
            SqliReasonCode.INC_AUTHENTICATION_FAILED,
            "A login redirect prevented reliable TIME_BASED verification.",
        )

    return None
