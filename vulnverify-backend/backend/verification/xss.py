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
from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
    XssVerificationContext,
)


def verify_xss(
    finding: NormalizedFinding,
    context: XssVerificationContext,
) -> VerifiedFinding:
    if finding.vulnerability.category != VulnerabilityCategory.XSS:
        raise ValueError("verify_xss() only accepts XSS findings")

    status, reason = classify_xss(context)

    return VerifiedFinding(
        finding_id=finding.finding_id,
        classification=VerificationClassification(
            status=status,
            confidence=context.verification_confidence,
            reason=reason,
        ),
        evidence=VerificationEvidence(
            indicators=_collect_indicators(context),
            request_reference=context.request_reference,
            response_reference=context.response_reference,
        ),
        verification_method=_verification_method(context.subtype),
    )


def classify_xss(
    context: XssVerificationContext,
) -> tuple[VerificationStatus, str]:
    inconclusive_reason = _get_inconclusive_reason(context)

    if inconclusive_reason is not None:
        return (
            VerificationStatus.INCONCLUSIVE,
            inconclusive_reason,
        )

    if _is_true_positive(context):
        return (
            VerificationStatus.TRUE_POSITIVE,
            (
                "Controlled XSS verification reproduced executable "
                "behavior in the required target execution context."
            ),
        )

    if _is_false_positive(context):
        return (
            VerificationStatus.FALSE_POSITIVE,
            (
                "Controlled replay completed successfully and the "
                "reported XSS behavior was neutralized, absent, "
                "non-executable, or specifically blocked across "
                "the required independent replay attempts."
            ),
        )

    return (
        VerificationStatus.INCONCLUSIVE,
        (
            "Available replay evidence does not satisfy the "
            "deterministic requirements for TRUE_POSITIVE or "
            "FALSE_POSITIVE."
        ),
    )


def _is_true_positive(
    context: XssVerificationContext,
) -> bool:
    marker_execution_confirmed = (
        context.marker_fired
        and context.marker_fired_in_correct_context
    )

    static_confirmation = all(
        [
            context.payload_reflected_or_rendered,
            context.payload_unescaped_in_executable_context,
            context.no_interfering_csp_encoding_or_sanitization,
            context.second_confirmation_unescaped_in_executable_context,
            context.independent_replay_attempts >= 2,
        ]
    )

    if context.subtype == XssSubtype.DOM_BASED:
        if marker_execution_confirmed:
            return (
                context.dom_attacker_controlled_data_reached_sink is True
            )

        return False

    if context.subtype == XssSubtype.STORED:
        if context.stored_injection_completed is not True:
            return False

        if context.stored_render_page_reached is not True:
            return False

    return marker_execution_confirmed or static_confirmation


def _is_false_positive(
    context: XssVerificationContext,
) -> bool:
    if not context.replay_completed_successfully:
        return False

    if context.independent_replay_attempts < 2:
        return False

    if not context.marker_never_fired_across_independent_attempts:
        return False

    if context.subtype == XssSubtype.STORED:
        if context.stored_render_page_reached is not True:
            return False

    if context.subtype == XssSubtype.DOM_BASED:
        if context.dom_attacker_controlled_data_reached_sink is False:
            return True

    neutralized_or_disproved = any(
        [
            context.payload_absent,
            context.payload_encoded_or_sanitized,
            context.payload_only_in_non_executable_context,
            context.payload_execution_vector_blocked_by_verified_policy,
        ]
    )

    return neutralized_or_disproved


def _get_inconclusive_reason(
    context: XssVerificationContext,
) -> str | None:
    if context.subtype == XssSubtype.UNKNOWN:
        return (
            "The XSS subtype is unknown and requires manual triage "
            "instead of automatic verification."
        )

    if context.blocking_reason is not None:
        return _blocking_reason_text(context.blocking_reason)

    if (
        context.subtype == XssSubtype.STORED
        and context.stored_injection_completed is True
        and context.stored_render_page_reached is not True
    ):
        return (
            "The stored XSS injection step completed, but the render "
            "page could not be confirmed as reachable."
        )

    return None


def _blocking_reason_text(
    reason: XssBlockingReason,
) -> str:
    messages = {
        XssBlockingReason.AUTH_SESSION_FAILURE:
            "Authentication or equivalent session context could not be established.",
        XssBlockingReason.CSRF_TOKEN_FAILURE:
            "A fresh valid CSRF token could not be obtained before replay.",
        XssBlockingReason.TARGET_UNREACHABLE:
            "The target endpoint could not be reached during replay.",
        XssBlockingReason.TARGET_TIMEOUT:
            "The target endpoint timed out during replay.",
        XssBlockingReason.TARGET_SERVER_ERROR:
            "The target returned a server error during replay.",
        XssBlockingReason.RENDER_PAGE_NOT_FOUND:
            "The stored XSS render page could not be located.",
        XssBlockingReason.RENDER_PAGE_UNREACHABLE:
            "The stored XSS render page could not be reached.",
        XssBlockingReason.BROWSER_RENDER_FAILURE:
            "The browser could not load or render the target for verification.",
        XssBlockingReason.ENVIRONMENT_DRIFT:
            "The application has materially changed since the scanner finding was recorded.",
        XssBlockingReason.WAF_REQUEST_BLOCK:
            "A WAF or rate limit blocked the replay request itself.",
        XssBlockingReason.INSUFFICIENT_EVIDENCE:
            "The available evidence is insufficient for deterministic XSS classification.",
        XssBlockingReason.REPLAY_REQUEST_INVALID:
            "The original request could not be reconstructed reliably enough for replay.",
    }

    return messages[reason]


def _verification_method(
    subtype: XssSubtype,
) -> str:
    methods = {
        XssSubtype.REFLECTED: "xss_reflected_rule_v1",
        XssSubtype.STORED: "xss_stored_rule_v1",
        XssSubtype.DOM_BASED: "xss_dom_rule_v1",
        XssSubtype.UNKNOWN: "xss_manual_triage_v1",
    }

    return methods[subtype]


def _collect_indicators(
    context: XssVerificationContext,
) -> list[str]:
    indicators: list[str] = []

    observed = [
        (
            context.marker_fired,
            "execution_marker_fired",
        ),
        (
            context.marker_fired_in_correct_context,
            "marker_fired_in_correct_context",
        ),
        (
            context.payload_reflected_or_rendered,
            "payload_reflected_or_rendered",
        ),
        (
            context.payload_unescaped_in_executable_context,
            "payload_unescaped_in_executable_context",
        ),
        (
            context.second_confirmation_unescaped_in_executable_context,
            "second_confirmation_unescaped_in_executable_context",
        ),
        (
            context.payload_absent,
            "payload_absent",
        ),
        (
            context.payload_encoded_or_sanitized,
            "payload_encoded_or_sanitized",
        ),
        (
            context.payload_only_in_non_executable_context,
            "payload_only_in_non_executable_context",
        ),
        (
            context.payload_execution_vector_blocked_by_verified_policy,
            "payload_execution_vector_blocked_by_verified_policy",
        ),
        (
            context.marker_never_fired_across_independent_attempts,
            "marker_never_fired_across_independent_attempts",
        ),
        (
            context.stored_injection_completed is True,
            "stored_injection_completed",
        ),
        (
            context.stored_render_page_reached is True,
            "stored_render_page_reached",
        ),
        (
            context.dom_attacker_controlled_data_reached_sink is True,
            "dom_attacker_controlled_data_reached_sink",
        ),
    ]

    for matched, indicator in observed:
        if matched:
            indicators.append(indicator)

    if context.blocking_reason is not None:
        indicators.append(
            f"blocking_reason:{context.blocking_reason.value}"
        )

    return indicators