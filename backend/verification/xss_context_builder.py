from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
    XssVerificationContext,
)
from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
)


def build_xss_verification_context(
    *,
    subtype: XssSubtype,
    attempts: list[XssReplayAttemptObservation],
    verification_confidence: float,
    blocking_reason: XssBlockingReason | None = None,
    stored_injection_completed: bool | None = None,
    stored_render_page_reached: bool | None = None,
    request_reference: str | None = None,
    response_reference: str | None = None,
) -> XssVerificationContext:
    derived_blocking_reason = (
        blocking_reason
        or _derive_blocking_reason(attempts)
    )

    distinct_variants = {
        attempt.payload_variant_id
        for attempt in attempts
        if attempt.payload_variant_id
    }

    marker_fired = any(
        attempt.marker_fired
        for attempt in attempts
    )

    marker_fired_in_correct_context = any(
        attempt.marker_fired
        and attempt.marker_fired_in_correct_context
        for attempt in attempts
    )

    static_confirming_variants = {
        attempt.payload_variant_id
        for attempt in attempts
        if (
            attempt.payload_reflected_or_rendered
            and attempt.payload_unescaped_in_executable_context
            and attempt.no_interfering_csp_encoding_or_sanitization
        )
    }

    two_distinct_static_confirmations = (
        len(static_confirming_variants) >= 2
    )

    two_distinct_attempts = (
        len(attempts) >= 2
        and len(distinct_variants) >= 2
    )

    marker_never_fired = (
        two_distinct_attempts
        and not marker_fired
    )

    return XssVerificationContext(
        subtype=subtype,
        replay_completed_successfully=(
            _verification_attempts_completed_successfully(
                subtype=subtype,
                attempts=attempts,
            )
        ),
        independent_replay_attempts=len(attempts),

        marker_fired=marker_fired,
        marker_fired_in_correct_context=(
            marker_fired_in_correct_context
        ),

        payload_reflected_or_rendered=any(
            attempt.payload_reflected_or_rendered
            for attempt in attempts
        ),
        payload_unescaped_in_executable_context=any(
            attempt.payload_unescaped_in_executable_context
            for attempt in attempts
        ),
        no_interfering_csp_encoding_or_sanitization=any(
            attempt.no_interfering_csp_encoding_or_sanitization
            for attempt in attempts
        ),

        second_confirmation_unescaped_in_executable_context=(
            two_distinct_static_confirmations
        ),

        payload_absent=_all_attempts_match(
            attempts,
            "payload_absent",
        ),
        payload_encoded_or_sanitized=_all_attempts_match(
            attempts,
            "payload_encoded_or_sanitized",
        ),
        payload_only_in_non_executable_context=_all_attempts_match(
            attempts,
            "payload_only_in_non_executable_context",
        ),
        payload_execution_vector_blocked_by_verified_policy=(
            _all_attempts_match(
                attempts,
                "payload_execution_vector_blocked_by_verified_policy",
            )
        ),

        marker_never_fired_across_independent_attempts=(
            marker_never_fired
        ),

        stored_injection_completed=stored_injection_completed,
        stored_render_page_reached=stored_render_page_reached,

        dom_attacker_controlled_data_reached_sink=(
            _derive_dom_sink_observation(attempts)
        ),

        blocking_reason=derived_blocking_reason,

        verification_confidence=verification_confidence,

        request_reference=request_reference,
        response_reference=response_reference,
    )


def _verification_attempts_completed_successfully(
    *,
    subtype: XssSubtype,
    attempts: list[XssReplayAttemptObservation],
) -> bool:
    if not attempts:
        return False

    for attempt in attempts:
        if not attempt.browser_completed_successfully:
            return False

        if subtype == XssSubtype.DOM_BASED:
            continue

        if attempt.replay is None:
            return False

        replay = attempt.replay

        if not replay.replay.executed:
            return False

        if replay.errors:
            return False

        status = replay.replay.response.status

        if status is None:
            return False

        if status >= 500:
            return False

    return True


def _derive_blocking_reason(
    attempts: list[XssReplayAttemptObservation],
) -> XssBlockingReason | None:
    for attempt in attempts:
        if attempt.browser_error is not None:
            return XssBlockingReason.BROWSER_RENDER_FAILURE

        replay = attempt.replay

        if replay is None:
            continue

        if not replay.replay.executed:
            return XssBlockingReason.TARGET_UNREACHABLE

        status = replay.replay.response.status

        if status is not None and status >= 500:
            return XssBlockingReason.TARGET_SERVER_ERROR

    return None


def _all_attempts_match(
    attempts: list[XssReplayAttemptObservation],
    field_name: str,
) -> bool:
    if not attempts:
        return False

    return all(
        bool(getattr(attempt, field_name))
        for attempt in attempts
    )


def _derive_dom_sink_observation(
    attempts: list[XssReplayAttemptObservation],
) -> bool | None:
    observations = [
        attempt.dom_attacker_controlled_data_reached_sink
        for attempt in attempts
        if attempt.dom_attacker_controlled_data_reached_sink
        is not None
    ]

    if not observations:
        return None

    if any(observations):
        return True

    return False