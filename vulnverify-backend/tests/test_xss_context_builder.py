from datetime import datetime, timezone

from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
)
from backend.verification.xss_context_builder import (
    build_xss_verification_context,
)
from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
)


def make_replay(
    *,
    status: int | None = 200,
    executed: bool = True,
    errors: list[str] | None = None,
) -> ReplayResult:
    return ReplayResult(
        finding_id="xss-001",
        replay=ReplayExecution(
            executed=executed,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://example.test/search?q=test",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={},
                body="<html></html>",
            ),
        ),
        observations=[],
        errors=errors or [],
    )


def test_single_marker_execution_builds_tp_evidence():
    context = build_xss_verification_context(
        subtype=XssSubtype.REFLECTED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=make_replay(),
                browser_completed_successfully=True,
                marker_fired=True,
                marker_fired_in_correct_context=True,
            ),
        ],
        verification_confidence=0.95,
    )

    assert context.marker_fired is True
    assert context.marker_fired_in_correct_context is True
    assert context.replay_completed_successfully is True


def test_two_distinct_static_confirmations_are_detected():
    attempts = [
        XssReplayAttemptObservation(
            payload_variant_id="variant-1",
            replay=make_replay(),
            browser_completed_successfully=True,
            payload_reflected_or_rendered=True,
            payload_unescaped_in_executable_context=True,
            no_interfering_csp_encoding_or_sanitization=True,
        ),
        XssReplayAttemptObservation(
            payload_variant_id="variant-2",
            replay=make_replay(),
            browser_completed_successfully=True,
            payload_reflected_or_rendered=True,
            payload_unescaped_in_executable_context=True,
            no_interfering_csp_encoding_or_sanitization=True,
        ),
    ]

    context = build_xss_verification_context(
        subtype=XssSubtype.REFLECTED,
        attempts=attempts,
        verification_confidence=0.90,
    )

    assert (
        context.second_confirmation_unescaped_in_executable_context
        is True
    )


def test_same_variant_twice_does_not_count_as_independent_fp_evidence():
    attempts = [
        XssReplayAttemptObservation(
            payload_variant_id="same-variant",
            replay=make_replay(),
            browser_completed_successfully=True,
            payload_encoded_or_sanitized=True,
        ),
        XssReplayAttemptObservation(
            payload_variant_id="same-variant",
            replay=make_replay(),
            browser_completed_successfully=True,
            payload_encoded_or_sanitized=True,
        ),
    ]

    context = build_xss_verification_context(
        subtype=XssSubtype.REFLECTED,
        attempts=attempts,
        verification_confidence=0.40,
    )

    assert (
        context.marker_never_fired_across_independent_attempts
        is False
    )


def test_two_distinct_neutralized_variants_build_fp_evidence():
    attempts = [
        XssReplayAttemptObservation(
            payload_variant_id="variant-1",
            replay=make_replay(),
            browser_completed_successfully=True,
            payload_encoded_or_sanitized=True,
        ),
        XssReplayAttemptObservation(
            payload_variant_id="variant-2",
            replay=make_replay(),
            browser_completed_successfully=True,
            payload_encoded_or_sanitized=True,
        ),
    ]

    context = build_xss_verification_context(
        subtype=XssSubtype.REFLECTED,
        attempts=attempts,
        verification_confidence=0.90,
    )

    assert context.payload_encoded_or_sanitized is True
    assert (
        context.marker_never_fired_across_independent_attempts
        is True
    )


def test_server_error_is_derived_as_inconclusive_blocker():
    context = build_xss_verification_context(
        subtype=XssSubtype.REFLECTED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=make_replay(status=503),
                browser_completed_successfully=False,
            ),
        ],
        verification_confidence=0.20,
    )

    assert (
        context.blocking_reason
        == XssBlockingReason.TARGET_SERVER_ERROR
    )


def test_transport_failure_is_target_unreachable():
    context = build_xss_verification_context(
        subtype=XssSubtype.REFLECTED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=make_replay(
                    status=None,
                    executed=False,
                    errors=["connection failed"],
                ),
                browser_completed_successfully=False,
            ),
        ],
        verification_confidence=0.20,
    )

    assert (
        context.blocking_reason
        == XssBlockingReason.TARGET_UNREACHABLE
    )


def test_browser_failure_is_derived():
    context = build_xss_verification_context(
        subtype=XssSubtype.REFLECTED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=make_replay(),
                browser_completed_successfully=False,
                browser_error="chromium failed to render",
            ),
        ],
        verification_confidence=0.20,
    )

    assert (
        context.blocking_reason
        == XssBlockingReason.BROWSER_RENDER_FAILURE
    )


def test_dom_does_not_require_http_replay():
    context = build_xss_verification_context(
        subtype=XssSubtype.DOM_BASED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=None,
                browser_completed_successfully=True,
                marker_fired=True,
                marker_fired_in_correct_context=True,
                dom_attacker_controlled_data_reached_sink=True,
            ),
        ],
        verification_confidence=0.95,
    )

    assert context.replay_completed_successfully is True
    assert (
        context.dom_attacker_controlled_data_reached_sink
        is True
    )