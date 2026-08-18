from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.replay.engine import execute_replay
from backend.replay.request_builder import build_replay_request
from backend.replay.xss_query_mutation import (
    build_reflected_xss_variant_request,
)
from backend.verification.xss_context import XssSubtype
from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
)
from backend.verification.xss_response_analysis import (
    analyze_reflected_xss_response,
)


def replay_original_xss_request(
    *,
    finding: NormalizedFinding,
    subtype: XssSubtype,
    payload_variant_id: str = "scanner-original",
    timeout_seconds: float = 10.0,
) -> XssReplayAttemptObservation:
    """
    Replay the scanner-captured XSS request without modifying its
    payload or reconstructing a new XSS payload.

    DOM-based XSS is browser-only under the current cybersecurity
    specification and therefore does not perform an HTTP replay here.
    """
    if subtype == XssSubtype.DOM_BASED:
        return XssReplayAttemptObservation(
            payload_variant_id=payload_variant_id,
            replay=None,
        )

    replay_request = build_replay_request(finding)

    replay_result = execute_replay(
        finding_id=finding.finding_id,
        request=replay_request,
        timeout_seconds=timeout_seconds,
    )

    return XssReplayAttemptObservation(
        payload_variant_id=payload_variant_id,
        replay=replay_result,
    )


def collect_reflected_xss_variant_attempts(
    *,
    finding: NormalizedFinding,
    payload_variants: list[tuple[str, str]],
    timeout_seconds: float = 10.0,
) -> list[XssReplayAttemptObservation]:
    """
    Replay one HTTP request per (variant_id, payload) pair, mutating
    the finding's tested QUERY parameter for each, and run the
    conservative response-only analyzer against each result.

    Collection only: no aggregation across attempts and no TP/FP/
    INCONCLUSIVE classification happens here.
    """

    attempts: list[XssReplayAttemptObservation] = []

    for variant_id, payload in payload_variants:
        request = build_reflected_xss_variant_request(
            finding=finding,
            payload=payload,
        )

        replay_result = execute_replay(
            finding_id=finding.finding_id,
            request=request,
            timeout_seconds=timeout_seconds,
        )

        attempts.append(
            _build_reflected_attempt_observation(
                variant_id=variant_id,
                payload=payload,
                replay_result=replay_result,
            )
        )

    return attempts


def _build_reflected_attempt_observation(
    *,
    variant_id: str,
    payload: str,
    replay_result: ReplayResult,
) -> XssReplayAttemptObservation:
    replay_succeeded = (
        replay_result.replay.executed
        and not replay_result.errors
        and replay_result.replay.response.status is not None
        and replay_result.replay.response.status < 500
    )

    if not replay_succeeded:
        return XssReplayAttemptObservation(
            payload_variant_id=variant_id,
            replay=replay_result,
            browser_completed_successfully=False,
        )

    analysis = analyze_reflected_xss_response(
        payload=payload,
        response=replay_result.replay.response,
    )

    return XssReplayAttemptObservation(
        payload_variant_id=variant_id,
        replay=replay_result,
        browser_completed_successfully=True,
        payload_reflected_or_rendered=(
            analysis.payload_reflected_or_rendered
        ),
        payload_unescaped_in_executable_context=(
            analysis.payload_unescaped_in_executable_context
        ),
        no_interfering_csp_encoding_or_sanitization=(
            analysis.no_interfering_csp_encoding_or_sanitization
        ),
        payload_absent=analysis.payload_absent,
        payload_encoded_or_sanitized=(
            analysis.payload_encoded_or_sanitized
        ),
        payload_only_in_non_executable_context=(
            analysis.payload_only_in_non_executable_context
        ),
    )