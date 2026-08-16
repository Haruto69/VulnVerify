from backend.models.normalized_finding import NormalizedFinding
from backend.replay.engine import execute_replay
from backend.replay.request_builder import build_replay_request
from backend.verification.xss_context import XssSubtype
from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
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