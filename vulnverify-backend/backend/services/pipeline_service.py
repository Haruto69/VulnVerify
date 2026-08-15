from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.replay.engine import execute_replay
from backend.replay.request_builder import build_replay_request


def replay_finding(
    finding: NormalizedFinding,
    timeout_seconds: float = 10.0,
) -> ReplayResult:
    """
    Replay a normalized finding using the generic replay pipeline.

    This function does not perform vulnerability-specific mutation
    or TP/FP classification.
    """

    replay_request = build_replay_request(
        finding
    )

    return execute_replay(
        finding_id=finding.finding_id,
        request=replay_request,
        timeout_seconds=timeout_seconds,
    )