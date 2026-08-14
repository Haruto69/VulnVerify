from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayRequest


def build_replay_request(
    finding: NormalizedFinding,
) -> ReplayRequest:
    """
    Build a replay-ready request from a normalized finding.

    This function only reconstructs the request captured during
    normalization. It does not perform vulnerability-specific
    mutations or send the request.
    """

    return ReplayRequest(
        method=finding.request.method,
        url=finding.request.url,
        headers=dict(finding.request.headers),
        body=finding.request.body,
    )