from datetime import datetime, timezone

import httpx

from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)


def execute_replay(
    finding_id: str,
    request: ReplayRequest,
    timeout_seconds: float = 10.0,
) -> ReplayResult:
    """
    Execute a replay request and record what happened.

    This function performs only generic HTTP execution.
    It does not perform vulnerability-specific mutations,
    observations, or TP/FP classification.
    """

    timestamp = datetime.now(timezone.utc)

    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=timeout_seconds,
        ) as client:
            response = client.request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                content=request.body,
            )

        replay_response = ReplayResponse(
            status=response.status_code,
            headers=dict(response.headers),
            body=response.text,
        )

        errors = []

    except httpx.RequestError as exc:
        replay_response = ReplayResponse(
            status=None,
            headers={},
            body=None,
        )

        errors = [
            f"{type(exc).__name__}: {exc}"
        ]

    return ReplayResult(
        finding_id=finding_id,
        replay=ReplayExecution(
            executed=True,
            timestamp=timestamp,
            request=request,
            response=replay_response,
        ),
        observations=[],
        errors=errors,
    )