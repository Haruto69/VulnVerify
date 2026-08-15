from enum import Enum

from pydantic import BaseModel

from backend.models.replay_result import (
    ReplayRequest,
    ReplayResult,
)
from backend.replay.engine import execute_replay


class CsrfDefenseLocation(str, Enum):
    HEADER = "HEADER"
    QUERY = "QUERY"
    BODY = "BODY"


class CsrfTokenReplayResult(BaseModel):
    original_replay: ReplayResult
    modified_replay: ReplayResult

    defense_location: CsrfDefenseLocation
    defense_name: str

    defense_removed: bool

    rejection_observed: bool
    rejection_status: int | None = None


def replay_without_csrf_defense(
    finding_id: str,
    request: ReplayRequest,
    defense_name: str,
    defense_location: CsrfDefenseLocation,
    timeout_seconds: float = 10.0,
) -> CsrfTokenReplayResult:
    """
    Replay a request once unchanged and once with the known CSRF
    defense removed.

    This function records what happened. It does not decide whether
    the finding is TRUE_POSITIVE or FALSE_POSITIVE.
    """

    original_replay = execute_replay(
        finding_id=finding_id,
        request=request,
        timeout_seconds=timeout_seconds,
    )

    modified_request = _remove_csrf_defense(
        request=request,
        defense_name=defense_name,
        defense_location=defense_location,
    )

    modified_replay = execute_replay(
        finding_id=finding_id,
        request=modified_request,
        timeout_seconds=timeout_seconds,
    )

    modified_status = (
        modified_replay.replay.response.status
    )

    rejection_observed = (
        modified_status in {403, 419}
    )

    return CsrfTokenReplayResult(
        original_replay=original_replay,
        modified_replay=modified_replay,
        defense_location=defense_location,
        defense_name=defense_name,
        defense_removed=True,
        rejection_observed=rejection_observed,
        rejection_status=modified_status,
    )


def _remove_csrf_defense(
    request: ReplayRequest,
    defense_name: str,
    defense_location: CsrfDefenseLocation,
) -> ReplayRequest:
    headers = dict(request.headers)
    url = request.url
    body = request.body

    if defense_location == CsrfDefenseLocation.HEADER:
        headers = {
            key: value
            for key, value in headers.items()
            if key.lower() != defense_name.lower()
        }

    elif defense_location == CsrfDefenseLocation.QUERY:
        url = _remove_query_parameter(
            url=url,
            parameter_name=defense_name,
        )

    elif defense_location == CsrfDefenseLocation.BODY:
        body = _remove_form_parameter(
            body=body,
            parameter_name=defense_name,
        )

    return ReplayRequest(
        method=request.method,
        url=url,
        headers=headers,
        body=body,
    )


def _remove_query_parameter(
    url: str,
    parameter_name: str,
) -> str:
    from urllib.parse import (
        parse_qsl,
        urlencode,
        urlsplit,
        urlunsplit,
    )

    parts = urlsplit(url)

    parameters = [
        (key, value)
        for key, value in parse_qsl(
            parts.query,
            keep_blank_values=True,
        )
        if key != parameter_name
    ]

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(parameters),
            parts.fragment,
        )
    )


def _remove_form_parameter(
    body: str | None,
    parameter_name: str,
) -> str | None:
    if body is None:
        return None

    from urllib.parse import (
        parse_qsl,
        urlencode,
    )

    parameters = [
        (key, value)
        for key, value in parse_qsl(
            body,
            keep_blank_values=True,
        )
        if key != parameter_name
    ]

    return urlencode(parameters)