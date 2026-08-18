from enum import Enum
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

from pydantic import BaseModel

from backend.models.replay_result import (
    ReplayRequest,
    ReplayResult,
)
from backend.replay.engine import execute_replay


DEFAULT_ATTACKER_ORIGIN = "https://attacker.example"
DEFAULT_ATTACKER_REFERER = (
    "https://attacker.example/csrf-test"
)


class CsrfDefenseLocation(str, Enum):
    HEADER = "HEADER"
    QUERY = "QUERY"
    BODY = "BODY"


class CsrfOriginMutation(str, Enum):
    ORIGIN = "ORIGIN"
    REFERER = "REFERER"
    BOTH = "BOTH"


class CsrfTokenReplayResult(BaseModel):
    original_replay: ReplayResult
    modified_replay: ReplayResult

    defense_location: CsrfDefenseLocation
    defense_name: str

    defense_removed: bool

    rejection_observed: bool
    rejection_status: int | None = None


class CsrfOriginReplayResult(BaseModel):
    original_replay: ReplayResult
    modified_replay: ReplayResult

    mutation: CsrfOriginMutation

    attacker_origin: str | None = None
    attacker_referer: str | None = None

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


def replay_with_cross_site_origin(
    finding_id: str,
    request: ReplayRequest,
    mutation: CsrfOriginMutation,
    timeout_seconds: float = 10.0,
    attacker_origin: str = DEFAULT_ATTACKER_ORIGIN,
    attacker_referer: str = DEFAULT_ATTACKER_REFERER,
) -> CsrfOriginReplayResult:
    """
    Replay a request once unchanged and once using controlled
    cross-site Origin and/or Referer values.

    Authentication/session data and unrelated request fields are
    preserved.

    A rejection is recorded only as an observation. Classification
    requires separate verification that the rejection is attributable
    to Origin/Referer enforcement.
    """

    original_replay = execute_replay(
        finding_id=finding_id,
        request=request,
        timeout_seconds=timeout_seconds,
    )

    modified_request = _apply_cross_site_origin(
        request=request,
        mutation=mutation,
        attacker_origin=attacker_origin,
        attacker_referer=attacker_referer,
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

    return CsrfOriginReplayResult(
        original_replay=original_replay,
        modified_replay=modified_replay,
        mutation=mutation,
        attacker_origin=(
            attacker_origin
            if mutation
            in {
                CsrfOriginMutation.ORIGIN,
                CsrfOriginMutation.BOTH,
            }
            else None
        ),
        attacker_referer=(
            attacker_referer
            if mutation
            in {
                CsrfOriginMutation.REFERER,
                CsrfOriginMutation.BOTH,
            }
            else None
        ),
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


def _apply_cross_site_origin(
    request: ReplayRequest,
    mutation: CsrfOriginMutation,
    attacker_origin: str,
    attacker_referer: str,
) -> ReplayRequest:
    """
    Copy the replay request and replace only the selected source
    headers.

    Existing header capitalization is handled case-insensitively.
    """

    headers = dict(request.headers)

    if mutation in {
        CsrfOriginMutation.ORIGIN,
        CsrfOriginMutation.BOTH,
    }:
        headers = _set_header(
            headers=headers,
            name="Origin",
            value=attacker_origin,
        )

    if mutation in {
        CsrfOriginMutation.REFERER,
        CsrfOriginMutation.BOTH,
    }:
        headers = _set_header(
            headers=headers,
            name="Referer",
            value=attacker_referer,
        )

    return ReplayRequest(
        method=request.method,
        url=request.url,
        headers=headers,
        body=request.body,
    )


def _set_header(
    headers: dict[str, str],
    name: str,
    value: str,
) -> dict[str, str]:
    """
    Set a header case-insensitively without creating duplicates.
    """

    updated_headers = {
        key: existing_value
        for key, existing_value in headers.items()
        if key.lower() != name.lower()
    }

    updated_headers[name] = value

    return updated_headers


def _remove_query_parameter(
    url: str,
    parameter_name: str,
) -> str:
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

    parameters = [
        (key, value)
        for key, value in parse_qsl(
            body,
            keep_blank_values=True,
        )
        if key != parameter_name
    ]

    return urlencode(parameters)