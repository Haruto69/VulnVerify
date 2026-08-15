from typing import Any, Callable

from pydantic import BaseModel, Field

from backend.models.replay_result import (
    ReplayRequest,
    ReplayResult,
)
from backend.replay.engine import execute_replay
from backend.verification.csrf_state import (
    CsrfStateObservation,
)


class CsrfStateSnapshot(BaseModel):
    observed: bool
    value: Any | None = None
    errors: list[str] = Field(default_factory=list)


def perform_csrf_state_check(
    finding_id: str,
    forged_request: ReplayRequest,
    observe_state: Callable[[], CsrfStateSnapshot],
    timeout_seconds: float = 10.0,
    deterministic_acceptance_indicator: str | None = None,
) -> tuple[
    ReplayResult,
    CsrfStateObservation,
]:
    """
    Observe application state before replay, execute the forged
    request, then observe state again.

    State observation is supplied by the caller so this orchestration
    does not guess how a particular application exposes its state.
    """

    before = observe_state()

    replay_result = execute_replay(
        finding_id=finding_id,
        request=forged_request,
        timeout_seconds=timeout_seconds,
    )

    after = observe_state()

    state_changed = _compare_state(
        before=before,
        after=after,
    )

    indicator_matched = _indicator_matched(
        replay_result=replay_result,
        indicator=deterministic_acceptance_indicator,
    )

    errors = [
        *before.errors,
        *after.errors,
    ]

    return (
        replay_result,
        CsrfStateObservation(
            before_state_observed=before.observed,
            after_state_observed=after.observed,
            state_changed=state_changed,
            deterministic_acceptance_indicator=(
                deterministic_acceptance_indicator
            ),
            deterministic_acceptance_indicator_matched=(
                indicator_matched
            ),
            observation_method=(
                "before_after_state_check"
                if before.observed and after.observed
                else "response_indicator"
                if indicator_matched
                else None
            ),
            errors=errors,
        ),
    )


def _compare_state(
    before: CsrfStateSnapshot,
    after: CsrfStateSnapshot,
) -> bool | None:
    """
    True  -> both states observed and changed.
    False -> both states observed and unchanged.
    None  -> comparison cannot be made reliably.
    """

    if not before.observed or not after.observed:
        return None

    return before.value != after.value


def _indicator_matched(
    replay_result: ReplayResult,
    indicator: str | None,
) -> bool:
    if indicator is None:
        return False

    body = replay_result.replay.response.body

    if body is None:
        return False

    return indicator in body