from pydantic import BaseModel, Field


class CsrfStateObservation(BaseModel):
    """
    Result of checking application state around a CSRF replay.

    This model records evidence only.
    It does not classify the finding.
    """

    before_state_observed: bool = False
    after_state_observed: bool = False

    state_changed: bool | None = None

    deterministic_acceptance_indicator: str | None = None
    deterministic_acceptance_indicator_matched: bool = False

    observation_method: str | None = None

    errors: list[str] = Field(default_factory=list)


def derive_state_change_observed(
    observation: CsrfStateObservation,
) -> bool | None:
    """
    Return:
        True  -> state change directly observed.
        False -> before/after state observed and unchanged.
        None  -> state could not be determined.
    """

    if (
        observation.before_state_observed
        and observation.after_state_observed
        and observation.state_changed is not None
    ):
        return observation.state_changed

    return None


def has_strong_acceptance_evidence(
    observation: CsrfStateObservation,
) -> bool:
    """
    Deterministic application-level acceptance evidence may be used
    when an independent state observation is unavailable.
    """

    return (
        observation.deterministic_acceptance_indicator is not None
        and observation.deterministic_acceptance_indicator_matched
    )