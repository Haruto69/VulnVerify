from pydantic import BaseModel, Field


class CsrfBrowserObservation(BaseModel):
    """
    Result of browser-context CSRF verification.

    This records whether the browser actually sent the required
    authentication/session context during a cross-site request.
    """

    browser_check_executed: bool = False

    authentication_sent: bool | None = None
    session_cookie_sent: bool | None = None

    cross_site_request_attempted: bool = False

    request_reached_target: bool | None = None
    state_change_observed: bool | None = None

    blocking_reason: str | None = None

    errors: list[str] = Field(default_factory=list)


def browser_context_blocks_authenticated_csrf(
    observation: CsrfBrowserObservation,
) -> bool:
    """
    Return True only when browser-context evidence demonstrates that
    the required authenticated state is not sent cross-site.
    """

    if not observation.browser_check_executed:
        return False

    auth_not_sent = (
        observation.authentication_sent is False
    )

    session_not_sent = (
        observation.session_cookie_sent is False
    )

    return auth_not_sent or session_not_sent


def browser_context_unavailable(
    observation: CsrfBrowserObservation,
) -> bool:
    """
    Browser verification was required/attempted but could not produce
    a reliable result.
    """

    return (
        observation.browser_check_executed
        and bool(observation.errors)
        and observation.request_reached_target is None
    )