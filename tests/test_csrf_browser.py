from backend.verification.csrf_browser import (
    CsrfBrowserObservation,
    browser_context_blocks_authenticated_csrf,
    browser_context_unavailable,
)


def test_browser_blocks_csrf_when_session_cookie_not_sent():
    observation = CsrfBrowserObservation(
        browser_check_executed=True,
        authentication_sent=True,
        session_cookie_sent=False,
        cross_site_request_attempted=True,
        request_reached_target=True,
    )

    assert (
        browser_context_blocks_authenticated_csrf(
            observation
        )
        is True
    )


def test_browser_blocks_csrf_when_authentication_not_sent():
    observation = CsrfBrowserObservation(
        browser_check_executed=True,
        authentication_sent=False,
        session_cookie_sent=True,
        cross_site_request_attempted=True,
        request_reached_target=True,
    )

    assert (
        browser_context_blocks_authenticated_csrf(
            observation
        )
        is True
    )


def test_browser_does_not_block_when_auth_context_is_sent():
    observation = CsrfBrowserObservation(
        browser_check_executed=True,
        authentication_sent=True,
        session_cookie_sent=True,
        cross_site_request_attempted=True,
        request_reached_target=True,
    )

    assert (
        browser_context_blocks_authenticated_csrf(
            observation
        )
        is False
    )


def test_browser_not_executed_is_not_proof_of_protection():
    observation = CsrfBrowserObservation(
        browser_check_executed=False,
    )

    assert (
        browser_context_blocks_authenticated_csrf(
            observation
        )
        is False
    )


def test_browser_failure_is_unavailable():
    observation = CsrfBrowserObservation(
        browser_check_executed=True,
        cross_site_request_attempted=True,
        request_reached_target=None,
        errors=[
            "browser launch failed"
        ],
    )

    assert (
        browser_context_unavailable(
            observation
        )
        is True
    )


def test_successful_browser_check_is_not_unavailable():
    observation = CsrfBrowserObservation(
        browser_check_executed=True,
        cross_site_request_attempted=True,
        request_reached_target=True,
        authentication_sent=True,
        session_cookie_sent=True,
    )

    assert (
        browser_context_unavailable(
            observation
        )
        is False
    )