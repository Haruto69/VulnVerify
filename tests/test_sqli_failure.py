from backend.verification.sqli_failure import (
    SqliFailureContext,
    SqliFailureReason,
    evaluate_sqli_failure,
)


def test_normal_success_response_is_not_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=200,
        )
    )

    assert result.inconclusive is False
    assert result.reasons == ()


def test_401_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=401,
        )
    )

    assert result.inconclusive is True
    assert (
        SqliFailureReason.AUTHENTICATION_REQUIRED
        in result.reasons
    )


def test_403_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=403,
        )
    )

    assert result.inconclusive is True
    assert SqliFailureReason.FORBIDDEN in result.reasons


def test_419_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=419,
        )
    )

    assert result.inconclusive is True
    assert (
        SqliFailureReason.CSRF_OR_SESSION_REJECTED
        in result.reasons
    )


def test_429_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=429,
        )
    )

    assert result.inconclusive is True
    assert SqliFailureReason.RATE_LIMITED in result.reasons


def test_missing_authentication_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=200,
            authentication_missing=True,
        )
    )

    assert result.inconclusive is True
    assert (
        SqliFailureReason.AUTHENTICATION_REQUIRED
        in result.reasons
    )


def test_expired_session_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=200,
            session_expired=True,
        )
    )

    assert result.inconclusive is True
    assert (
        SqliFailureReason.SESSION_EXPIRED
        in result.reasons
    )


def test_waf_block_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=200,
            waf_blocked=True,
        )
    )

    assert result.inconclusive is True
    assert SqliFailureReason.WAF_BLOCKED in result.reasons


def test_login_redirect_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=302,
            login_redirected=True,
        )
    )

    assert result.inconclusive is True
    assert (
        SqliFailureReason.LOGIN_REDIRECT
        in result.reasons
    )


def test_target_unreachable_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            target_unreachable=True,
        )
    )

    assert result.inconclusive is True
    assert (
        SqliFailureReason.TARGET_UNREACHABLE
        in result.reasons
    )


def test_dns_failure_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            dns_failure=True,
        )
    )

    assert result.inconclusive is True
    assert SqliFailureReason.DNS_FAILURE in result.reasons


def test_connection_failure_is_inconclusive():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            connection_failure=True,
        )
    )

    assert result.inconclusive is True
    assert (
        SqliFailureReason.CONNECTION_FAILURE
        in result.reasons
    )


def test_multiple_failure_reasons_are_preserved():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=401,
            session_expired=True,
            login_redirected=True,
        )
    )

    assert result.inconclusive is True

    assert result.reasons == (
        SqliFailureReason.AUTHENTICATION_REQUIRED,
        SqliFailureReason.SESSION_EXPIRED,
        SqliFailureReason.LOGIN_REDIRECT,
    )


def test_401_does_not_duplicate_authentication_reason():
    result = evaluate_sqli_failure(
        SqliFailureContext(
            status_code=401,
            authentication_missing=True,
        )
    )

    assert result.reasons.count(
        SqliFailureReason.AUTHENTICATION_REQUIRED
    ) == 1