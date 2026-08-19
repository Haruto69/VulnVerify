"""
Tests for backend/replay/session_refresh.py -- generic, opt-in
authenticated-replay session refresh -- and its wiring into
backend/replay/request_builder.py, the CSRF/SQLi/XSS verification
paths in backend/api/findings.py, and automatic verification
(backend/services/auto_verification_service.py).

No live DVWA (or any live target) is required: session-refresh
network calls are mocked at the httpx.Client level, exactly the way
the existing replay tests already mock backend.replay.engine's use
of httpx.
"""

import json
import logging

from backend.models.normalized_finding import (
    FindingContext,
    FindingSource,
    HttpRequest,
    NormalizedConfidence,
    NormalizedFinding,
    NormalizedSeverity,
    OriginalTest,
    ParameterLocation,
    RequirementState,
    TargetInfo,
    VulnerabilityCategory,
    VulnerabilityInfo,
)
from backend.replay.request_builder import build_replay_request
from backend.replay.session_refresh import (
    AuthSessionConfig,
    finding_requires_authentication,
    load_auth_session_config_from_env,
    refresh_session,
    resolve_session_cookie_override,
)


ENV_KEYS = [
    "VULNVERIFY_AUTH_LOGIN_URL",
    "VULNVERIFY_AUTH_USERNAME",
    "VULNVERIFY_AUTH_PASSWORD",
    "VULNVERIFY_AUTH_USERNAME_FIELD",
    "VULNVERIFY_AUTH_PASSWORD_FIELD",
    "VULNVERIFY_AUTH_COOKIE_NAME",
    "VULNVERIFY_AUTH_METHOD",
    "VULNVERIFY_AUTH_EXTRA_FIELD_Login",
]


def clear_auth_env(monkeypatch):
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def set_dvwa_style_auth_env(monkeypatch):
    monkeypatch.setenv(
        "VULNVERIFY_AUTH_LOGIN_URL",
        "http://127.0.0.1/DVWA/login.php",
    )
    monkeypatch.setenv("VULNVERIFY_AUTH_USERNAME", "admin")
    monkeypatch.setenv("VULNVERIFY_AUTH_PASSWORD", "password")
    monkeypatch.setenv("VULNVERIFY_AUTH_EXTRA_FIELD_Login", "Login")


def make_finding(
    *,
    requires_auth: bool = True,
    cookie_header: str | None = "PHPSESSID=stale-session-0001",
) -> NormalizedFinding:
    headers = {"host": "127.0.0.1"}
    if cookie_header is not None:
        headers["cookie"] = cookie_header

    return NormalizedFinding(
        scan_id="scan-session-001",
        finding_id="finding-session-001",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.SQLI,
            subtype=None,
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-89",
        ),
        target=TargetInfo(
            url="http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1",
            normalized_url=(
                "http://127.0.0.1/DVWA/vulnerabilities/sqli/"
            ),
            host="127.0.0.1",
            path="/DVWA/vulnerabilities/sqli/",
            parameter="id",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(payload="'", evidence="SQL error"),
        request=HttpRequest(
            method="GET",
            url="http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1",
            path="/DVWA/vulnerabilities/sqli/",
            headers=headers,
            body=None,
        ),
        context=FindingContext(
            authentication_required=(
                RequirementState.YES
                if requires_auth
                else RequirementState.NO
            ),
            session_required=RequirementState.UNKNOWN,
        ),
    )


class _FakeResponse:
    def __init__(self, status_code, cookies):
        self.status_code = status_code
        self.cookies = cookies


class _FakeHttpxClient:
    """
    Stands in for httpx.Client in backend.replay.session_refresh --
    records the request it was given and returns a preconfigured
    response, without any real network I/O.
    """

    calls: list[dict] = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def request(self, *, method, url, data):
        _FakeHttpxClient.calls.append(
            {"method": method, "url": url, "data": dict(data)}
        )
        return _FakeHttpxClient.response


def install_fake_httpx_client(
    monkeypatch,
    status_code=302,
    cookies=None,
):
    _FakeHttpxClient.calls = []
    _FakeHttpxClient.response = _FakeResponse(
        status_code=status_code,
        cookies=(
            cookies
            if cookies is not None
            else {"PHPSESSID": "fresh-session-9999"}
        ),
    )
    monkeypatch.setattr(
        "backend.replay.session_refresh.httpx.Client",
        _FakeHttpxClient,
    )
    return _FakeHttpxClient


# ---------------------------------------------------------------------
# D. No refresh configuration exists -> resolve returns None (caller
# falls back to the original scanner-captured Cookie, and the existing
# staleness detection still produces INCONCLUSIVE for a genuinely
# stale session).
# ---------------------------------------------------------------------


def test_no_env_config_means_no_refresh(monkeypatch):
    clear_auth_env(monkeypatch)

    assert load_auth_session_config_from_env() is None

    finding = make_finding(requires_auth=True)
    assert resolve_session_cookie_override(finding) is None


def test_partial_env_config_is_not_used(monkeypatch):
    # Missing password: must not silently proceed with a partial
    # config or guess a blank password.
    clear_auth_env(monkeypatch)
    monkeypatch.setenv(
        "VULNVERIFY_AUTH_LOGIN_URL", "http://127.0.0.1/login"
    )
    monkeypatch.setenv("VULNVERIFY_AUTH_USERNAME", "admin")

    assert load_auth_session_config_from_env() is None


# ---------------------------------------------------------------------
# finding_requires_authentication: only findings whose own normalized
# context calls for it are ever eligible for a refresh attempt.
# ---------------------------------------------------------------------


def test_finding_not_requiring_auth_never_triggers_refresh(
    monkeypatch,
):
    set_dvwa_style_auth_env(monkeypatch)
    fake_client = install_fake_httpx_client(monkeypatch)

    finding = make_finding(requires_auth=False)

    assert finding_requires_authentication(finding) is False
    assert resolve_session_cookie_override(finding) is None
    assert fake_client.calls == []


# ---------------------------------------------------------------------
# E. Refresh configuration exists -> login/session refresh occurs.
# ---------------------------------------------------------------------


def test_refresh_session_posts_credentials_and_returns_cookie(
    monkeypatch,
):
    fake_client = install_fake_httpx_client(
        monkeypatch,
        status_code=302,
        cookies={"PHPSESSID": "fresh-session-9999"},
    )

    config = AuthSessionConfig(
        login_url="http://127.0.0.1/DVWA/login.php",
        username="admin",
        password="password",
        extra_fields={"Login": "Login"},
    )

    result = refresh_session(config)

    assert result == "PHPSESSID=fresh-session-9999"
    assert len(fake_client.calls) == 1
    assert (
        fake_client.calls[0]["url"]
        == "http://127.0.0.1/DVWA/login.php"
    )
    assert fake_client.calls[0]["data"] == {
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }


def test_refresh_session_filters_to_configured_cookie_name(
    monkeypatch,
):
    install_fake_httpx_client(
        monkeypatch,
        cookies={
            "PHPSESSID": "fresh-session-9999",
            "unrelated_tracking_cookie": "abc",
        },
    )

    config = AuthSessionConfig(
        login_url="http://127.0.0.1/DVWA/login.php",
        username="admin",
        password="password",
        cookie_name="PHPSESSID",
    )

    result = refresh_session(config)

    assert result == "PHPSESSID=fresh-session-9999"


def test_refresh_session_returns_none_when_login_fails(monkeypatch):
    install_fake_httpx_client(monkeypatch, status_code=403)

    config = AuthSessionConfig(
        login_url="http://127.0.0.1/DVWA/login.php",
        username="admin",
        password="wrong-password",
    )

    assert refresh_session(config) is None


def test_refresh_session_returns_none_when_no_cookie_set(
    monkeypatch,
):
    install_fake_httpx_client(monkeypatch, status_code=200, cookies={})

    config = AuthSessionConfig(
        login_url="http://127.0.0.1/DVWA/login.php",
        username="admin",
        password="password",
    )

    assert refresh_session(config) is None


def test_refresh_session_handles_network_failure(monkeypatch):
    import httpx

    class RaisingClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, **kwargs):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(
        "backend.replay.session_refresh.httpx.Client",
        RaisingClient,
    )

    config = AuthSessionConfig(
        login_url="http://127.0.0.1/DVWA/login.php",
        username="admin",
        password="password",
    )

    assert refresh_session(config) is None


# ---------------------------------------------------------------------
# K. Credentials are never written to logs.
# ---------------------------------------------------------------------


def test_credentials_never_appear_in_logs(monkeypatch, caplog):
    install_fake_httpx_client(monkeypatch, status_code=403)

    config = AuthSessionConfig(
        login_url="http://127.0.0.1/DVWA/login.php",
        username="super-secret-admin",
        password="super-secret-password",
    )

    with caplog.at_level(logging.DEBUG):
        refresh_session(config)
        # repr()/str() are exactly what an uncaught exception,
        # logging.exception(), or a debugger would stringify.
        rendered = repr(config) + str(config) + logging.Formatter(
        ).format(
            logging.LogRecord(
                "x", logging.INFO, "", 0, "%s", (config,), None
            )
        )

    for record in caplog.records:
        assert "super-secret-admin" not in record.getMessage()
        assert "super-secret-password" not in record.getMessage()

    assert "super-secret-admin" not in rendered
    assert "super-secret-password" not in rendered


# ---------------------------------------------------------------------
# B/F/G. build_replay_request: original request preserved; only the
# Cookie header changes when an override is supplied; nothing changes
# when it is not.
# ---------------------------------------------------------------------


def test_build_replay_request_uses_original_cookie_when_no_override():
    finding = make_finding(
        cookie_header="PHPSESSID=still-valid-session"
    )

    request = build_replay_request(finding)

    assert request.headers["cookie"] == "PHPSESSID=still-valid-session"
    assert request.method == "GET"
    assert request.url == finding.request.url


def test_build_replay_request_override_replaces_only_cookie():
    finding = make_finding(
        cookie_header="PHPSESSID=stale-session-0001"
    )

    request = build_replay_request(
        finding, session_cookie_override="PHPSESSID=fresh-session-9999"
    )

    assert request.headers["cookie"] == "PHPSESSID=fresh-session-9999"
    # Everything else about the request is unchanged.
    assert request.method == finding.request.method
    assert request.url == finding.request.url
    assert request.body == finding.request.body
    assert request.headers["host"] == "127.0.0.1"


def test_build_replay_request_override_adds_cookie_when_absent():
    finding = make_finding(cookie_header=None)
    assert "cookie" not in finding.request.headers

    request = build_replay_request(
        finding, session_cookie_override="PHPSESSID=fresh-session-9999"
    )

    assert request.headers["cookie"] == "PHPSESSID=fresh-session-9999"
