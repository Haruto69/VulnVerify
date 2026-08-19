"""
Generic, opt-in authenticated-replay session refresh.

Problem this solves: every replay request is currently reconstructed
from the scanner-captured Cookie header (see
backend/replay/request_builder.py::build_replay_request). That header
was valid when the scan ran, but by the time verification happens --
possibly much later -- the session it names may have expired. The
vulnerable endpoint can still be real and exploitable; only the
captured credential material is stale. Without a way to obtain a
*current* session, verification can only ever fall back to
INCONCLUSIVE for such findings (see
backend/verification/csrf_context.py::_session_unavailable, which
already detects this from the replay's own 401/redirect response --
that detection is untouched by this module).

What this module deliberately does NOT do:
  - It never guesses a login URL, username, password, or form field
    name. AuthSessionConfig must be fully, explicitly supplied
    (see load_auth_session_config_from_env below) -- nothing here
    invents credentials.
  - It never hardcodes DVWA or any other specific application. The
    login POST is a generic username/password form submission; which
    URL and field names to use is entirely caller-supplied
    configuration.
  - It never classifies a finding. This module only ever returns a
    Cookie header string (or None) for the replay layer to use --
    TRUE_POSITIVE/FALSE_POSITIVE/INCONCLUSIVE decisions remain
    entirely with the existing, unmodified verifiers.
  - It never persists the password anywhere. AuthSessionConfig is
    built fresh from environment variables (or an explicit
    caller-supplied instance) on each use and is never written to
    backend/storage/repository.py's scans/findings/verified_findings
    collections.
"""

import logging
import os

import httpx
from pydantic import BaseModel, Field

from backend.models.normalized_finding import NormalizedFinding


logger = logging.getLogger(__name__)


_ENV_LOGIN_URL = "VULNVERIFY_AUTH_LOGIN_URL"
_ENV_USERNAME = "VULNVERIFY_AUTH_USERNAME"
_ENV_PASSWORD = "VULNVERIFY_AUTH_PASSWORD"
_ENV_USERNAME_FIELD = "VULNVERIFY_AUTH_USERNAME_FIELD"
_ENV_PASSWORD_FIELD = "VULNVERIFY_AUTH_PASSWORD_FIELD"
_ENV_EXTRA_FIELD_PREFIX = "VULNVERIFY_AUTH_EXTRA_FIELD_"
_ENV_COOKIE_NAME = "VULNVERIFY_AUTH_COOKIE_NAME"
_ENV_METHOD = "VULNVERIFY_AUTH_METHOD"


class AuthSessionConfig(BaseModel):
    """
    The smallest generic description of "how to log in" this project
    needs: a login endpoint plus a username/password form submission.
    Covers ordinary form-based login (DVWA, and most simple web apps)
    without encoding any single application's specifics.

    Optional:
      extra_fields: additional static form fields the login endpoint
        requires beyond username/password (e.g. a submit-button
        name/value pair like DVWA's Login=Login). Never a place to
        smuggle in more credentials -- values here are configuration,
        not secrets, and may end up in logs/errors like any other
        non-sensitive form field.
      cookie_name: if set, only this cookie is taken from the login
        response and reused; if None, every cookie the login response
        sets is reused. Leaving it unset is the safe default for an
        unknown application (a login response may set more than one
        cookie that together represent the session).
    """

    login_url: str
    username: str = Field(repr=False)
    password: str = Field(repr=False)
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict[str, str] = Field(default_factory=dict)
    method: str = "POST"
    cookie_name: str | None = None

    def __repr__(self) -> str:
        # Pydantic's default __repr__ already omits repr=False fields,
        # but this is the safety net actually relied on: even if a
        # future field is added carelessly, this class must never be
        # able to leak username/password through logging.exception(),
        # a debugger, or an unhandled traceback that stringifies a
        # local variable.
        return (
            f"AuthSessionConfig(login_url={self.login_url!r}, "
            f"username_field={self.username_field!r}, "
            f"password_field={self.password_field!r}, "
            f"extra_fields={self.extra_fields!r}, "
            f"method={self.method!r}, "
            f"cookie_name={self.cookie_name!r})"
        )

    __str__ = __repr__


def load_auth_session_config_from_env() -> AuthSessionConfig | None:
    """
    Build an AuthSessionConfig from environment variables, or None if
    the minimum required variables (login URL, username, password)
    are not all present.

    This is the only place credentials enter the system in this
    iteration: there is no per-scan or per-finding credential storage
    (see backend/storage/repository.py, which persists scans/
    findings/verified findings/ground truth only), and no frontend
    field for a password -- see the accompanying task report for why.
    python-dotenv (already a project dependency) can supply these
    from a local, gitignored .env file; nothing here reads or writes
    that file directly.
    """

    login_url = os.environ.get(_ENV_LOGIN_URL)
    username = os.environ.get(_ENV_USERNAME)
    password = os.environ.get(_ENV_PASSWORD)

    if not login_url or not username or not password:
        return None

    extra_fields = {
        key[len(_ENV_EXTRA_FIELD_PREFIX):]: value
        for key, value in os.environ.items()
        if key.startswith(_ENV_EXTRA_FIELD_PREFIX) and value
    }

    return AuthSessionConfig(
        login_url=login_url,
        username=username,
        password=password,
        username_field=(
            os.environ.get(_ENV_USERNAME_FIELD) or "username"
        ),
        password_field=(
            os.environ.get(_ENV_PASSWORD_FIELD) or "password"
        ),
        extra_fields=extra_fields,
        method=os.environ.get(_ENV_METHOD) or "POST",
        cookie_name=os.environ.get(_ENV_COOKIE_NAME) or None,
    )


def refresh_session(
    config: AuthSessionConfig,
    timeout_seconds: float = 10.0,
) -> str | None:
    """
    Perform one login request and return a Cookie header string built
    from whatever cookies the login response sets, or None if the
    login could not be completed (network failure, non-2xx/3xx
    response, or no cookie was set at all).

    Never raises: a login failure must never crash the verification
    it was trying to help -- the caller falls back to the original
    scanner-captured Cookie, and the existing staleness detection
    (backend/verification/csrf_context.py::_session_unavailable)
    still applies to that replay exactly as it did before this
    module existed.

    Never logs config.username/config.password -- see
    AuthSessionConfig.__repr__ above; only non-sensitive facts
    (the login URL and the resulting HTTP status) are logged.
    """

    form_data = {
        config.username_field: config.username,
        config.password_field: config.password,
        **config.extra_fields,
    }

    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=timeout_seconds,
        ) as client:
            response = client.request(
                method=config.method,
                url=config.login_url,
                data=form_data,
            )
    except httpx.RequestError as exc:
        logger.warning(
            "Session refresh failed: could not reach login_url=%s "
            "(%s)",
            config.login_url,
            type(exc).__name__,
        )
        return None

    if response.status_code >= 400:
        logger.warning(
            "Session refresh failed: login_url=%s returned status=%s",
            config.login_url,
            response.status_code,
        )
        return None

    cookies = {
        name: value
        for name, value in response.cookies.items()
    }

    if config.cookie_name is not None:
        cookies = {
            name: value
            for name, value in cookies.items()
            if name == config.cookie_name
        }

    if not cookies:
        logger.warning(
            "Session refresh failed: login_url=%s did not set any "
            "cookie",
            config.login_url,
        )
        return None

    logger.info(
        "Session refresh succeeded: login_url=%s status=%s "
        "cookie_count=%d",
        config.login_url,
        response.status_code,
        len(cookies),
    )

    return "; ".join(
        f"{name}={value}" for name, value in cookies.items()
    )


def finding_requires_authentication(
    finding: NormalizedFinding,
) -> bool:
    """
    True when the finding's own normalized context says an
    authenticated/session-bound state is required to exercise it --
    the exact same signal backend/verification/csrf_context.py
    already uses for authenticated_or_privileged_context_required and
    forged_request_is_plausible_under_threat_model. Session refresh is
    only ever attempted for findings that already declare this need;
    it is never applied to a finding whose context doesn't call for
    it.
    """

    return (
        finding.context.authentication_required == "YES"
        or finding.context.session_required == "YES"
    )


def resolve_session_cookie_override(
    finding: NormalizedFinding,
    *,
    config: AuthSessionConfig | None = None,
    timeout_seconds: float = 10.0,
) -> str | None:
    """
    The single entry point the verification orchestration layer
    (backend/api/findings.py, backend/services/
    auto_verification_service.py) calls: returns a fresh Cookie header
    string to use for this finding's replay(s), or None when no
    refresh should happen -- either because the finding doesn't
    declare an authentication/session requirement, no
    AuthSessionConfig is available (see
    load_auth_session_config_from_env), or the login attempt itself
    failed.

    None is a completely normal, expected result, not an error: the
    caller's existing replay path (build_replay_request with no
    override) and existing staleness detection remain exactly as they
    were before session refresh existed.
    """

    if not finding_requires_authentication(finding):
        return None

    resolved_config = (
        config
        if config is not None
        else load_auth_session_config_from_env()
    )

    if resolved_config is None:
        return None

    return refresh_session(
        resolved_config,
        timeout_seconds=timeout_seconds,
    )
