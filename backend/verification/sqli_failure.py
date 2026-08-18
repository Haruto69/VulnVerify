from dataclasses import dataclass
from enum import Enum


class SqliFailureReason(str, Enum):
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    FORBIDDEN = "FORBIDDEN"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    CSRF_OR_SESSION_REJECTED = "CSRF_OR_SESSION_REJECTED"
    RATE_LIMITED = "RATE_LIMITED"
    WAF_BLOCKED = "WAF_BLOCKED"
    LOGIN_REDIRECT = "LOGIN_REDIRECT"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    DNS_FAILURE = "DNS_FAILURE"
    CONNECTION_FAILURE = "CONNECTION_FAILURE"


@dataclass(frozen=True)
class SqliFailureContext:
    status_code: int | None = None

    authentication_missing: bool = False
    session_expired: bool = False
    waf_blocked: bool = False
    login_redirected: bool = False

    target_unreachable: bool = False
    dns_failure: bool = False
    connection_failure: bool = False


@dataclass(frozen=True)
class SqliFailureEvaluation:
    inconclusive: bool
    reasons: tuple[SqliFailureReason, ...]


def evaluate_sqli_failure(
    context: SqliFailureContext,
) -> SqliFailureEvaluation:
    reasons: list[SqliFailureReason] = []

    if context.status_code == 401:
        reasons.append(
            SqliFailureReason.AUTHENTICATION_REQUIRED
        )

    if context.status_code == 403:
        reasons.append(
            SqliFailureReason.FORBIDDEN
        )

    if context.status_code == 419:
        reasons.append(
            SqliFailureReason.CSRF_OR_SESSION_REJECTED
        )

    if context.status_code == 429:
        reasons.append(
            SqliFailureReason.RATE_LIMITED
        )

    if context.authentication_missing:
        if (
            SqliFailureReason.AUTHENTICATION_REQUIRED
            not in reasons
        ):
            reasons.append(
                SqliFailureReason.AUTHENTICATION_REQUIRED
            )

    if context.session_expired:
        reasons.append(
            SqliFailureReason.SESSION_EXPIRED
        )

    if context.waf_blocked:
        reasons.append(
            SqliFailureReason.WAF_BLOCKED
        )

    if context.login_redirected:
        reasons.append(
            SqliFailureReason.LOGIN_REDIRECT
        )

    if context.target_unreachable:
        reasons.append(
            SqliFailureReason.TARGET_UNREACHABLE
        )

    if context.dns_failure:
        reasons.append(
            SqliFailureReason.DNS_FAILURE
        )

    if context.connection_failure:
        reasons.append(
            SqliFailureReason.CONNECTION_FAILURE
        )

    return SqliFailureEvaluation(
        inconclusive=bool(reasons),
        reasons=tuple(reasons),
    )