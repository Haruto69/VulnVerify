from datetime import datetime, timezone

from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.verification.csrf import (
    CsrfVerificationContext,
    verify_csrf,
)


def make_csrf_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-csrf-001",
        finding_id="csrf-finding-001",

        source={
            "scanner": "ZAP",
            "scanner_finding_id": "40103",
            "original_name": "Cross Site Request Forgery",
        },

        vulnerability={
            "category": "CSRF",
            "subtype": None,
            "raw_severity": "Medium",
            "normalized_severity": "MEDIUM",
            "raw_confidence": "Medium",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-352",
        },

        target={
            "url": "http://example.test/change-email",
            "normalized_url": (
                "http://example.test/change-email"
            ),
            "host": "example.test",
            "path": "/change-email",
            "parameter": "email",
            "parameter_location": "FORM",
        },

        original_test={
            "payload": "new@example.test",
            "evidence": None,
        },

        request={
            "method": "POST",
            "url": "http://example.test/change-email",
            "path": "/change-email",
            "query_parameters": {},
            "headers": {
                "content-type": (
                    "application/x-www-form-urlencoded"
                )
            },
            "cookies": {},
            "body": "email=new@example.test",
            "content_type": (
                "application/x-www-form-urlencoded"
            ),
            "raw": None,
        },

        response=None,

        context={
            "authentication_required": "YES",
            "session_required": "YES",
        },

        references=[],
        metadata={},
    )


def make_replay_result(
    status: int | None = 200,
) -> ReplayResult:

    return ReplayResult(
        finding_id="csrf-finding-001",

        replay={
            "executed": True,
            "timestamp": datetime.now(timezone.utc),

            "request": {
                "method": "POST",
                "url": "http://example.test/change-email",
                "headers": {},
                "body": "email=new@example.test",
            },

            "response": {
                "status": status,
                "headers": {},
                "body": (
                    "Email changed"
                    if status is not None
                    else None
                ),
            },
        },

        observations=[],
        errors=[],
    )


def test_csrf_true_positive():
    finding = make_csrf_finding()
    replay = make_replay_result()

    context = CsrfVerificationContext(
        state_changing_endpoint=True,
        authenticated_or_privileged_context_required=True,
        forged_request_is_plausible_under_threat_model=True,
        effective_csrf_defense_absent_or_bypassable=True,
        request_accepted=True,
        controlled_state_change_observed=True,
        reproducible=True,
        evidence_saved=True,
        verification_confidence=0.95,
    )

    result = verify_csrf(
        finding=finding,
        replay_result=replay,
        context=context,
    )

    assert (
        result.classification.status
        == "TRUE_POSITIVE"
    )

    assert (
        result.classification.confidence
        == 0.95
    )

    assert (
        result.verification_method
        == "csrf_rule_v1"
    )


def test_csrf_false_positive_when_token_enforced():
    finding = make_csrf_finding()
    replay = make_replay_result(status=403)

    context = CsrfVerificationContext(
        state_changing_endpoint=True,
        required_csrf_token_or_custom_header_is_enforced=True,
        verification_confidence=0.95,
    )

    result = verify_csrf(
        finding=finding,
        replay_result=replay,
        context=context,
    )

    assert (
        result.classification.status
        == "FALSE_POSITIVE"
    )

    assert (
        "token or custom header is enforced"
        in result.classification.reason
    )


def test_csrf_false_positive_when_endpoint_not_state_changing():
    finding = make_csrf_finding()
    replay = make_replay_result()

    context = CsrfVerificationContext(
        state_changing_endpoint=False,
        verification_confidence=0.90,
    )

    result = verify_csrf(
        finding=finding,
        replay_result=replay,
        context=context,
    )

    assert (
        result.classification.status
        == "FALSE_POSITIVE"
    )


def test_csrf_inconclusive_when_session_unavailable():
    finding = make_csrf_finding()
    replay = make_replay_result(status=None)

    context = CsrfVerificationContext(
        authentication_or_session_unavailable=True,
        verification_confidence=0.30,
    )

    result = verify_csrf(
        finding=finding,
        replay_result=replay,
        context=context,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )

    assert (
        "Authentication or session"
        in result.classification.reason
    )

    assert (
        result.evidence.response_reference
        is None
    )


def test_csrf_inconclusive_when_browser_context_required():
    finding = make_csrf_finding()
    replay = make_replay_result()

    context = CsrfVerificationContext(
        browser_context_required_but_unavailable=True,
        verification_confidence=0.40,
    )

    result = verify_csrf(
        finding=finding,
        replay_result=replay,
        context=context,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )


def test_http_200_alone_does_not_create_true_positive():
    finding = make_csrf_finding()

    replay = make_replay_result(
        status=200
    )

    context = CsrfVerificationContext(
        verification_confidence=0.40,
    )

    result = verify_csrf(
        finding=finding,
        replay_result=replay,
        context=context,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )


def test_http_403_alone_does_not_create_false_positive():
    finding = make_csrf_finding()

    replay = make_replay_result(
        status=403
    )

    context = CsrfVerificationContext(
        verification_confidence=0.40,
    )

    result = verify_csrf(
        finding=finding,
        replay_result=replay,
        context=context,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )