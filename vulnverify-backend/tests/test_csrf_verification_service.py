from datetime import datetime, timezone

from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.services.csrf_verification_service import (
    finalize_csrf_verification,
)
from backend.verification.csrf_defense import (
    CsrfDefenseObservation,
)
from backend.verification.csrf_origin import (
    CsrfOriginObservation,
)
from backend.verification.csrf_state import (
    CsrfStateObservation,
)


def make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id="csrf-001",
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
            "url": "http://example.test/change",
            "normalized_url": "http://example.test/change",
            "host": "example.test",
            "path": "/change",
            "parameter": None,
            "parameter_location": "UNKNOWN",
        },
        original_test={
            "payload": None,
            "evidence": None,
        },
        request={
            "method": "POST",
            "url": "http://example.test/change",
            "path": "/change",
            "query_parameters": {},
            "headers": {},
            "cookies": {},
            "body": None,
            "content_type": None,
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


def make_replay(
    status: int | None = 200,
) -> ReplayResult:
    return ReplayResult(
        finding_id="csrf-001",
        replay={
            "executed": True,
            "timestamp": datetime.now(timezone.utc),
            "request": {
                "method": "POST",
                "url": "http://example.test/change",
                "headers": {},
                "body": None,
            },
            "response": {
                "status": status,
                "headers": {},
                "body": "ok",
            },
        },
        observations=[],
        errors=[],
    )


def test_service_returns_true_positive():
    result = finalize_csrf_verification(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=True,
        ),
        state_changing_endpoint=True,
        forged_request_is_plausible_under_threat_model=True,
        effective_csrf_defense_absent_or_bypassable=True,
        request_accepted=True,
        reproducible=True,
        evidence_saved=True,
        verification_confidence=0.95,
    )

    assert (
        result.classification.status
        == "TRUE_POSITIVE"
    )

    assert (
        result.classification.confidence
        == 0.95
    )


def test_service_returns_false_positive_for_token_enforcement():
    result = finalize_csrf_verification(
        finding=make_finding(),
        replay_result=make_replay(status=403),
        state_observation=CsrfStateObservation(),
        defense_observation=CsrfDefenseObservation(
            rejection_attributable_to_csrf_defense=True,
            defense_enforced=True,
        ),
        verification_confidence=0.95,
    )

    assert (
        result.classification.status
        == "FALSE_POSITIVE"
    )

    assert (
        "token or custom header is enforced"
        in result.classification.reason
    )


def test_service_returns_false_positive_for_origin_enforcement():
    result = finalize_csrf_verification(
        finding=make_finding(),
        replay_result=make_replay(status=403),
        state_observation=CsrfStateObservation(),
        origin_observation=CsrfOriginObservation(
            rejection_attributable_to_origin_policy=True,
            origin_or_referer_enforced=True,
        ),
        verification_confidence=0.95,
    )

    assert (
        result.classification.status
        == "FALSE_POSITIVE"
    )

    assert (
        "Origin or Referer"
        in result.classification.reason
    )


def test_service_returns_inconclusive_when_state_check_fails():
    result = finalize_csrf_verification(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(
            before_state_observed=False,
            after_state_observed=False,
            errors=[
                "state endpoint unavailable"
            ],
        ),
        verification_confidence=0.30,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )

    assert (
        "state change cannot be observed"
        in result.classification.reason.lower()
    )


def test_http_200_still_does_not_create_true_positive():
    result = finalize_csrf_verification(
        finding=make_finding(),
        replay_result=make_replay(status=200),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.40,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )
    