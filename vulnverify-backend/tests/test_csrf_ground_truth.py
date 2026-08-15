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


def make_finding(
    finding_id: str,
    *,
    auth_required: str = "YES",
    session_required: str = "YES",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-ground-truth",
        finding_id=finding_id,
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
            "authentication_required": auth_required,
            "session_required": session_required,
        },
        references=[],
        metadata={},
    )


def make_replay(
    finding_id: str,
    *,
    status: int | None = 200,
    errors: list[str] | None = None,
) -> ReplayResult:
    return ReplayResult(
        finding_id=finding_id,
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
                "body": None,
            },
        },
        observations=[],
        errors=errors or [],
    )


def test_csrf_001_intentionally_vulnerable_state_change():
    finding = make_finding("CSRF-001")

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay("CSRF-001"),
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


def test_csrf_002_token_protected_state_change():
    finding = make_finding("CSRF-002")

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay(
            "CSRF-002",
            status=403,
        ),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=False,
        ),
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


def test_csrf_003_origin_referer_protected():
    finding = make_finding("CSRF-003")

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay(
            "CSRF-003",
            status=403,
        ),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=False,
        ),
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


def test_csrf_004_non_state_changing_endpoint():
    finding = make_finding("CSRF-004")

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay("CSRF-004"),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=False,
        ),
        state_changing_endpoint=False,
        verification_confidence=0.90,
    )

    assert (
        result.classification.status
        == "FALSE_POSITIVE"
    )


def test_csrf_005_session_required_but_unavailable():
    finding = make_finding(
        "CSRF-005",
        auth_required="YES",
        session_required="YES",
    )

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay(
            "CSRF-005",
            status=401,
        ),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.20,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )


def test_csrf_006_samesite_requires_browser_context():
    finding = make_finding("CSRF-006")

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay("CSRF-006"),
        state_observation=CsrfStateObservation(),
        browser_observation=None,
        browser_context_required=True,
        verification_confidence=0.30,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )


def test_csrf_007_ambiguous_server_error():
    finding = make_finding("CSRF-007")

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay(
            "CSRF-007",
            status=500,
        ),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.30,
    )

    assert (
        result.classification.status
        == "INCONCLUSIVE"
    )


def test_csrf_008_required_custom_header():
    finding = make_finding("CSRF-008")

    result = finalize_csrf_verification(
        finding=finding,
        replay_result=make_replay(
            "CSRF-008",
            status=403,
        ),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=False,
        ),
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