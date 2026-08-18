from datetime import datetime, timezone

from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.verification.csrf_browser import (
    CsrfBrowserObservation,
)
from backend.verification.csrf_context import (
    build_csrf_verification_context,
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
    auth_required: str = "YES",
    session_required: str = "YES",
) -> NormalizedFinding:
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
            "authentication_required": auth_required,
            "session_required": session_required,
        },
        references=[],
        metadata={},
    )


def make_replay(
    status: int | None = 200,
    errors: list[str] | None = None,
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
                "body": None,
            },
        },
        observations=[],
        errors=errors or [],
    )


def test_context_uses_observed_state_change():
    context = build_csrf_verification_context(
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
        context.controlled_state_change_observed
        is True
    )

    assert (
        context.authenticated_or_privileged_context_required
        is True
    )


def test_context_uses_deterministic_indicator():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(
            deterministic_acceptance_indicator="Password Changed.",
            deterministic_acceptance_indicator_matched=True,
        ),
        verification_confidence=0.80,
    )

    assert (
        context.strong_deterministic_acceptance_evidence
        is True
    )

    assert (
        context.controlled_state_change_observed
        is False
    )


def test_context_uses_token_defense_observation():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(status=403),
        state_observation=CsrfStateObservation(),
        defense_observation=CsrfDefenseObservation(
            rejection_attributable_to_csrf_defense=True,
            defense_enforced=True,
        ),
        verification_confidence=0.90,
    )

    assert (
        context.required_csrf_token_or_custom_header_is_enforced
        is True
    )


def test_context_uses_origin_policy_observation():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(status=403),
        state_observation=CsrfStateObservation(),
        origin_observation=CsrfOriginObservation(
            rejection_attributable_to_origin_policy=True,
            origin_or_referer_enforced=True,
        ),
        verification_confidence=0.90,
    )

    assert (
        context.cross_site_origin_or_referer_is_reliably_rejected
        is True
    )


def test_missing_defense_observations_default_to_false():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.40,
    )

    assert (
        context.required_csrf_token_or_custom_header_is_enforced
        is False
    )

    assert (
        context.cross_site_origin_or_referer_is_reliably_rejected
        is False
    )


def test_401_with_required_session_is_inconclusive_signal():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(
            status=401
        ),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.20,
    )

    assert (
        context.authentication_or_session_unavailable
        is True
    )


def test_transport_failure_marks_target_unavailable():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(
            status=None,
            errors=[
                "ConnectError: target unreachable"
            ],
        ),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.10,
    )

    assert (
        context.target_unavailable_or_unstable
        is True
    )


def test_500_is_ambiguous_server_error():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(
            status=500
        ),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.30,
    )

    assert (
        context.ambiguous_server_error
        is True
    )


def test_403_without_observation_does_not_prove_defense():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(
            status=403
        ),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.40,
    )

    assert (
        context.required_csrf_token_or_custom_header_is_enforced
        is False
    )

    assert (
        context.cross_site_origin_or_referer_is_reliably_rejected
        is False
    )


def test_unknown_state_without_error_is_not_forced_unobservable():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(),
        verification_confidence=0.40,
    )

    assert (
        context.state_change_not_observable
        is False
    )


def test_context_uses_browser_evidence_when_auth_not_sent():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(),
        browser_observation=CsrfBrowserObservation(
            browser_check_executed=True,
            authentication_sent=True,
            session_cookie_sent=False,
            cross_site_request_attempted=True,
            request_reached_target=True,
        ),
        browser_context_required=True,
        verification_confidence=0.90,
    )

    assert (
        context.browser_context_demonstrates_authentication_not_sent
        is True
    )

    assert (
        context.browser_context_required_but_unavailable
        is False
    )


def test_required_browser_context_missing_is_inconclusive_signal():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(),
        browser_observation=None,
        browser_context_required=True,
        verification_confidence=0.30,
    )

    assert (
        context.browser_context_required_but_unavailable
        is True
    )


def test_failed_required_browser_check_is_unavailable():
    context = build_csrf_verification_context(
        finding=make_finding(),
        replay_result=make_replay(),
        state_observation=CsrfStateObservation(),
        browser_observation=CsrfBrowserObservation(
            browser_check_executed=True,
            cross_site_request_attempted=True,
            request_reached_target=None,
            errors=[
                "browser launch failed"
            ],
        ),
        browser_context_required=True,
        verification_confidence=0.20,
    )

    assert (
        context.browser_context_required_but_unavailable
        is True
    )