from datetime import datetime, timezone

from backend.models.normalized_finding import (
    NormalizedFinding,
)
from backend.models.replay_result import ReplayResult
from backend.services.pipeline_service import (
    verify_csrf_finding,
)
from backend.services.scan_service import (
    get_verified_finding,
)
from backend.storage.repository import (
    verified_findings,
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
            "original_name": (
                "Cross Site Request Forgery"
            ),
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
            "normalized_url": (
                "http://example.test/change"
            ),
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


def make_replay() -> ReplayResult:
    return ReplayResult(
        finding_id="csrf-001",
        replay={
            "executed": True,
            "timestamp": datetime.now(
                timezone.utc
            ),
            "request": {
                "method": "POST",
                "url": "http://example.test/change",
                "headers": {},
                "body": None,
            },
            "response": {
                "status": 200,
                "headers": {},
                "body": "changed",
            },
        },
        observations=[],
        errors=[],
    )


def test_csrf_pipeline_verifies_and_stores_result():
    verified_findings.clear()

    result = verify_csrf_finding(
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

    stored = get_verified_finding(
        scan_id="scan-001",
        finding_id="csrf-001",
    )

    assert stored is not None

    assert (
        stored.classification.status
        == "TRUE_POSITIVE"
    )