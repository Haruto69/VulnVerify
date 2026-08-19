from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.normalized_finding import (
    NormalizedFinding,
)
from backend.models.replay_result import (
    ReplayResult,
)
from backend.replay.csrf import (
    CsrfDefenseLocation,
    CsrfTokenReplayResult,
)
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)


client = TestClient(
    app
)


def make_finding(
    finding_id: str = "csrf-001",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id=finding_id,
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
            "url": (
                "http://example.test/change"
            ),
            "normalized_url": (
                "http://example.test/change"
            ),
            "host": "example.test",
            "path": "/change",
            "parameter": "csrf_token",
            "parameter_location": "FORM",
        },
        original_test={
            "payload": None,
            "evidence": None,
        },
        request={
            "method": "POST",
            "url": (
                "http://example.test/change"
            ),
            "path": "/change",
            "query_parameters": {},
            "headers": {
                "Cookie": "session=abc123",
            },
            "cookies": {
                "session": "abc123",
            },
            "body": (
                "csrf_token=abc"
                "&email=new@example.test"
            ),
            "content_type": (
                "application/"
                "x-www-form-urlencoded"
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


def make_replay(
    status: int,
    body: str | None = None,
) -> ReplayResult:
    return ReplayResult(
        finding_id="csrf-001",
        replay={
            "executed": True,
            "timestamp": datetime.now(
                timezone.utc
            ),
            "request": {
                "method": "POST",
                "url": (
                    "http://example.test/change"
                ),
                "headers": {},
                "body": None,
            },
            "response": {
                "status": status,
                "headers": {},
                "body": body,
            },
        },
        observations=[],
        errors=[],
    )


def setup_scan():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    scans["scan-001"] = {
        "scan_id": "scan-001",
        "filename": "test.json",
        "content_type": (
            "application/json"
        ),
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    normalized_findings[
        "scan-001"
    ] = [
        make_finding()
    ]


def test_verify_endpoint_returns_404_for_unknown_scan():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    response = client.post(
        (
            "/api/v1/scans/"
            "missing/findings/"
            "csrf-001/verify"
        ),
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": (
                        "changed"
                    )
                }
            }
        },
    )

    assert response.status_code == 404


def test_verify_endpoint_returns_404_for_unknown_finding():
    setup_scan()

    response = client.post(
        (
            "/api/v1/scans/"
            "scan-001/findings/"
            "missing/verify"
        ),
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": (
                        "changed"
                    )
                }
            }
        },
    )

    assert response.status_code == 404


def test_verify_endpoint_returns_inconclusive_for_indicator_only(
    monkeypatch,
):
    setup_scan()

    def fake_replay_finding(
        finding,
        timeout_seconds,
        session_cookie_override=None,
    ):
        return make_replay(
            status=200,
            body="Password Changed.",
        )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        fake_replay_finding,
    )

    response = client.post(
        (
            "/api/v1/scans/"
            "scan-001/findings/"
            "csrf-001/verify"
        ),
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": (
                        "Password Changed."
                    )
                }
            }
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["classification"]["status"]
        == "INCONCLUSIVE"
    )

    assert (
        data["classification"]["confidence"]
        == 0.85
    )

    assert (
        "csrf-001"
        in verified_findings["scan-001"]
    )


def test_verify_endpoint_detects_enforced_csrf_token(
    monkeypatch,
):
    setup_scan()

    baseline = make_replay(
        status=200,
        body="ok",
    )

    rejected = make_replay(
        status=403,
        body="CSRF validation failed",
    )

    def fake_replay_finding(
        finding,
        timeout_seconds,
        session_cookie_override=None,
    ):
        return baseline

    def fake_defense_replay(
        finding_id,
        request,
        defense_name,
        defense_location,
        timeout_seconds,
    ):
        return CsrfTokenReplayResult(
            original_replay=baseline,
            modified_replay=rejected,
            defense_location=(
                CsrfDefenseLocation.BODY
            ),
            defense_name="csrf_token",
            defense_removed=True,
            rejection_observed=True,
            rejection_status=403,
        )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        fake_replay_finding,
    )

    monkeypatch.setattr(
        (
            "backend.api.findings."
            "replay_without_csrf_defense"
        ),
        fake_defense_replay,
    )

    response = client.post(
        (
            "/api/v1/scans/"
            "scan-001/findings/"
            "csrf-001/verify"
        ),
        json={
            "csrf": {
                "defense_test": {
                    "name": "csrf_token",
                    "location": "BODY",
                }
            }
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["classification"]["status"]
        == "FALSE_POSITIVE"
    )

    assert (
        data["classification"]["confidence"]
        == 0.97
    )


def test_verify_endpoint_rejects_empty_config():
    setup_scan()

    response = client.post(
        (
            "/api/v1/scans/"
            "scan-001/findings/"
            "csrf-001/verify"
        ),
        json={
            "csrf": {}
        },
    )

    assert response.status_code == 422