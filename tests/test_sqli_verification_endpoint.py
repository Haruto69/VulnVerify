"""
Real end-to-end regression tests for TIME_BASED SQLi verification
reachability through POST /scans/{scan_id}/findings/{finding_id}/verify.

Mirrors the conventions in tests/test_verification_endpoint.py (same
TestClient(app), same storage-clearing setup_scan() pattern, same
monkeypatch-at-the-call-site style) but exercises the SQLi dispatch
branch added to backend/api/findings.py rather than the CSRF one.

Network replay itself (backend.replay.sqli_time_based_collector.
collect_time_based_replay_evidence) is monkeypatched at its call site
in backend.api.findings, exactly like replay_finding is monkeypatched
in the CSRF tests -- no real HTTP calls are made.
"""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.normalized_finding import (
    FindingSource,
    HttpRequest,
    NormalizedConfidence,
    NormalizedFinding,
    NormalizedSeverity,
    OriginalTest,
    ParameterLocation,
    TargetInfo,
    VulnerabilityCategory,
    VulnerabilityInfo,
)
from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.replay.sqli_time_based_collector import (
    SqliTimeBasedReplayEvidence,
)
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)
from backend.verification.sqli_timing import (
    TimedReplay,
    TimingSample,
)


client = TestClient(app)


def make_sqli_finding(
    finding_id: str = "sqli-time-001",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id=finding_id,
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.SQLI,
            subtype="TIME_BASED",
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-89",
        ),
        target=TargetInfo(
            url="http://test.local/item?id=1",
            normalized_url="http://test.local/item",
            host="test.local",
            path="/item",
            parameter="id",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="1' AND SLEEP(5)-- ",
            evidence="scanner-evidence",
        ),
        request=HttpRequest(
            method="GET",
            url="http://test.local/item?id=1",
            path="/item",
        ),
    )


def make_csrf_finding(
    finding_id: str = "csrf-endpoint-001",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id=finding_id,
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40103",
            original_name="Cross Site Request Forgery",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.CSRF,
            subtype=None,
            raw_severity="Medium",
            normalized_severity=NormalizedSeverity.MEDIUM,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.UNKNOWN,
            cwe="CWE-352",
        ),
        target=TargetInfo(
            url="http://example.test/change",
            normalized_url="http://example.test/change",
            host="example.test",
            path="/change",
            parameter="csrf_token",
            parameter_location=ParameterLocation.FORM,
        ),
        original_test=OriginalTest(
            payload=None,
            evidence=None,
        ),
        request=HttpRequest(
            method="POST",
            url="http://example.test/change",
            path="/change",
        ),
    )


def timed_replay(
    *,
    number: int,
    response_time_ms: float,
    status: int | None = 200,
) -> TimedReplay:
    replay_result = ReplayResult(
        finding_id="sqli-time-001",
        replay=ReplayExecution(
            executed=status is not None,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://test.local/item?id=1",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={},
                body="ok",
            ),
        ),
        observations=[],
        errors=[],
    )

    sample = TimingSample(
        request_number=number,
        timestamp=replay_result.replay.timestamp,
        status=status,
        response_time_ms=response_time_ms,
        response_length=2,
        body_fingerprint="test",
        headers={},
        errors=(),
    )

    return TimedReplay(
        sample=sample,
        replay_result=replay_result,
    )


def stable_baseline_evidence(
    verification_attempts: tuple[TimedReplay, ...],
) -> SqliTimeBasedReplayEvidence:
    baseline_attempts = tuple(
        timed_replay(number=number, response_time_ms=100.0)
        for number in range(1, 6)
    )

    return SqliTimeBasedReplayEvidence(
        baseline_request=ReplayRequest(
            method="GET",
            url="http://test.local/item?id=1",
            headers={},
            body=None,
        ),
        verification_request=ReplayRequest(
            method="GET",
            url="http://test.local/item?id=1%27+AND+SLEEP%285%29--+",
            headers={},
            body=None,
        ),
        baseline_attempts=baseline_attempts,
        verification_attempts=verification_attempts,
        valid_verification_trials=verification_attempts,
    )


def delayed_verification_evidence() -> SqliTimeBasedReplayEvidence:
    return stable_baseline_evidence(
        verification_attempts=(
            timed_replay(number=1, response_time_ms=2500.0),
            timed_replay(number=2, response_time_ms=2600.0),
            timed_replay(number=3, response_time_ms=2700.0),
        )
    )


def undelayed_verification_evidence() -> SqliTimeBasedReplayEvidence:
    return stable_baseline_evidence(
        verification_attempts=(
            timed_replay(number=1, response_time_ms=110.0),
            timed_replay(number=2, response_time_ms=105.0),
            timed_replay(number=3, response_time_ms=115.0),
        )
    )


def failed_baseline_evidence() -> SqliTimeBasedReplayEvidence:
    """
    Every baseline attempt hits the failure contract (401), so the
    collector never establishes a stable baseline. This exercises the
    INCONCLUSIVE path without needing a real unreachable network call.
    """

    baseline_attempts = tuple(
        timed_replay(number=number, response_time_ms=100.0, status=401)
        for number in range(1, 6)
    )

    verification_attempts = (
        timed_replay(number=1, response_time_ms=2500.0),
        timed_replay(number=2, response_time_ms=2600.0),
        timed_replay(number=3, response_time_ms=2700.0),
    )

    return SqliTimeBasedReplayEvidence(
        baseline_request=ReplayRequest(
            method="GET",
            url="http://test.local/item?id=1",
            headers={},
            body=None,
        ),
        verification_request=ReplayRequest(
            method="GET",
            url="http://test.local/item?id=1%27+AND+SLEEP%285%29--+",
            headers={},
            body=None,
        ),
        baseline_attempts=baseline_attempts,
        verification_attempts=verification_attempts,
        valid_verification_trials=verification_attempts,
    )


def setup_scan_with_sqli_finding():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    scans["scan-001"] = {
        "scan_id": "scan-001",
        "filename": "test.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    normalized_findings["scan-001"] = [make_sqli_finding()]


def setup_scan_with_csrf_finding():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    scans["scan-001"] = {
        "scan_id": "scan-001",
        "filename": "test.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    normalized_findings["scan-001"] = [make_csrf_finding()]


def verify_url(finding_id: str) -> str:
    return f"/api/v1/scans/scan-001/findings/{finding_id}/verify"


SQLI_TRIGGER = {
    "sqli": {
        "time_based": {
            "baseline_parameter_value": "1",
        }
    }
}


# ---------------------------------------------------------------------
# Successful verification path
# ---------------------------------------------------------------------


def test_valid_time_based_trigger_reaches_true_positive(monkeypatch):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_time_based_replay_evidence",
        lambda **kwargs: delayed_verification_evidence(),
    )

    response = client.post(
        verify_url("sqli-time-001"),
        json=SQLI_TRIGGER,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["classification"]["status"] == "TRUE_POSITIVE"
    assert data["classification"]["confidence"] == 0.98
    assert data["verification_method"] == "sqli_time_based_rule_v1"


def test_verified_finding_is_persisted_and_retrievable(monkeypatch):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_time_based_replay_evidence",
        lambda **kwargs: delayed_verification_evidence(),
    )

    client.post(verify_url("sqli-time-001"), json=SQLI_TRIGGER)

    assert "sqli-time-001" in verified_findings["scan-001"]

    listed = client.get(
        "/api/v1/scans/scan-001/verified-findings"
    ).json()

    assert listed["count"] == 1
    assert (
        listed["findings"][0]["classification"]["status"]
        == "TRUE_POSITIVE"
    )


def test_baseline_parameter_value_reaches_the_collector(monkeypatch):
    setup_scan_with_sqli_finding()

    captured = {}

    def fake_collector(**kwargs):
        captured.update(kwargs)
        return delayed_verification_evidence()

    monkeypatch.setattr(
        "backend.api.findings.collect_time_based_replay_evidence",
        fake_collector,
    )

    client.post(
        verify_url("sqli-time-001"),
        json={
            "sqli": {
                "time_based": {
                    "baseline_parameter_value": "restored-value",
                }
            }
        },
    )

    assert (
        captured["baseline_parameter_value"] == "restored-value"
    )
    assert captured["finding"].finding_id == "sqli-time-001"


# ---------------------------------------------------------------------
# FALSE_POSITIVE / INCONCLUSIVE paths (no delay, and failure contract)
# ---------------------------------------------------------------------


def test_undelayed_verification_reaches_false_positive(monkeypatch):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_time_based_replay_evidence",
        lambda **kwargs: undelayed_verification_evidence(),
    )

    response = client.post(
        verify_url("sqli-time-001"),
        json=SQLI_TRIGGER,
    )

    assert response.status_code == 200
    assert (
        response.json()["classification"]["status"]
        == "FALSE_POSITIVE"
    )


def test_failed_baseline_reaches_inconclusive_not_a_crash(monkeypatch):
    """
    Regression pin for the fixed AttributeError defect: a fully failed
    baseline (context.baseline_statistics is None) must still return a
    clean 200 INCONCLUSIVE response, not a 500.
    """

    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_time_based_replay_evidence",
        lambda **kwargs: failed_baseline_evidence(),
    )

    response = client.post(
        verify_url("sqli-time-001"),
        json=SQLI_TRIGGER,
    )

    assert response.status_code == 200
    assert (
        response.json()["classification"]["status"]
        == "INCONCLUSIVE"
    )


# ---------------------------------------------------------------------
# Invalid / missing SQLi configuration
# ---------------------------------------------------------------------


def test_sqli_trigger_without_time_based_config_is_rejected():
    setup_scan_with_sqli_finding()

    response = client.post(
        verify_url("sqli-time-001"),
        json={"sqli": {}},
    )

    assert response.status_code == 422


def test_empty_trigger_is_rejected():
    setup_scan_with_sqli_finding()

    response = client.post(
        verify_url("sqli-time-001"),
        json={},
    )

    assert response.status_code == 422


def test_both_csrf_and_sqli_trigger_is_rejected():
    setup_scan_with_sqli_finding()

    response = client.post(
        verify_url("sqli-time-001"),
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": "ok"
                }
            },
            "sqli": {
                "time_based": {
                    "baseline_parameter_value": "1",
                }
            },
        },
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------
# Category / trigger-family mismatch (dispatch correctness)
# ---------------------------------------------------------------------


def test_sqli_trigger_against_csrf_finding_is_rejected():
    setup_scan_with_csrf_finding()

    response = client.post(
        verify_url("csrf-endpoint-001"),
        json=SQLI_TRIGGER,
    )

    assert response.status_code == 400
    assert (
        "SQLi TIME_BASED"
        in response.json()["detail"]
    )


def test_csrf_trigger_against_sqli_finding_is_rejected_unchanged():
    """
    Non-SQLi trigger behavior is unaffected by the new dispatch: a
    CSRF trigger against a non-CSRF finding still produces the exact
    original error message.
    """

    setup_scan_with_sqli_finding()

    response = client.post(
        verify_url("sqli-time-001"),
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": "ok"
                }
            }
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "This verification endpoint currently "
        "supports CSRF findings only."
    )


def test_unknown_scan_returns_404_for_sqli_trigger():
    setup_scan_with_sqli_finding()

    response = client.post(
        "/api/v1/scans/missing/findings/sqli-time-001/verify",
        json=SQLI_TRIGGER,
    )

    assert response.status_code == 404


def test_unknown_finding_returns_404_for_sqli_trigger():
    setup_scan_with_sqli_finding()

    response = client.post(
        verify_url("missing-finding"),
        json=SQLI_TRIGGER,
    )

    assert response.status_code == 404


# ---------------------------------------------------------------------
# CSRF verification still works after the SQLi dispatch was added
# ---------------------------------------------------------------------


def test_csrf_trigger_still_reaches_csrf_verification(monkeypatch):
    setup_scan_with_csrf_finding()

    def fake_replay_finding(finding, timeout_seconds):
        return ReplayResult(
            finding_id="csrf-endpoint-001",
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="POST",
                    url="http://example.test/change",
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=200,
                    headers={},
                    body="Password Changed.",
                ),
            ),
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        fake_replay_finding,
    )

    response = client.post(
        verify_url("csrf-endpoint-001"),
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
    assert (
        response.json()["classification"]["status"]
        == "INCONCLUSIVE"
    )
    assert "csrf-endpoint-001" in verified_findings["scan-001"]
