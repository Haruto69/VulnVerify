"""
End-to-end reachability tests for ERROR_BASED SQLi verification
through POST /scans/{scan_id}/findings/{finding_id}/verify.

Mirrors tests/test_sqli_verification_endpoint.py's conventions
exactly (same TestClient(app), same storage-clearing setup_scan()
pattern, same monkeypatch-at-the-call-site style) but exercises the
new trigger.sqli.error_based dispatch branch.

The reference fixture mirrors the real DVWA/ZAP finding described in
the project audit: category=SQLI, scanner=ZAP, cwe=CWE-89,
parameter=id (QUERY), payload="'", evidence="You have an error in
your SQL syntax".
"""

from datetime import datetime, timezone
from urllib.parse import quote

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
from backend.replay.sqli_error_based_collector import (
    SqliErrorBasedReplayEvidence,
)
from backend.services.pipeline_service import (
    verify_error_based_sqli_finding,
)
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)
from backend.verification.sqli_response import (
    ResponseObservation,
)


client = TestClient(app)

MYSQL_ERROR_BODY = (
    "Fatal error ... mysqli_sql_exception: You have an error in "
    "your SQL syntax; check the manual..."
)
CLEAN_BODY = "<html><body>ID: 1<br>First name: admin</body></html>"


def make_sqli_finding(
    finding_id: str = "sqli-error-001",
) -> NormalizedFinding:
    quoted_payload = quote("'", safe="")

    url = (
        "http://127.0.0.1/DVWA/vulnerabilities/sqli/"
        f"?id={quoted_payload}&Submit=Submit"
    )

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
            subtype=None,
            raw_severity="High (Medium)",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-89",
        ),
        target=TargetInfo(
            url=url,
            normalized_url=(
                "http://127.0.0.1/DVWA/vulnerabilities/sqli/"
            ),
            host="127.0.0.1",
            path="/DVWA/vulnerabilities/sqli/",
            parameter="id",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="'",
            evidence=(
                "You have an error in your SQL syntax"
            ),
        ),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/DVWA/vulnerabilities/sqli/",
        ),
    )


def make_csrf_finding(
    finding_id: str = "csrf-error-endpoint-001",
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
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-352",
        ),
        target=TargetInfo(
            url="http://example.test/change",
            normalized_url="http://example.test/change",
            host="example.test",
            path="/change",
            parameter=None,
            parameter_location=ParameterLocation.UNKNOWN,
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


def setup_scan_with_sqli_finding():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    scans["scan-001"] = {
        "scan_id": "scan-001",
        "filename": "zap_dvwa.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    normalized_findings["scan-001"] = [
        make_sqli_finding()
    ]


def verify_url(finding_id: str) -> str:
    return (
        f"/api/v1/scans/scan-001/findings/{finding_id}/verify"
    )


ERROR_BASED_TRIGGER = {
    "sqli": {
        "error_based": {},
    }
}


def make_replay_result(
    body: str,
    status: int = 200,
) -> ReplayResult:
    return ReplayResult(
        finding_id="sqli-error-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url=(
                    "http://127.0.0.1/DVWA/vulnerabilities/sqli/"
                ),
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={},
                body=body,
            ),
        ),
        observations=[],
        errors=[],
    )


def make_failed_replay_result() -> ReplayResult:
    return ReplayResult(
        finding_id="sqli-error-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url=(
                    "http://127.0.0.1/DVWA/vulnerabilities/sqli/"
                ),
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=None,
                headers={},
                body=None,
            ),
        ),
        observations=[],
        errors=["ConnectError: connection refused"],
    )


def true_positive_evidence() -> SqliErrorBasedReplayEvidence:
    request = ReplayRequest(
        method="GET",
        url="http://127.0.0.1/DVWA/vulnerabilities/sqli/",
        headers={},
        body=None,
    )

    return SqliErrorBasedReplayEvidence(
        baseline_request=request,
        verification_request=request,
        baseline_replays=(
            make_replay_result(CLEAN_BODY),
            make_replay_result(CLEAN_BODY),
            make_replay_result(CLEAN_BODY),
        ),
        verification_replays=(
            make_replay_result(MYSQL_ERROR_BODY),
            make_replay_result(MYSQL_ERROR_BODY),
            make_replay_result(MYSQL_ERROR_BODY),
        ),
    )


# ---------------------------------------------------------------------
# Trigger schema: subtype selection / validation
# ---------------------------------------------------------------------


def test_valid_error_based_trigger_is_accepted(monkeypatch):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        lambda **kwargs: true_positive_evidence(),
    )

    response = client.post(
        verify_url("sqli-error-001"),
        json=ERROR_BASED_TRIGGER,
    )

    assert response.status_code == 200
    assert (
        response.json()["classification"]["status"]
        == "TRUE_POSITIVE"
    )


def test_existing_time_based_trigger_still_works(monkeypatch):
    setup_scan_with_sqli_finding()

    def undelayed_evidence(**kwargs):
        from backend.replay.sqli_time_based_collector import (
            SqliTimeBasedReplayEvidence,
        )
        from backend.verification.sqli_timing import (
            TimedReplay,
            TimingSample,
        )

        def sample(number, ms):
            replay_result = make_replay_result(CLEAN_BODY)
            return TimedReplay(
                sample=TimingSample(
                    request_number=number,
                    timestamp=replay_result.replay.timestamp,
                    status=200,
                    response_time_ms=ms,
                    response_length=len(CLEAN_BODY),
                    body_fingerprint="fp",
                    headers={},
                    errors=(),
                ),
                replay_result=replay_result,
            )

        baseline = tuple(
            sample(i, 100.0) for i in range(1, 6)
        )
        verification = tuple(
            sample(i, 105.0) for i in range(1, 4)
        )

        return SqliTimeBasedReplayEvidence(
            baseline_request=ReplayRequest(
                method="GET",
                url="http://127.0.0.1/DVWA/vulnerabilities/sqli/",
                headers={},
                body=None,
            ),
            verification_request=ReplayRequest(
                method="GET",
                url="http://127.0.0.1/DVWA/vulnerabilities/sqli/",
                headers={},
                body=None,
            ),
            baseline_attempts=baseline,
            verification_attempts=verification,
            valid_verification_trials=verification,
        )

    monkeypatch.setattr(
        "backend.api.findings.collect_time_based_replay_evidence",
        undelayed_evidence,
    )

    response = client.post(
        verify_url("sqli-error-001"),
        json={
            "sqli": {
                "time_based": {
                    "baseline_parameter_value": "1"
                }
            }
        },
    )

    assert response.status_code == 200
    assert (
        response.json()["verification_method"]
        == "sqli_time_based_rule_v1"
    )


def test_missing_sqli_subtype_is_rejected():
    setup_scan_with_sqli_finding()

    response = client.post(
        verify_url("sqli-error-001"),
        json={"sqli": {}},
    )

    assert response.status_code == 422


def test_both_sqli_subtypes_is_rejected():
    setup_scan_with_sqli_finding()

    response = client.post(
        verify_url("sqli-error-001"),
        json={
            "sqli": {
                "time_based": {
                    "baseline_parameter_value": "1"
                },
                "error_based": {},
            }
        },
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------
# ERROR_BASED classification via the real endpoint
# ---------------------------------------------------------------------


def test_error_based_true_positive_with_mysql_signature(
    monkeypatch,
):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        lambda **kwargs: true_positive_evidence(),
    )

    response = client.post(
        verify_url("sqli-error-001"),
        json=ERROR_BASED_TRIGGER,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["classification"]["status"] == "TRUE_POSITIVE"
    assert data["verification_method"] == "sqli_error_based_rule_v1"
    assert (
        "database_error_absent_from_baseline"
        in data["evidence"]["indicators"]
    )


def test_error_based_inconclusive_on_replay_failure(monkeypatch):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.replay.sqli_error_based_collector.execute_replay",
        lambda **kwargs: make_failed_replay_result(),
    )

    response = client.post(
        verify_url("sqli-error-001"),
        json=ERROR_BASED_TRIGGER,
    )

    assert response.status_code == 200
    assert (
        response.json()["classification"]["status"]
        == "INCONCLUSIVE"
    )


def test_error_based_rejects_non_sqli_finding():
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

    response = client.post(
        verify_url("csrf-error-endpoint-001"),
        json=ERROR_BASED_TRIGGER,
    )

    assert response.status_code == 400


def test_unknown_finding_returns_404_for_error_based_trigger():
    setup_scan_with_sqli_finding()

    response = client.post(
        "/api/v1/scans/scan-001/findings/missing/verify",
        json=ERROR_BASED_TRIGGER,
    )

    assert response.status_code == 404


# ---------------------------------------------------------------------
# Persistence and downstream eligibility (risk-priorities)
# ---------------------------------------------------------------------


def test_verified_error_based_finding_is_persisted(monkeypatch):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        lambda **kwargs: true_positive_evidence(),
    )

    client.post(
        verify_url("sqli-error-001"),
        json=ERROR_BASED_TRIGGER,
    )

    assert "sqli-error-001" in verified_findings["scan-001"]

    listed = client.get(
        "/api/v1/scans/scan-001/verified-findings"
    ).json()

    assert listed["count"] == 1
    assert (
        listed["findings"][0]["classification"]["status"]
        == "TRUE_POSITIVE"
    )


def test_verified_error_based_finding_reaches_risk_priorities(
    monkeypatch,
):
    setup_scan_with_sqli_finding()

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        lambda **kwargs: true_positive_evidence(),
    )

    client.post(
        verify_url("sqli-error-001"),
        json=ERROR_BASED_TRIGGER,
    )

    risk = client.get(
        "/api/v1/scans/scan-001/risk-priorities"
    ).json()

    assert risk["count"] == 1

    priority = risk["priorities"][0]

    assert priority["finding_id"] == "sqli-error-001"
    assert priority["verification_status"] == "TRUE_POSITIVE"
    assert priority["scanner_severity"] == "HIGH"
    # TRUE_POSITIVE priority follows scanner severity directly
    # (existing, unmodified Risk/Priority V1 rule).
    assert priority["priority"] == "HIGH"
