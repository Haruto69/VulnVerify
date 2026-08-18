from fastapi.testclient import TestClient

from backend.main import app
from backend.models.normalized_finding import NormalizedFinding
from backend.models.verified_finding import VerifiedFinding
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)


client = TestClient(app)


def make_normalized(
    finding_id: str,
    scan_id: str = "scan-risk-001",
    severity: str = "HIGH",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source={
            "scanner": "ZAP",
            "scanner_finding_id": "40018",
            "original_name": "SQL Injection - MySQL",
        },
        vulnerability={
            "category": "SQLI",
            "subtype": None,
            "raw_severity": "High",
            "normalized_severity": severity,
            "raw_confidence": "2",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-89",
        },
        target={
            "url": "http://example.test/item?id=1",
            "normalized_url": "http://example.test/item",
            "host": "example.test",
            "path": "/item",
            "parameter": "id",
            "parameter_location": "QUERY",
        },
        original_test={
            "payload": "'",
            "evidence": "SQL syntax error",
        },
        request={
            "method": "GET",
            "url": "http://example.test/item?id=1",
            "path": "/item",
            "query_parameters": {"id": ["1"]},
            "headers": {},
            "cookies": {},
            "body": None,
            "content_type": None,
            "raw": None,
        },
        response=None,
        context={
            "authentication_required": "UNKNOWN",
            "session_required": "UNKNOWN",
        },
        references=[],
        metadata={},
    )


def make_verified(
    finding_id: str,
    status: str = "TRUE_POSITIVE",
    confidence: float = 0.9,
) -> VerifiedFinding:
    return VerifiedFinding(
        finding_id=finding_id,
        classification={
            "status": status,
            "confidence": confidence,
            "reason": "test result",
        },
        evidence={
            "indicators": [],
            "request_reference": None,
            "response_reference": None,
        },
        verification_method="sqli_time_based_rule_v1",
    )


def setup_scan(
    scan_id: str = "scan-risk-001",
    normalized: list[NormalizedFinding] | None = None,
    verified: list[VerifiedFinding] | None = None,
):
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    scans[scan_id] = {
        "scan_id": scan_id,
        "filename": "test.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    normalized_findings[scan_id] = normalized or []

    if verified:
        verified_findings[scan_id] = {
            finding.finding_id: finding
            for finding in verified
        }


def test_unknown_scan_returns_404():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    response = client.get(
        "/api/v1/scans/missing/risk-priorities"
    )

    assert response.status_code == 404


def test_scan_with_no_verified_findings_returns_empty_priorities():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[],
    )

    response = client.get(
        "/api/v1/scans/scan-risk-001/risk-priorities"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == "scan-risk-001"
    assert data["count"] == 0
    assert data["priorities"] == []


def test_successful_response_shape():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a", severity="HIGH"),
        ],
        verified=[
            make_verified(
                finding_id="f-a",
                status="TRUE_POSITIVE",
            ),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-risk-001/risk-priorities"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == "scan-risk-001"
    assert data["count"] == 1
    assert len(data["priorities"]) == 1

    priority = data["priorities"][0]

    assert priority["finding_id"] == "f-a"
    assert priority["scan_id"] == "scan-risk-001"
    assert priority["priority"] == "HIGH"
    assert priority["verification_status"] == "TRUE_POSITIVE"
    assert priority["scanner_severity"] == "HIGH"


def test_normalized_only_findings_are_excluded():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a"),
            make_normalized(finding_id="f-unverified"),
        ],
        verified=[
            make_verified(finding_id="f-a"),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-risk-001/risk-priorities"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1

    finding_ids = {
        item["finding_id"]
        for item in data["priorities"]
    }

    assert finding_ids == {"f-a"}
    assert "f-unverified" not in finding_ids


def test_false_positive_with_critical_severity_maps_to_informational():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-a", severity="CRITICAL"
            ),
        ],
        verified=[
            make_verified(
                finding_id="f-a", status="FALSE_POSITIVE"
            ),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-risk-001/risk-priorities"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["priorities"][0]["priority"] == "INFORMATIONAL"


def test_inconclusive_high_severity_is_capped_at_medium():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a", severity="HIGH"),
        ],
        verified=[
            make_verified(
                finding_id="f-a", status="INCONCLUSIVE"
            ),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-risk-001/risk-priorities"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["priorities"][0]["priority"] == "MEDIUM"


def test_confidence_does_not_affect_priority_through_the_api():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a", severity="HIGH"),
            make_normalized(finding_id="f-b", severity="HIGH"),
        ],
        verified=[
            make_verified(
                finding_id="f-a",
                status="TRUE_POSITIVE",
                confidence=0.99,
            ),
            make_verified(
                finding_id="f-b",
                status="TRUE_POSITIVE",
                confidence=0.0,
            ),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-risk-001/risk-priorities"
    )

    assert response.status_code == 200

    data = response.json()

    priorities_by_id = {
        item["finding_id"]: item["priority"]
        for item in data["priorities"]
    }

    assert (
        priorities_by_id["f-a"]
        == priorities_by_id["f-b"]
        == "HIGH"
    )
