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
    scan_id: str = "scan-dedup-001",
    category: str = "SQLI",
    normalized_url: str = "http://example.test/item",
    parameter: str | None = "id",
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
            "category": category,
            "subtype": None,
            "raw_severity": "High",
            "normalized_severity": "HIGH",
            "raw_confidence": "2",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-89",
        },
        target={
            "url": f"{normalized_url}?id=1",
            "normalized_url": normalized_url,
            "host": "example.test",
            "path": "/item",
            "parameter": parameter,
            "parameter_location": "QUERY",
        },
        original_test={
            "payload": "'",
            "evidence": "SQL syntax error",
        },
        request={
            "method": "GET",
            "url": f"{normalized_url}?id=1",
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
    scan_id: str = "scan-dedup-001",
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
        "/api/v1/scans/missing/duplicate-groups"
    )

    assert response.status_code == 404


def test_scan_with_no_verified_findings_returns_empty_groups():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[],
    )

    response = client.get(
        "/api/v1/scans/scan-dedup-001/duplicate-groups"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == "scan-dedup-001"
    assert data["count"] == 0
    assert data["groups"] == []


def test_matching_findings_are_returned_as_one_group():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a"),
            make_normalized(finding_id="f-b"),
        ],
        verified=[
            make_verified(finding_id="f-a"),
            make_verified(finding_id="f-b"),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-dedup-001/duplicate-groups"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert len(data["groups"]) == 1

    group = data["groups"][0]

    assert group["scan_id"] == "scan-dedup-001"
    assert group["category"] == "SQLI"
    assert group["normalized_url"] == "http://example.test/item"
    assert group["parameter"] == "id"

    member_ids = {
        member["finding_id"]
        for member in group["members"]
    }

    assert member_ids == {"f-a", "f-b"}


def test_different_category_remains_separate():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a", category="SQLI"),
            make_normalized(finding_id="f-b", category="XSS"),
        ],
        verified=[
            make_verified(finding_id="f-a"),
            make_verified(finding_id="f-b"),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-dedup-001/duplicate-groups"
    )

    assert response.status_code == 200
    assert response.json()["count"] == 2


def test_different_normalized_url_remains_separate():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-a",
                normalized_url="http://example.test/first",
            ),
            make_normalized(
                finding_id="f-b",
                normalized_url="http://example.test/second",
            ),
        ],
        verified=[
            make_verified(finding_id="f-a"),
            make_verified(finding_id="f-b"),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-dedup-001/duplicate-groups"
    )

    assert response.status_code == 200
    assert response.json()["count"] == 2


def test_different_parameter_remains_separate():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a", parameter="id"),
            make_normalized(finding_id="f-b", parameter="name"),
        ],
        verified=[
            make_verified(finding_id="f-a"),
            make_verified(finding_id="f-b"),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-dedup-001/duplicate-groups"
    )

    assert response.status_code == 200
    assert response.json()["count"] == 2


def test_classification_status_and_confidence_are_preserved():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a"),
            make_normalized(finding_id="f-b"),
        ],
        verified=[
            make_verified(
                finding_id="f-a",
                status="TRUE_POSITIVE",
                confidence=0.9,
            ),
            make_verified(
                finding_id="f-b",
                status="INCONCLUSIVE",
                confidence=0.0,
            ),
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-dedup-001/duplicate-groups"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1

    members_by_id = {
        member["finding_id"]: member
        for member in data["groups"][0]["members"]
    }

    assert (
        members_by_id["f-a"]["classification"]["status"]
        == "TRUE_POSITIVE"
    )
    assert (
        members_by_id["f-a"]["classification"]["confidence"]
        == 0.9
    )

    assert (
        members_by_id["f-b"]["classification"]["status"]
        == "INCONCLUSIVE"
    )
    assert (
        members_by_id["f-b"]["classification"]["confidence"]
        == 0.0
    )


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
        "/api/v1/scans/scan-dedup-001/duplicate-groups"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1

    member_ids = {
        member["finding_id"]
        for member in data["groups"][0]["members"]
    }

    assert member_ids == {"f-a"}
    assert "f-unverified" not in member_ids
