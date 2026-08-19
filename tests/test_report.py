import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.ground_truth import GroundTruthLabel
from backend.models.normalized_finding import NormalizedFinding
from backend.models.verified_finding import VerifiedFinding
from backend.services.ground_truth_service import (
    save_ground_truth_labels,
)
from backend.services.report_service import build_scan_report
from backend.storage.repository import (
    ground_truth,
    normalized_findings,
    scans,
    verified_findings,
)


client = TestClient(app)


def make_normalized(
    finding_id: str,
    scan_id: str = "scan-report-001",
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
) -> VerifiedFinding:
    return VerifiedFinding(
        finding_id=finding_id,
        classification={
            "status": status,
            "confidence": 0.9,
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
    scan_id: str = "scan-report-001",
    normalized: list[NormalizedFinding] | None = None,
    verified: list[VerifiedFinding] | None = None,
):
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()
    ground_truth.clear()

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


def test_build_report_raises_for_unknown_scan():
    scans.clear()

    with pytest.raises(ValueError):
        build_scan_report("missing-scan")


def test_report_counts_and_findings_shape():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-tp"),
            make_normalized(finding_id="f-unverified"),
        ],
        verified=[
            make_verified(
                finding_id="f-tp", status="TRUE_POSITIVE"
            ),
        ],
    )

    report = build_scan_report("scan-report-001")

    assert report.scan_id == "scan-report-001"
    assert report.filename == "test.json"
    assert report.scanner == "ZAP"
    assert report.raw_finding_count == 2
    assert report.verified_count == 1
    assert report.true_positive_count == 1
    assert report.false_positive_count == 0
    assert report.unverified_count == 1
    assert len(report.findings) == 2

    by_id = {f.finding_id: f for f in report.findings}

    assert by_id["f-tp"].verification_status == "TRUE_POSITIVE"
    assert by_id["f-tp"].priority is not None

    assert by_id["f-unverified"].verification_status is None
    assert by_id["f-unverified"].priority is None


def test_report_includes_evaluation_metrics():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[
            make_verified(finding_id="f-a", status="TRUE_POSITIVE")
        ],
    )

    save_ground_truth_labels(
        "scan-report-001",
        [
            GroundTruthLabel(
                finding_id="f-a",
                expected_status="TRUE_POSITIVE",
            )
        ],
    )

    report = build_scan_report("scan-report-001")

    assert report.evaluation.ground_truth_count == 1
    assert report.evaluation.true_positive == 1
    assert report.evaluation.precision == 1.0


def test_report_endpoint_unknown_scan_returns_404():
    scans.clear()

    response = client.get("/api/v1/scans/missing/report")

    assert response.status_code == 404


def test_report_endpoint_returns_full_shape():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[
            make_verified(finding_id="f-a", status="TRUE_POSITIVE")
        ],
    )

    response = client.get(
        "/api/v1/scans/scan-report-001/report"
    )

    assert response.status_code == 200
    body = response.json()

    assert body["scan_id"] == "scan-report-001"
    assert body["raw_finding_count"] == 1
    assert body["true_positive_count"] == 1
    assert body["findings"][0]["finding_id"] == "f-a"
    assert "evaluation" in body
    assert body["evaluation"]["ground_truth_count"] == 0
