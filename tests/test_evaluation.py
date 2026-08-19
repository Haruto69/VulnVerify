from fastapi.testclient import TestClient

from backend.main import app
from backend.models.ground_truth import GroundTruthLabel
from backend.models.normalized_finding import NormalizedFinding
from backend.models.verified_finding import VerifiedFinding
from backend.services.evaluation_service import (
    compute_evaluation_metrics,
)
from backend.services.ground_truth_service import (
    get_ground_truth_labels,
    load_demo_ground_truth,
    save_ground_truth_labels,
)
from backend.storage.repository import (
    ground_truth,
    normalized_findings,
    scans,
    verified_findings,
)


client = TestClient(app)


def make_normalized(
    finding_id: str,
    scan_id: str = "scan-eval-001",
    scanner: str = "ZAP",
    scanner_finding_id: str = "40018",
    path: str = "/item",
    parameter: str = "id",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source={
            "scanner": scanner,
            "scanner_finding_id": scanner_finding_id,
            "original_name": "SQL Injection - MySQL",
        },
        vulnerability={
            "category": "SQLI",
            "subtype": None,
            "raw_severity": "High",
            "normalized_severity": "HIGH",
            "raw_confidence": "2",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-89",
        },
        target={
            "url": f"http://example.test{path}?id=1",
            "normalized_url": f"http://example.test{path}",
            "host": "example.test",
            "path": path,
            "parameter": parameter,
            "parameter_location": "QUERY",
        },
        original_test={
            "payload": "'",
            "evidence": "SQL syntax error",
        },
        request={
            "method": "GET",
            "url": f"http://example.test{path}?id=1",
            "path": path,
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
    scan_id: str = "scan-eval-001",
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


# ---------------------------------------------------------------------
# ground_truth_service
# ---------------------------------------------------------------------


def test_save_ground_truth_labels_rejects_unknown_finding_id():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
    )

    try:
        save_ground_truth_labels(
            "scan-eval-001",
            [
                GroundTruthLabel(
                    finding_id="f-does-not-exist",
                    expected_status="TRUE_POSITIVE",
                )
            ],
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "f-does-not-exist" in str(exc)


def test_save_and_get_ground_truth_labels_roundtrip():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
    )

    save_ground_truth_labels(
        "scan-eval-001",
        [
            GroundTruthLabel(
                finding_id="f-a",
                expected_status="TRUE_POSITIVE",
            )
        ],
    )

    labels = get_ground_truth_labels("scan-eval-001")

    assert len(labels) == 1
    assert labels[0].finding_id == "f-a"
    assert labels[0].expected_status == "TRUE_POSITIVE"


def test_demo_ground_truth_matches_known_dvwa_sqli_finding():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-a",
                scanner="ZAP",
                scanner_finding_id="40018",
                path="/DVWA/vulnerabilities/sqli/",
                parameter="id",
            )
        ],
    )

    labels = load_demo_ground_truth("scan-eval-001")

    assert len(labels) == 1
    assert labels[0].finding_id == "f-a"
    assert labels[0].expected_status == "TRUE_POSITIVE"


def test_demo_ground_truth_does_not_match_unrelated_finding():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-a",
                scanner="ZAP",
                scanner_finding_id="40018",
                path="/some/other/page",
                parameter="q",
            )
        ],
    )

    labels = load_demo_ground_truth("scan-eval-001")

    assert labels == []
    assert get_ground_truth_labels("scan-eval-001") == []


# ---------------------------------------------------------------------
# evaluation_service.compute_evaluation_metrics
# ---------------------------------------------------------------------


def test_metrics_with_no_ground_truth_are_all_null_and_zero():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[make_verified(finding_id="f-a")],
    )

    metrics = compute_evaluation_metrics("scan-eval-001")

    assert metrics.ground_truth_count == 0
    assert metrics.evaluated_count == 0
    assert metrics.true_positive == 0
    assert metrics.false_positive == 0
    assert metrics.true_negative == 0
    assert metrics.false_negative == 0
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1 is None


def test_metrics_perfect_classifier():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-tp"),
            make_normalized(finding_id="f-tn"),
        ],
        verified=[
            make_verified(
                finding_id="f-tp", status="TRUE_POSITIVE"
            ),
            make_verified(
                finding_id="f-tn", status="FALSE_POSITIVE"
            ),
        ],
    )

    save_ground_truth_labels(
        "scan-eval-001",
        [
            GroundTruthLabel(
                finding_id="f-tp",
                expected_status="TRUE_POSITIVE",
            ),
            GroundTruthLabel(
                finding_id="f-tn",
                expected_status="FALSE_POSITIVE",
            ),
        ],
    )

    metrics = compute_evaluation_metrics("scan-eval-001")

    assert metrics.true_positive == 1
    assert metrics.true_negative == 1
    assert metrics.false_positive == 0
    assert metrics.false_negative == 0
    assert metrics.evaluated_count == 2
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


def test_metrics_false_positive_and_false_negative():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-fp"),
            make_normalized(finding_id="f-fn"),
        ],
        verified=[
            # scanner said FALSE_POSITIVE was actually vulnerable
            # (verifier over-confirms) -> counted as FP
            make_verified(
                finding_id="f-fp", status="TRUE_POSITIVE"
            ),
            # verifier missed an actual vulnerability -> FN
            make_verified(
                finding_id="f-fn", status="FALSE_POSITIVE"
            ),
        ],
    )

    save_ground_truth_labels(
        "scan-eval-001",
        [
            GroundTruthLabel(
                finding_id="f-fp",
                expected_status="FALSE_POSITIVE",
            ),
            GroundTruthLabel(
                finding_id="f-fn",
                expected_status="TRUE_POSITIVE",
            ),
        ],
    )

    metrics = compute_evaluation_metrics("scan-eval-001")

    assert metrics.true_positive == 0
    assert metrics.true_negative == 0
    assert metrics.false_positive == 1
    assert metrics.false_negative == 1
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 is None


def test_metrics_zero_denominator_when_no_predicted_positives():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[
            make_verified(
                finding_id="f-a", status="FALSE_POSITIVE"
            )
        ],
    )

    save_ground_truth_labels(
        "scan-eval-001",
        [
            GroundTruthLabel(
                finding_id="f-a",
                expected_status="TRUE_POSITIVE",
            )
        ],
    )

    metrics = compute_evaluation_metrics("scan-eval-001")

    # TP=0, FP=0 -> precision denominator is 0
    assert metrics.true_positive == 0
    assert metrics.false_negative == 1
    assert metrics.precision is None
    assert metrics.recall == 0.0
    assert metrics.f1 is None


def test_metrics_excludes_inconclusive_verdicts():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[
            make_verified(
                finding_id="f-a", status="INCONCLUSIVE"
            )
        ],
    )

    save_ground_truth_labels(
        "scan-eval-001",
        [
            GroundTruthLabel(
                finding_id="f-a",
                expected_status="TRUE_POSITIVE",
            )
        ],
    )

    metrics = compute_evaluation_metrics("scan-eval-001")

    assert metrics.ground_truth_count == 1
    assert metrics.excluded_inconclusive_count == 1
    assert metrics.evaluated_count == 0
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1 is None


def test_metrics_excludes_labels_with_no_verification_yet():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
        verified=[],
    )

    save_ground_truth_labels(
        "scan-eval-001",
        [
            GroundTruthLabel(
                finding_id="f-a",
                expected_status="TRUE_POSITIVE",
            )
        ],
    )

    metrics = compute_evaluation_metrics("scan-eval-001")

    assert metrics.ground_truth_count == 1
    assert metrics.unverified_ground_truth_count == 1
    assert metrics.evaluated_count == 0


# ---------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------


def test_metrics_endpoint_unknown_scan_returns_404():
    scans.clear()

    response = client.get("/api/v1/scans/missing/metrics")

    assert response.status_code == 404


def test_ground_truth_post_and_get_endpoints():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
    )

    post_response = client.post(
        "/api/v1/scans/scan-eval-001/ground-truth",
        json={
            "labels": [
                {
                    "finding_id": "f-a",
                    "expected_status": "TRUE_POSITIVE",
                }
            ]
        },
    )

    assert post_response.status_code == 200
    assert post_response.json()["count"] == 1

    get_response = client.get(
        "/api/v1/scans/scan-eval-001/ground-truth"
    )

    assert get_response.status_code == 200
    body = get_response.json()
    assert body["count"] == 1
    assert body["labels"][0]["finding_id"] == "f-a"


def test_ground_truth_post_rejects_unknown_finding_id_via_api():
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")],
    )

    response = client.post(
        "/api/v1/scans/scan-eval-001/ground-truth",
        json={
            "labels": [
                {
                    "finding_id": "not-real",
                    "expected_status": "TRUE_POSITIVE",
                }
            ]
        },
    )

    assert response.status_code == 400


def test_demo_ground_truth_endpoint_and_full_metrics_flow():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-a",
                scanner="ZAP",
                scanner_finding_id="40018",
                path="/DVWA/vulnerabilities/sqli/",
                parameter="id",
            )
        ],
        verified=[
            make_verified(
                finding_id="f-a", status="TRUE_POSITIVE"
            )
        ],
    )

    demo_response = client.post(
        "/api/v1/scans/scan-eval-001/ground-truth/demo"
    )

    assert demo_response.status_code == 200
    assert demo_response.json()["count"] == 1

    metrics_response = client.get(
        "/api/v1/scans/scan-eval-001/metrics"
    )

    assert metrics_response.status_code == 200
    metrics = metrics_response.json()

    assert metrics["scan_id"] == "scan-eval-001"
    assert metrics["ground_truth_count"] == 1
    assert metrics["evaluated_count"] == 1
    assert metrics["true_positive"] == 1
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0


def test_demo_ground_truth_endpoint_no_match_returns_empty():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-a",
                path="/unrelated",
                parameter="q",
            )
        ],
    )

    response = client.post(
        "/api/v1/scans/scan-eval-001/ground-truth/demo"
    )

    assert response.status_code == 200
    assert response.json()["count"] == 0

    metrics_response = client.get(
        "/api/v1/scans/scan-eval-001/metrics"
    )

    metrics = metrics_response.json()
    assert metrics["ground_truth_count"] == 0
    assert metrics["precision"] is None
