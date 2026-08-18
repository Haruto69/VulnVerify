from fastapi.testclient import TestClient

from backend.main import app
from backend.models.normalized_finding import NormalizedFinding
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)


client = TestClient(app)


def make_normalized(
    finding_id: str = "f-a",
    scan_id: str = "scan-enrich-001",
    scanner: str = "Burp",
    cwe: str | None = "CWE-942",
    references: list[str] | None = None,
    metadata: dict | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source={
            "scanner": scanner,
            "scanner_finding_id": "1",
            "original_name": "Cross-origin resource sharing",
        },
        vulnerability={
            "category": "CORS",
            "subtype": "Cross-origin resource sharing",
            "raw_severity": "Information",
            "normalized_severity": "INFORMATIONAL",
            "raw_confidence": "Certain",
            "normalized_confidence": "HIGH",
            "cwe": cwe,
        },
        target={
            "url": "http://example.test/socket.io/",
            "normalized_url": "http://example.test/socket.io/",
            "host": "example.test",
            "path": "/socket.io/",
            "parameter": None,
            "parameter_location": "UNKNOWN",
        },
        original_test={
            "payload": None,
            "evidence": None,
        },
        request={
            "method": "GET",
            "url": "http://example.test/socket.io/",
            "path": "/socket.io/",
            "query_parameters": {},
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
        references=references if references is not None else [],
        metadata=metadata if metadata is not None else {},
    )


def setup_scan(
    scan_id: str = "scan-enrich-001",
    normalized: list[NormalizedFinding] | None = None,
):
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    scans[scan_id] = {
        "scan_id": scan_id,
        "filename": "test.xml",
        "content_type": "application/xml",
        "scanner": "BURP",
        "status": "NORMALIZED",
        "error": None,
    }

    normalized_findings[scan_id] = normalized or []


def test_unknown_scan_returns_404():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    response = client.get(
        "/api/v1/scans/missing/enrichment"
    )

    assert response.status_code == 404


def test_scan_with_no_findings_returns_empty_enrichments():
    setup_scan(normalized=[])

    response = client.get(
        "/api/v1/scans/scan-enrich-001/enrichment"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == "scan-enrich-001"
    assert data["count"] == 0
    assert data["enrichments"] == []


def test_successful_response_shape():
    setup_scan(
        normalized=[
            make_normalized(finding_id="f-a"),
            make_normalized(finding_id="f-b"),
        ]
    )

    response = client.get(
        "/api/v1/scans/scan-enrich-001/enrichment"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == "scan-enrich-001"
    assert data["count"] == 2
    assert len(data["enrichments"]) == 2

    finding_ids = [
        item["finding_id"]
        for item in data["enrichments"]
    ]

    assert finding_ids == ["f-a", "f-b"]


def test_enrichment_works_before_any_verification():
    # verified_findings is deliberately left empty by setup_scan:
    # enrichment must not depend on verification having run.
    setup_scan(
        normalized=[make_normalized(finding_id="f-a")]
    )

    assert verified_findings == {}

    response = client.get(
        "/api/v1/scans/scan-enrich-001/enrichment"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert data["enrichments"][0]["finding_id"] == "f-a"


def test_json_serialization_preserves_all_fields():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-a",
                scanner="ZAP",
                cwe="CWE-89",
                references=[
                    "https://example.test/ref-one",
                    "https://example.test/ref-two",
                ],
                metadata={
                    "zap_description": (
                        "<p>SQL injection may be possible.</p>"
                    ),
                    "zap_solution": (
                        "<p>Do not trust client side input.</p>"
                    ),
                    "zap_tags": [
                        {
                            "tag": "OWASP_2021_A03",
                            "link": (
                                "https://owasp.org/Top10/"
                                "A03_2021-Injection/"
                            ),
                        },
                    ],
                },
            )
        ]
    )

    response = client.get(
        "/api/v1/scans/scan-enrich-001/enrichment"
    )

    assert response.status_code == 200

    enrichment = response.json()["enrichments"][0]

    assert enrichment["schema_version"] == "1.0"
    assert enrichment["scan_id"] == "scan-enrich-001"
    assert enrichment["finding_id"] == "f-a"
    assert enrichment["scanner"] == "ZAP"
    assert enrichment["cwe"] == "CWE-89"
    assert enrichment["cwe_url"] == (
        "https://cwe.mitre.org/data/definitions/89.html"
    )
    assert enrichment["owasp_category"] == "OWASP_2021_A03"
    assert enrichment["owasp_url"] == (
        "https://owasp.org/Top10/A03_2021-Injection/"
    )
    assert enrichment["description"] == (
        "SQL injection may be possible."
    )
    assert enrichment["remediation"] == (
        "Do not trust client side input."
    )
    assert enrichment["references"] == [
        "https://example.test/ref-one",
        "https://example.test/ref-two",
    ]


def test_finding_without_enrichment_data_returns_nulls():
    setup_scan(
        normalized=[
            make_normalized(
                finding_id="f-bare",
                cwe=None,
                references=[],
                metadata={},
            )
        ]
    )

    response = client.get(
        "/api/v1/scans/scan-enrich-001/enrichment"
    )

    assert response.status_code == 200

    enrichment = response.json()["enrichments"][0]

    assert enrichment["cwe"] is None
    assert enrichment["cwe_url"] is None
    assert enrichment["owasp_category"] is None
    assert enrichment["owasp_url"] is None
    assert enrichment["description"] is None
    assert enrichment["remediation"] is None
    assert enrichment["references"] == []
