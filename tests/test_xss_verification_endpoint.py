from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.normalized_finding import (
    NormalizedFinding,
)
from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)


client = TestClient(app)


def make_finding(
    finding_id: str = "xss-001",
    subtype: str = "Cross-site Scripting (Reflected)",
    category: str = "XSS",
    parameter: str | None = "q",
    parameter_location: str = "QUERY",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-xss-001",
        finding_id=finding_id,
        source={
            "scanner": "Burp",
            "scanner_finding_id": "1",
            "original_name": subtype,
        },
        vulnerability={
            "category": category,
            "subtype": subtype,
            "raw_severity": "High",
            "normalized_severity": "HIGH",
            "raw_confidence": "Firm",
            "normalized_confidence": "MEDIUM",
            "cwe": "CWE-79",
        },
        target={
            "url": "http://example.test/search?q=placeholder",
            "normalized_url": (
                "http://example.test/search?q=placeholder"
            ),
            "host": "example.test",
            "path": "/search",
            "parameter": parameter,
            "parameter_location": parameter_location,
        },
        original_test={
            "payload": None,
            "evidence": None,
        },
        request={
            "method": "GET",
            "url": "http://example.test/search?q=placeholder",
            "path": "/search",
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
        references=[],
        metadata={},
    )


def make_reflecting_replay_result(
    url: str,
    body: str,
    status: int = 200,
) -> ReplayResult:
    return ReplayResult(
        finding_id="xss-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url=url,
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


def setup_scan(finding: NormalizedFinding | None = None):
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    scans["scan-xss-001"] = {
        "scan_id": "scan-xss-001",
        "filename": "test.xml",
        "content_type": "application/xml",
        "scanner": "BURP",
        "status": "NORMALIZED",
        "error": None,
    }

    normalized_findings["scan-xss-001"] = [
        finding if finding is not None else make_finding()
    ]


def two_variant_payload():
    return {
        "reflected": {
            "payload_variants": [
                {
                    "variant_id": "v1",
                    "payload": "<script>MARK1</script>",
                },
                {
                    "variant_id": "v2",
                    "payload": "<script>MARK2</script>",
                },
            ],
        },
    }


def test_verify_endpoint_returns_404_for_unknown_scan():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    response = client.post(
        "/api/v1/scans/missing/findings/xss-001/verify",
        json={"xss": two_variant_payload()},
    )

    assert response.status_code == 404


def test_verify_endpoint_returns_404_for_unknown_finding():
    setup_scan()

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/missing/verify",
        json={"xss": two_variant_payload()},
    )

    assert response.status_code == 404


def test_verify_endpoint_rejects_non_xss_finding():
    setup_scan(finding=make_finding(category="CSRF"))

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/xss-001/verify",
        json={"xss": two_variant_payload()},
    )

    assert response.status_code == 400


def test_verify_endpoint_rejects_non_reflected_subtype():
    setup_scan(
        finding=make_finding(
            subtype="Cross-site Scripting (Stored)",
        )
    )

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/xss-001/verify",
        json={"xss": two_variant_payload()},
    )

    assert response.status_code == 400


def test_verify_endpoint_rejects_non_query_parameter():
    setup_scan(
        finding=make_finding(
            parameter="q",
            parameter_location="FORM",
        )
    )

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/xss-001/verify",
        json={"xss": two_variant_payload()},
    )

    assert response.status_code == 400


def test_verify_endpoint_rejects_expected_parameter_mismatch():
    setup_scan()

    payload = two_variant_payload()
    payload["reflected"]["expected_parameter"] = "not-q"

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/xss-001/verify",
        json={"xss": payload},
    )

    assert response.status_code == 400


def test_verify_endpoint_true_positive_via_two_structural_confirmations(
    monkeypatch,
):
    setup_scan()

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        # Both variants land in the response as a self-contained,
        # payload-authored <script> element.
        if "MARK1" in request.url:
            body = "<div><script>MARK1</script></div>"
        else:
            body = "<div><script>MARK2</script></div>"

        return make_reflecting_replay_result(
            url=request.url,
            body=body,
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/xss-001/verify",
        json={"xss": two_variant_payload()},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["classification"]["status"] == "TRUE_POSITIVE"
    assert data["classification"]["confidence"] == 0.0
    assert "xss-001" in verified_findings["scan-xss-001"]


def test_verify_endpoint_false_positive_when_consistently_absent(
    monkeypatch,
):
    setup_scan()

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        return make_reflecting_replay_result(
            url=request.url,
            body="<html><body>no reflection here</body></html>",
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/xss-001/verify",
        json={"xss": two_variant_payload()},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["classification"]["status"] == "FALSE_POSITIVE"
    assert data["classification"]["confidence"] == 0.0


def test_verify_endpoint_inconclusive_on_ambiguous_reflection(
    monkeypatch,
):
    setup_scan()

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        # Plain-text-node reflection: not one of the named inert or
        # executable sub-cases, so the analyzer stays ambiguous.
        if "MARK1" in request.url:
            body = "<p>MARK1</p>"
        else:
            body = "<p>MARK2</p>"

        return make_reflecting_replay_result(
            url=request.url,
            body=body,
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    payload = {
        "reflected": {
            "payload_variants": [
                {"variant_id": "v1", "payload": "MARK1"},
                {"variant_id": "v2", "payload": "MARK2"},
            ],
        },
    }

    response = client.post(
        "/api/v1/scans/scan-xss-001/findings/xss-001/verify",
        json={"xss": payload},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["classification"]["status"] == "INCONCLUSIVE"
    assert data["classification"]["confidence"] == 0.0
