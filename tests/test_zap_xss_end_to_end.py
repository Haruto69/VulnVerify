"""
End-to-end proof that a ZAP reflected XSS alert (pluginid 40012),
previously discarded by ZapParser's formerly SQLi-only
_is_supported_alert, is no longer lost between parsing and
verification.

Covers the full path:
    ZAP JSON -> ZapParser -> NormalizedFinding -> XSS verification
    context/endpoint
via the real, unmodified HTTP API -- upload, list, verify -- not a
direct function call, so this also proves get_parser("ZAP") and the
normalization service route the finding through unchanged.
"""

from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)

client = TestClient(app)


XSS_ZAP_REPORT = "tests/fixtures/zap/zap_xss_positive.json"


def read_fixture(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def _upload_zap_xss_fixture(
    scan_id: str = "scan-zap-xss-001",
) -> str:
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    with open(XSS_ZAP_REPORT, "rb") as f:
        response = client.post(
            "/api/v1/scans",
            data={"scanner": "ZAP"},
            files={
                "file": (
                    "zap_xss_positive.json",
                    f,
                    "application/json",
                )
            },
        )

    assert response.status_code == 200
    return response.json()["scan_id"]


def test_upload_produces_one_xss_finding_via_the_real_zap_parser():
    scan_id = _upload_zap_xss_fixture()

    response = client.get(f"/api/v1/scans/{scan_id}/findings")

    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 1
    finding = body["findings"][0]

    assert finding["vulnerability"]["category"] == "XSS"
    assert finding["vulnerability"]["subtype"] == "REFLECTED"
    assert finding["source"]["scanner"] == "ZAP"
    assert finding["source"]["scanner_finding_id"] == "40012"
    assert finding["target"]["parameter"] == "name"
    assert finding["target"]["parameter_location"] == "QUERY"


def test_zap_xss_finding_reaches_true_positive_through_real_verify_endpoint(
    monkeypatch,
):
    scan_id = _upload_zap_xss_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        from datetime import datetime, timezone

        from backend.models.replay_result import (
            ReplayExecution,
            ReplayRequest,
            ReplayResponse,
            ReplayResult,
        )

        if "MARK1" in request.url:
            body = "<div><script>MARK1</script></div>"
        else:
            body = "<div><script>MARK2</script></div>"

        return ReplayResult(
            finding_id=finding_id,
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="GET",
                    url=request.url,
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=200,
                    headers={},
                    body=body,
                ),
            ),
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
        json={
            "xss": {
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
            },
        },
    )

    assert response.status_code == 200

    data = response.json()

    # The finding was NOT lost between parsing and verification, and
    # the existing (unmodified) XSS verification engine -- not the
    # parser -- is what produced this verdict from real reflection
    # evidence.
    assert data["classification"]["status"] == "TRUE_POSITIVE"
    assert finding_id in verified_findings[scan_id]


def test_zap_xss_finding_reaches_false_positive_when_not_reflected(
    monkeypatch,
):
    # The parser fix must not make every ZAP XSS alert an automatic
    # TRUE_POSITIVE -- the existing verification engine still requires
    # real reflection evidence.
    scan_id = _upload_zap_xss_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        from datetime import datetime, timezone

        from backend.models.replay_result import (
            ReplayExecution,
            ReplayRequest,
            ReplayResponse,
            ReplayResult,
        )

        return ReplayResult(
            finding_id=finding_id,
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="GET",
                    url=request.url,
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=200,
                    headers={},
                    body="<html><body>no reflection here</body></html>",
                ),
            ),
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
        json={
            "xss": {
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
            },
        },
    )

    assert response.status_code == 200
    assert (
        response.json()["classification"]["status"]
        == "FALSE_POSITIVE"
    )
