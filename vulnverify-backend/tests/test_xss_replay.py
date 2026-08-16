from datetime import datetime, timezone

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
from backend.replay.xss import replay_original_xss_request
from backend.verification.xss_context import XssSubtype


def make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-xss-001",
        finding_id="xss-001",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40012",
            original_name="Cross Site Scripting (Reflected)",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.XSS,
            subtype="REFLECTED",
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="High",
            normalized_confidence=NormalizedConfidence.HIGH,
            cwe="CWE-79",
        ),
        target=TargetInfo(
            url="http://example.test/search?q=scanner-payload",
            normalized_url="http://example.test/search?q=scanner-payload",
            host="example.test",
            path="/search",
            parameter="q",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="scanner-payload",
            evidence="scanner-evidence",
        ),
        request=HttpRequest(
            method="GET",
            url="http://example.test/search?q=scanner-payload",
            path="/search",
            headers={
                "Cookie": "session=test-session",
                "User-Agent": "scanner-agent",
            },
        ),
    )


def make_replay_result() -> ReplayResult:
    return ReplayResult(
        finding_id="xss-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://example.test/search?q=scanner-payload",
                headers={
                    "Cookie": "session=test-session",
                    "User-Agent": "scanner-agent",
                },
                body=None,
            ),
            response=ReplayResponse(
                status=200,
                headers={},
                body="<html>scanner-payload</html>",
            ),
        ),
        observations=[],
        errors=[],
    )


def test_reflected_xss_replays_original_request(monkeypatch):
    captured = {}

    def fake_execute_replay(
        *,
        finding_id,
        request,
        timeout_seconds,
    ):
        captured["finding_id"] = finding_id
        captured["request"] = request
        captured["timeout_seconds"] = timeout_seconds
        return make_replay_result()

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    finding = make_finding()

    observation = replay_original_xss_request(
        finding=finding,
        subtype=XssSubtype.REFLECTED,
        timeout_seconds=7.0,
    )

    assert observation.payload_variant_id == "scanner-original"
    assert observation.replay is not None

    assert captured["finding_id"] == "xss-001"
    assert captured["timeout_seconds"] == 7.0

    request = captured["request"]

    assert request.method == finding.request.method
    assert request.url == finding.request.url
    assert request.headers == finding.request.headers
    assert request.body == finding.request.body


def test_original_scanner_payload_is_not_replaced(monkeypatch):
    captured = {}

    def fake_execute_replay(
        *,
        finding_id,
        request,
        timeout_seconds,
    ):
        captured["request"] = request
        return make_replay_result()

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    finding = make_finding()

    replay_original_xss_request(
        finding=finding,
        subtype=XssSubtype.REFLECTED,
    )

    assert (
        captured["request"].url
        == "http://example.test/search?q=scanner-payload"
    )


def test_stored_xss_replays_injection_request(monkeypatch):
    calls = []

    def fake_execute_replay(
        *,
        finding_id,
        request,
        timeout_seconds,
    ):
        calls.append(request)
        return make_replay_result()

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    observation = replay_original_xss_request(
        finding=make_finding(),
        subtype=XssSubtype.STORED,
    )

    assert len(calls) == 1
    assert observation.replay is not None


def test_dom_xss_does_not_perform_http_replay(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError(
            "DOM-based XSS must not perform server replay"
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fail_if_called,
    )

    observation = replay_original_xss_request(
        finding=make_finding(),
        subtype=XssSubtype.DOM_BASED,
    )

    assert observation.payload_variant_id == "scanner-original"
    assert observation.replay is None


def test_custom_variant_id_is_preserved(monkeypatch):
    def fake_execute_replay(
        *,
        finding_id,
        request,
        timeout_seconds,
    ):
        return make_replay_result()

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    observation = replay_original_xss_request(
        finding=make_finding(),
        subtype=XssSubtype.REFLECTED,
        payload_variant_id="scanner-replay-1",
    )

    assert observation.payload_variant_id == "scanner-replay-1"