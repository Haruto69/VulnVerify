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
from backend.replay.xss import (
    collect_reflected_xss_variant_attempts,
    replay_original_xss_request,
)
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


def make_finding_with_marker_url() -> NormalizedFinding:
    finding = make_finding()

    return finding.model_copy(
        update={
            "target": finding.target.model_copy(
                update={
                    "url": (
                        "http://example.test/search?q=placeholder"
                    ),
                    "normalized_url": (
                        "http://example.test/search?q=placeholder"
                    ),
                    "parameter": "q",
                }
            ),
            "request": finding.request.model_copy(
                update={
                    "url": (
                        "http://example.test/search?q=placeholder"
                    ),
                }
            ),
        }
    )


def make_reflecting_replay_result(body: str) -> ReplayResult:
    return ReplayResult(
        finding_id="xss-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://example.test/search?q=placeholder",
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


def test_collect_reflected_xss_variant_attempts_replays_each_variant(
    monkeypatch,
):
    calls = []

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        calls.append(request.url)
        return make_reflecting_replay_result("<html>no match</html>")

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    finding = make_finding_with_marker_url()

    attempts = collect_reflected_xss_variant_attempts(
        finding=finding,
        payload_variants=[
            ("variant-1", "MARK1"),
            ("variant-2", "MARK2"),
        ],
    )

    assert len(attempts) == 2
    assert [a.payload_variant_id for a in attempts] == [
        "variant-1",
        "variant-2",
    ]
    assert calls[0].endswith("q=MARK1")
    assert calls[1].endswith("q=MARK2")


def test_collect_reflected_xss_variant_attempts_sets_evidence_from_analyzer(
    monkeypatch,
):
    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        return make_reflecting_replay_result(
            "<div><script>MARK1</script></div>"
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    finding = make_finding_with_marker_url()

    attempts = collect_reflected_xss_variant_attempts(
        finding=finding,
        payload_variants=[
            ("variant-1", "<script>MARK1</script>"),
        ],
    )

    assert len(attempts) == 1
    attempt = attempts[0]

    assert attempt.browser_completed_successfully is True
    assert attempt.payload_reflected_or_rendered is True
    assert attempt.payload_unescaped_in_executable_context is True
    # marker_fired must never be set by the HTTP-only analyzer.
    assert attempt.marker_fired is False


def test_collect_reflected_xss_variant_attempts_marks_failed_replay(
    monkeypatch,
):
    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        return ReplayResult(
            finding_id="xss-001",
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
                    status=503,
                    headers={},
                    body=None,
                ),
            ),
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    finding = make_finding_with_marker_url()

    attempts = collect_reflected_xss_variant_attempts(
        finding=finding,
        payload_variants=[("variant-1", "MARK1")],
    )

    assert attempts[0].browser_completed_successfully is False