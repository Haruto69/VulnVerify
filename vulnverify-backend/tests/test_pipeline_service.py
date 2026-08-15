from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.services.pipeline_service import replay_finding


def make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id="finding-001",
        source={
            "scanner": "ZAP",
            "scanner_finding_id": "40018",
            "original_name": "SQL Injection - MySQL",
        },
        vulnerability={
            "category": "SQLI",
            "subtype": None,
            "raw_severity": "High (Medium)",
            "normalized_severity": "HIGH",
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
            "query_parameters": {
                "id": ["1"]
            },
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


def test_replay_finding_uses_generic_pipeline(
    monkeypatch,
):
    finding = make_finding()

    captured = {}

    def fake_build_replay_request(
        normalized_finding,
    ):
        captured["finding"] = normalized_finding

        from backend.models.replay_result import ReplayRequest

        return ReplayRequest(
            method="GET",
            url="http://example.test/item?id=1",
            headers={},
            body=None,
        )

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
        captured["finding_id"] = finding_id
        captured["request"] = request
        captured["timeout_seconds"] = timeout_seconds

        return ReplayResult(
            finding_id=finding_id,
            replay={
                "executed": True,
                "timestamp": "2026-08-15T12:00:00Z",
                "request": request,
                "response": {
                    "status": 200,
                    "headers": {},
                    "body": "ok",
                },
            },
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.services.pipeline_service.build_replay_request",
        fake_build_replay_request,
    )

    monkeypatch.setattr(
        "backend.services.pipeline_service.execute_replay",
        fake_execute_replay,
    )

    result = replay_finding(
        finding=finding,
        timeout_seconds=5.0,
    )

    assert captured["finding"] == finding
    assert captured["finding_id"] == "finding-001"
    assert captured["timeout_seconds"] == 5.0

    assert result.finding_id == "finding-001"
    assert result.replay.response.status == 200