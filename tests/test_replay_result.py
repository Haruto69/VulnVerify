from datetime import datetime, timezone

from backend.models.replay_result import ReplayResult


def test_replay_result_with_http_response():
    result = ReplayResult(
        finding_id="finding-001",
        replay={
            "executed": True,
            "timestamp": datetime.now(timezone.utc),
            "request": {
                "method": "GET",
                "url": "http://example.test/item?id=1",
                "headers": {
                    "Accept": "text/html"
                },
                "body": None,
            },
            "response": {
                "status": 200,
                "headers": {
                    "Content-Type": "text/html"
                },
                "body": "response body",
            },
        },
        observations=[
            {
                "indicator": "Expected response marker found",
                "matched": True,
            }
        ],
        errors=[],
    )

    assert result.schema_version == "1.0"
    assert result.finding_id == "finding-001"

    assert result.replay.executed is True
    assert result.replay.request.method == "GET"

    assert result.replay.response.status == 200

    assert len(result.observations) == 1
    assert result.observations[0].matched is True

    assert result.errors == []


def test_replay_result_without_http_response():
    result = ReplayResult(
        finding_id="finding-002",
        replay={
            "executed": True,
            "timestamp": datetime.now(timezone.utc),
            "request": {
                "method": "GET",
                "url": "http://example.test/item?id=1",
                "headers": {},
                "body": None,
            },
            "response": {
                "status": None,
                "headers": {},
                "body": None,
            },
        },
        observations=[],
        errors=[
            "Request timed out"
        ],
    )

    assert result.replay.executed is True
    assert result.replay.response.status is None
    assert result.replay.response.headers == {}
    assert result.replay.response.body is None

    assert result.errors == [
        "Request timed out"
    ]