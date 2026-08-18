import httpx

from backend.models.replay_result import ReplayRequest
from backend.replay.engine import execute_replay


def test_execute_replay_with_http_response(
    monkeypatch,
):
    def handler(request: httpx.Request):
        assert request.method == "GET"

        assert str(request.url) == (
            "http://example.test/item?id=1"
        )

        assert (
            request.headers["x-test-header"]
            == "test-value"
        )

        return httpx.Response(
            status_code=200,
            headers={
                "Content-Type": "text/plain"
            },
            text="replay worked",
        )

    transport = httpx.MockTransport(
        handler
    )

    original_client = httpx.Client

    def mock_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        mock_client,
    )

    replay_request = ReplayRequest(
        method="GET",
        url="http://example.test/item?id=1",
        headers={
            "x-test-header": "test-value"
        },
        body=None,
    )

    result = execute_replay(
        finding_id="finding-001",
        request=replay_request,
    )

    assert result.finding_id == "finding-001"

    assert result.replay.executed is True

    assert (
        result.replay.request
        == replay_request
    )

    assert (
        result.replay.response.status
        == 200
    )

    assert (
        result.replay.response.body
        == "replay worked"
    )

    assert result.observations == []
    assert result.errors == []


def test_execute_replay_with_transport_error(
    monkeypatch,
):
    def handler(request: httpx.Request):
        raise httpx.ConnectError(
            "Connection refused",
            request=request,
        )

    transport = httpx.MockTransport(
        handler
    )

    original_client = httpx.Client

    def mock_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        mock_client,
    )

    replay_request = ReplayRequest(
        method="GET",
        url="http://example.test/item?id=1",
        headers={},
        body=None,
    )

    result = execute_replay(
        finding_id="finding-002",
        request=replay_request,
    )

    assert result.replay.executed is True

    assert (
        result.replay.response.status
        is None
    )

    assert (
        result.replay.response.headers
        == {}
    )

    assert (
        result.replay.response.body
        is None
    )

    assert len(result.errors) == 1

    assert (
        "ConnectError"
        in result.errors[0]
    )

    assert (
        "Connection refused"
        in result.errors[0]
    )


def test_execute_replay_does_not_follow_redirects(
    monkeypatch,
):
    def handler(request: httpx.Request):
        return httpx.Response(
            status_code=302,
            headers={
                "Location": "/login"
            },
        )

    transport = httpx.MockTransport(
        handler
    )

    original_client = httpx.Client

    def mock_client(*args, **kwargs):
        assert (
            kwargs["follow_redirects"]
            is False
        )

        kwargs["transport"] = transport

        return original_client(
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        mock_client,
    )

    replay_request = ReplayRequest(
        method="GET",
        url="http://example.test/protected",
        headers={},
        body=None,
    )

    result = execute_replay(
        finding_id="finding-003",
        request=replay_request,
    )

    assert (
        result.replay.response.status
        == 302
    )

    assert (
        result.replay.response.headers[
            "location"
        ]
        == "/login"
    )