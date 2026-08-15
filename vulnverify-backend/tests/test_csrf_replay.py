from backend.models.replay_result import (
    ReplayRequest,
    ReplayResult,
)
from backend.replay.csrf import (
    CsrfDefenseLocation,
    _remove_csrf_defense,
    replay_without_csrf_defense,
)


def make_request() -> ReplayRequest:
    return ReplayRequest(
        method="POST",
        url=(
            "http://example.test/profile"
            "?csrf_token=query-token&id=1"
        ),
        headers={
            "X-CSRF-Token": "header-token",
            "Cookie": "session=abc123",
        },
        body=(
            "email=test@example.com"
            "&csrf_token=body-token"
        ),
    )


def test_remove_header_csrf_token():
    request = make_request()

    result = _remove_csrf_defense(
        request=request,
        defense_name="X-CSRF-Token",
        defense_location=CsrfDefenseLocation.HEADER,
    )

    assert "X-CSRF-Token" not in result.headers
    assert (
        result.headers["Cookie"]
        == "session=abc123"
    )

    assert result.url == request.url
    assert result.body == request.body


def test_remove_header_is_case_insensitive():
    request = make_request()

    result = _remove_csrf_defense(
        request=request,
        defense_name="x-csrf-token",
        defense_location=CsrfDefenseLocation.HEADER,
    )

    assert "X-CSRF-Token" not in result.headers


def test_remove_query_csrf_token():
    request = make_request()

    result = _remove_csrf_defense(
        request=request,
        defense_name="csrf_token",
        defense_location=CsrfDefenseLocation.QUERY,
    )

    assert "csrf_token=" not in result.url
    assert "id=1" in result.url

    assert (
        result.headers
        == request.headers
    )

    assert result.body == request.body


def test_remove_body_csrf_token():
    request = make_request()

    result = _remove_csrf_defense(
        request=request,
        defense_name="csrf_token",
        defense_location=CsrfDefenseLocation.BODY,
    )

    assert "csrf_token=" not in result.body
    assert "email=test%40example.com" in result.body

    assert result.url == request.url

    assert (
        result.headers
        == request.headers
    )


def test_original_request_is_not_mutated():
    request = make_request()

    _remove_csrf_defense(
        request=request,
        defense_name="X-CSRF-Token",
        defense_location=CsrfDefenseLocation.HEADER,
    )

    assert (
        request.headers["X-CSRF-Token"]
        == "header-token"
    )


def test_replay_records_rejection_without_classifying(
    monkeypatch,
):
    request = make_request()

    calls = []

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
        calls.append(request)

        status = (
            200
            if len(calls) == 1
            else 403
        )

        return ReplayResult(
            finding_id=finding_id,
            replay={
                "executed": True,
                "timestamp": (
                    "2026-08-15T12:00:00Z"
                ),
                "request": request,
                "response": {
                    "status": status,
                    "headers": {},
                    "body": None,
                },
            },
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.csrf.execute_replay",
        fake_execute_replay,
    )

    result = replay_without_csrf_defense(
        finding_id="csrf-001",
        request=request,
        defense_name="X-CSRF-Token",
        defense_location=(
            CsrfDefenseLocation.HEADER
        ),
    )

    assert len(calls) == 2

    assert (
        calls[0].headers["X-CSRF-Token"]
        == "header-token"
    )

    assert (
        "X-CSRF-Token"
        not in calls[1].headers
    )

    assert (
        result.original_replay.replay.response.status
        == 200
    )

    assert (
        result.modified_replay.replay.response.status
        == 403
    )

    assert result.rejection_observed is True
    assert result.rejection_status == 403


def test_200_modified_response_is_not_rejection(
    monkeypatch,
):
    request = make_request()

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
        return ReplayResult(
            finding_id=finding_id,
            replay={
                "executed": True,
                "timestamp": (
                    "2026-08-15T12:00:00Z"
                ),
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
        "backend.replay.csrf.execute_replay",
        fake_execute_replay,
    )

    result = replay_without_csrf_defense(
        finding_id="csrf-001",
        request=request,
        defense_name="X-CSRF-Token",
        defense_location=(
            CsrfDefenseLocation.HEADER
        ),
    )

    assert result.rejection_observed is False
    assert result.rejection_status == 200