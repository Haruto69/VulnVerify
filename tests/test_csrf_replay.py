from backend.models.replay_result import (
    ReplayRequest,
    ReplayResult,
)
from backend.replay.csrf import (
    DEFAULT_ATTACKER_ORIGIN,
    DEFAULT_ATTACKER_REFERER,
    CsrfDefenseLocation,
    CsrfOriginMutation,
    _apply_cross_site_origin,
    _remove_csrf_defense,
    replay_with_cross_site_origin,
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
            "Origin": "http://example.test",
            "Referer": "http://example.test/profile",
            "X-CSRF-Token": "header-token",
            "Cookie": "session=abc123",
            "Authorization": "Bearer test-token",
        },
        body=(
            "email=test@example.com"
            "&csrf_token=body-token"
        ),
    )


def make_replay_result(
    finding_id: str,
    request: ReplayRequest,
    status: int,
) -> ReplayResult:
    return ReplayResult(
        finding_id=finding_id,
        replay={
            "executed": True,
            "timestamp": "2026-08-15T12:00:00Z",
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

    assert (
        "email=test%40example.com"
        in result.body
    )

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

        return make_replay_result(
            finding_id=finding_id,
            request=request,
            status=status,
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
        return make_replay_result(
            finding_id=finding_id,
            request=request,
            status=200,
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


def test_cross_site_origin_replaces_origin_only():
    request = make_request()

    result = _apply_cross_site_origin(
        request=request,
        mutation=CsrfOriginMutation.ORIGIN,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
        attacker_referer=DEFAULT_ATTACKER_REFERER,
    )

    assert (
        result.headers["Origin"]
        == DEFAULT_ATTACKER_ORIGIN
    )

    assert (
        result.headers["Referer"]
        == "http://example.test/profile"
    )

    assert (
        result.headers["Cookie"]
        == "session=abc123"
    )

    assert (
        result.headers["Authorization"]
        == "Bearer test-token"
    )


def test_cross_site_referer_replaces_referer_only():
    request = make_request()

    result = _apply_cross_site_origin(
        request=request,
        mutation=CsrfOriginMutation.REFERER,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
        attacker_referer=DEFAULT_ATTACKER_REFERER,
    )

    assert (
        result.headers["Origin"]
        == "http://example.test"
    )

    assert (
        result.headers["Referer"]
        == DEFAULT_ATTACKER_REFERER
    )


def test_cross_site_both_replaces_both_headers():
    request = make_request()

    result = _apply_cross_site_origin(
        request=request,
        mutation=CsrfOriginMutation.BOTH,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
        attacker_referer=DEFAULT_ATTACKER_REFERER,
    )

    assert (
        result.headers["Origin"]
        == DEFAULT_ATTACKER_ORIGIN
    )

    assert (
        result.headers["Referer"]
        == DEFAULT_ATTACKER_REFERER
    )


def test_cross_site_mutation_preserves_request_data():
    request = make_request()

    result = _apply_cross_site_origin(
        request=request,
        mutation=CsrfOriginMutation.BOTH,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
        attacker_referer=DEFAULT_ATTACKER_REFERER,
    )

    assert result.method == request.method
    assert result.url == request.url
    assert result.body == request.body

    assert (
        result.headers["Cookie"]
        == request.headers["Cookie"]
    )

    assert (
        result.headers["Authorization"]
        == request.headers["Authorization"]
    )


def test_cross_site_mutation_does_not_change_original_request():
    request = make_request()

    _apply_cross_site_origin(
        request=request,
        mutation=CsrfOriginMutation.BOTH,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
        attacker_referer=DEFAULT_ATTACKER_REFERER,
    )

    assert (
        request.headers["Origin"]
        == "http://example.test"
    )

    assert (
        request.headers["Referer"]
        == "http://example.test/profile"
    )


def test_cross_site_header_matching_is_case_insensitive():
    request = ReplayRequest(
        method="POST",
        url="http://example.test/change",
        headers={
            "origin": "http://example.test",
            "referer": "http://example.test/change",
            "Cookie": "session=abc123",
        },
        body=None,
    )

    result = _apply_cross_site_origin(
        request=request,
        mutation=CsrfOriginMutation.BOTH,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
        attacker_referer=DEFAULT_ATTACKER_REFERER,
    )

    origin_headers = [
        key
        for key in result.headers
        if key.lower() == "origin"
    ]

    referer_headers = [
        key
        for key in result.headers
        if key.lower() == "referer"
    ]

    assert len(origin_headers) == 1
    assert len(referer_headers) == 1

    assert (
        result.headers["Origin"]
        == DEFAULT_ATTACKER_ORIGIN
    )

    assert (
        result.headers["Referer"]
        == DEFAULT_ATTACKER_REFERER
    )


def test_origin_replay_records_rejection(
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

        return make_replay_result(
            finding_id=finding_id,
            request=request,
            status=status,
        )

    monkeypatch.setattr(
        "backend.replay.csrf.execute_replay",
        fake_execute_replay,
    )

    result = replay_with_cross_site_origin(
        finding_id="csrf-001",
        request=request,
        mutation=CsrfOriginMutation.BOTH,
    )

    assert len(calls) == 2

    assert (
        calls[0].headers["Origin"]
        == "http://example.test"
    )

    assert (
        calls[1].headers["Origin"]
        == DEFAULT_ATTACKER_ORIGIN
    )

    assert (
        calls[1].headers["Referer"]
        == DEFAULT_ATTACKER_REFERER
    )

    assert (
        calls[1].headers["Cookie"]
        == "session=abc123"
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

    assert (
        result.mutation
        == CsrfOriginMutation.BOTH
    )


def test_origin_replay_200_is_not_rejection(
    monkeypatch,
):
    request = make_request()

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
        return make_replay_result(
            finding_id=finding_id,
            request=request,
            status=200,
        )

    monkeypatch.setattr(
        "backend.replay.csrf.execute_replay",
        fake_execute_replay,
    )

    result = replay_with_cross_site_origin(
        finding_id="csrf-001",
        request=request,
        mutation=CsrfOriginMutation.BOTH,
    )

    assert result.rejection_observed is False
    assert result.rejection_status == 200