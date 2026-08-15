from backend.models.replay_result import (
    ReplayRequest,
    ReplayResult,
)
from backend.replay.csrf_state_check import (
    CsrfStateSnapshot,
    _compare_state,
    perform_csrf_state_check,
)


def make_request() -> ReplayRequest:
    return ReplayRequest(
        method="POST",
        url="http://example.test/change-email",
        headers={
            "Cookie": "session=abc123",
        },
        body="email=new@example.test",
    )


def test_compare_state_detects_change():
    before = CsrfStateSnapshot(
        observed=True,
        value="old@example.test",
    )

    after = CsrfStateSnapshot(
        observed=True,
        value="new@example.test",
    )

    assert (
        _compare_state(before, after)
        is True
    )


def test_compare_state_detects_no_change():
    before = CsrfStateSnapshot(
        observed=True,
        value="old@example.test",
    )

    after = CsrfStateSnapshot(
        observed=True,
        value="old@example.test",
    )

    assert (
        _compare_state(before, after)
        is False
    )


def test_compare_state_returns_unknown_when_before_missing():
    before = CsrfStateSnapshot(
        observed=False,
    )

    after = CsrfStateSnapshot(
        observed=True,
        value="new@example.test",
    )

    assert (
        _compare_state(before, after)
        is None
    )


def test_state_check_observes_before_and_after(
    monkeypatch,
):
    request = make_request()

    states = iter(
        [
            CsrfStateSnapshot(
                observed=True,
                value="old@example.test",
            ),
            CsrfStateSnapshot(
                observed=True,
                value="new@example.test",
            ),
        ]
    )

    def observe_state():
        return next(states)

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
        return ReplayResult(
            finding_id=finding_id,
            replay={
                "executed": True,
                "timestamp": "2026-08-15T12:00:00Z",
                "request": request,
                "response": {
                    "status": 200,
                    "headers": {},
                    "body": "Email changed",
                },
            },
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.csrf_state_check.execute_replay",
        fake_execute_replay,
    )

    replay, observation = (
        perform_csrf_state_check(
            finding_id="csrf-001",
            forged_request=request,
            observe_state=observe_state,
        )
    )

    assert (
        replay.replay.response.status
        == 200
    )

    assert (
        observation.before_state_observed
        is True
    )

    assert (
        observation.after_state_observed
        is True
    )

    assert (
        observation.state_changed
        is True
    )

    assert (
        observation.observation_method
        == "before_after_state_check"
    )


def test_state_check_detects_unchanged_state(
    monkeypatch,
):
    request = make_request()

    states = iter(
        [
            CsrfStateSnapshot(
                observed=True,
                value="old@example.test",
            ),
            CsrfStateSnapshot(
                observed=True,
                value="old@example.test",
            ),
        ]
    )

    def observe_state():
        return next(states)

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
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
        "backend.replay.csrf_state_check.execute_replay",
        fake_execute_replay,
    )

    _, observation = perform_csrf_state_check(
        finding_id="csrf-001",
        forged_request=request,
        observe_state=observe_state,
    )

    assert (
        observation.state_changed
        is False
    )


def test_state_check_uses_deterministic_indicator_as_fallback(
    monkeypatch,
):
    request = make_request()

    states = iter(
        [
            CsrfStateSnapshot(
                observed=False,
            ),
            CsrfStateSnapshot(
                observed=False,
            ),
        ]
    )

    def observe_state():
        return next(states)

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
        return ReplayResult(
            finding_id=finding_id,
            replay={
                "executed": True,
                "timestamp": "2026-08-15T12:00:00Z",
                "request": request,
                "response": {
                    "status": 200,
                    "headers": {},
                    "body": (
                        "Password Changed."
                    ),
                },
            },
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.csrf_state_check.execute_replay",
        fake_execute_replay,
    )

    _, observation = perform_csrf_state_check(
        finding_id="csrf-001",
        forged_request=request,
        observe_state=observe_state,
        deterministic_acceptance_indicator=(
            "Password Changed."
        ),
    )

    assert (
        observation.state_changed
        is None
    )

    assert (
        observation.deterministic_acceptance_indicator_matched
        is True
    )

    assert (
        observation.observation_method
        == "response_indicator"
    )


def test_state_check_collects_observation_errors(
    monkeypatch,
):
    request = make_request()

    states = iter(
        [
            CsrfStateSnapshot(
                observed=False,
                errors=[
                    "before state unavailable"
                ],
            ),
            CsrfStateSnapshot(
                observed=False,
                errors=[
                    "after state unavailable"
                ],
            ),
        ]
    )

    def observe_state():
        return next(states)

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds,
    ):
        return ReplayResult(
            finding_id=finding_id,
            replay={
                "executed": True,
                "timestamp": "2026-08-15T12:00:00Z",
                "request": request,
                "response": {
                    "status": 200,
                    "headers": {},
                    "body": None,
                },
            },
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.csrf_state_check.execute_replay",
        fake_execute_replay,
    )

    _, observation = perform_csrf_state_check(
        finding_id="csrf-001",
        forged_request=request,
        observe_state=observe_state,
    )

    assert observation.state_changed is None

    assert observation.errors == [
        "before state unavailable",
        "after state unavailable",
    ]