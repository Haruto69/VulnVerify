from backend.models.replay_result import ReplayResult
from backend.replay.csrf import (
    CsrfDefenseLocation,
    CsrfTokenReplayResult,
)
from backend.verification.csrf_defense import (
    evaluate_csrf_defense,
)


def make_replay_result(
    status: int,
) -> ReplayResult:
    return ReplayResult(
        finding_id="csrf-001",
        replay={
            "executed": True,
            "timestamp": "2026-08-15T12:00:00Z",
            "request": {
                "method": "POST",
                "url": "http://example.test/change",
                "headers": {},
                "body": None,
            },
            "response": {
                "status": status,
                "headers": {},
                "body": None,
            },
        },
        observations=[],
        errors=[],
    )


def make_token_replay(
    modified_status: int,
    rejection_observed: bool,
) -> CsrfTokenReplayResult:
    return CsrfTokenReplayResult(
        original_replay=make_replay_result(200),
        modified_replay=make_replay_result(
            modified_status
        ),
        defense_location=CsrfDefenseLocation.HEADER,
        defense_name="X-CSRF-Token",
        defense_removed=True,
        rejection_observed=rejection_observed,
        rejection_status=modified_status,
    )


def test_defense_enforced_when_rejection_is_attributable():
    replay = make_token_replay(
        modified_status=403,
        rejection_observed=True,
    )

    result = evaluate_csrf_defense(
        replay_result=replay,
        rejection_attributable_to_csrf_defense=True,
    )

    assert result.defense_enforced is True


def test_403_alone_does_not_prove_defense():
    replay = make_token_replay(
        modified_status=403,
        rejection_observed=True,
    )

    result = evaluate_csrf_defense(
        replay_result=replay,
        rejection_attributable_to_csrf_defense=False,
    )

    assert result.defense_enforced is False


def test_no_rejection_means_defense_not_enforced():
    replay = make_token_replay(
        modified_status=200,
        rejection_observed=False,
    )

    result = evaluate_csrf_defense(
        replay_result=replay,
        rejection_attributable_to_csrf_defense=True,
    )

    assert result.defense_enforced is False