from backend.models.replay_result import ReplayResult
from backend.replay.csrf import (
    CsrfOriginMutation,
    CsrfOriginReplayResult,
)
from backend.verification.csrf_origin import (
    evaluate_csrf_origin_policy,
)


def make_replay(
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


def make_origin_replay(
    modified_status: int,
    rejection_observed: bool,
) -> CsrfOriginReplayResult:
    return CsrfOriginReplayResult(
        original_replay=make_replay(200),
        modified_replay=make_replay(
            modified_status
        ),
        mutation=CsrfOriginMutation.BOTH,
        attacker_origin="https://attacker.example",
        attacker_referer=(
            "https://attacker.example/csrf-test"
        ),
        rejection_observed=rejection_observed,
        rejection_status=modified_status,
    )


def test_origin_policy_enforced_when_rejection_is_attributable():
    replay = make_origin_replay(
        modified_status=403,
        rejection_observed=True,
    )

    result = evaluate_csrf_origin_policy(
        replay_result=replay,
        rejection_attributable_to_origin_policy=True,
    )

    assert (
        result.origin_or_referer_enforced
        is True
    )


def test_403_alone_does_not_prove_origin_policy():
    replay = make_origin_replay(
        modified_status=403,
        rejection_observed=True,
    )

    result = evaluate_csrf_origin_policy(
        replay_result=replay,
        rejection_attributable_to_origin_policy=False,
    )

    assert (
        result.origin_or_referer_enforced
        is False
    )


def test_successful_cross_site_replay_means_policy_not_enforced():
    replay = make_origin_replay(
        modified_status=200,
        rejection_observed=False,
    )

    result = evaluate_csrf_origin_policy(
        replay_result=replay,
        rejection_attributable_to_origin_policy=True,
    )

    assert (
        result.origin_or_referer_enforced
        is False
    )