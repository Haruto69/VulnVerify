from fastapi import (
    APIRouter,
    HTTPException,
)

from backend.models.verification_trigger import (
    VerificationTriggerRequest,
)
from backend.replay.csrf import (
    replay_with_cross_site_origin,
    replay_without_csrf_defense,
)
from backend.replay.request_builder import (
    build_replay_request,
)
from backend.services.pipeline_service import (
    replay_finding,
    verify_csrf_finding,
)
from backend.services.scan_service import (
    get_normalized_findings,
    get_scan,
)
from backend.verification.csrf_defense import (
    evaluate_csrf_defense,
)
from backend.verification.csrf_origin import (
    evaluate_csrf_origin_policy,
)
from backend.verification.csrf_state import (
    CsrfStateObservation,
)


router = APIRouter(
    prefix="/scans",
    tags=["findings"],
)


@router.post(
    "/{scan_id}/findings/{finding_id}/verify"
)
async def verify_finding(
    scan_id: str,
    finding_id: str,
    trigger: VerificationTriggerRequest,
):
    """
    Run configured CSRF verification checks for one normalized
    finding.

    The endpoint only derives conclusions that are supported by
    deterministic replay evidence. Missing application-specific
    evidence results in INCONCLUSIVE rather than a guessed verdict.
    """

    scan = get_scan(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    finding = _find_normalized_finding(
        scan_id=scan_id,
        finding_id=finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    if finding.vulnerability.category != "CSRF":
        raise HTTPException(
            status_code=400,
            detail=(
                "This verification endpoint currently "
                "supports CSRF findings only."
            ),
        )

    request = build_replay_request(
        finding
    )

    baseline_replay = replay_finding(
        finding=finding,
        timeout_seconds=trigger.timeout_seconds,
    )

    state_observation = _build_state_observation(
        replay_result=baseline_replay,
        trigger=trigger,
    )

    defense_observation = None

    if trigger.csrf.defense_test is not None:
        defense_replay = (
            replay_without_csrf_defense(
                finding_id=finding.finding_id,
                request=request,
                defense_name=(
                    trigger.csrf
                    .defense_test
                    .name
                ),
                defense_location=(
                    trigger.csrf
                    .defense_test
                    .location
                ),
                timeout_seconds=(
                    trigger.timeout_seconds
                ),
            )
        )

        attributable = (
            _controlled_rejection_is_attributable(
                original_status=(
                    defense_replay
                    .original_replay
                    .replay
                    .response
                    .status
                ),
                modified_status=(
                    defense_replay
                    .modified_replay
                    .replay
                    .response
                    .status
                ),
                rejection_observed=(
                    defense_replay
                    .rejection_observed
                ),
            )
        )

        defense_observation = (
            evaluate_csrf_defense(
                replay_result=defense_replay,
                rejection_attributable_to_csrf_defense=(
                    attributable
                ),
            )
        )

    origin_observation = None

    if trigger.csrf.origin_test is not None:
        origin_replay = (
            replay_with_cross_site_origin(
                finding_id=finding.finding_id,
                request=request,
                mutation=(
                    trigger.csrf
                    .origin_test
                    .mutation
                ),
                timeout_seconds=(
                    trigger.timeout_seconds
                ),
            )
        )

        attributable = (
            _controlled_rejection_is_attributable(
                original_status=(
                    origin_replay
                    .original_replay
                    .replay
                    .response
                    .status
                ),
                modified_status=(
                    origin_replay
                    .modified_replay
                    .replay
                    .response
                    .status
                ),
                rejection_observed=(
                    origin_replay
                    .rejection_observed
                ),
            )
        )

        origin_observation = (
            evaluate_csrf_origin_policy(
                replay_result=origin_replay,
                rejection_attributable_to_origin_policy=(
                    attributable
                ),
            )
        )

    request_accepted = (
        state_observation
        .deterministic_acceptance_indicator_matched
    )

    verified = verify_csrf_finding(
        finding=finding,
        replay_result=baseline_replay,
        state_observation=state_observation,
        defense_observation=defense_observation,
        origin_observation=origin_observation,

        state_changing_endpoint=(
            _infer_state_changing_endpoint(
                finding.request.method
            )
        ),

        forged_request_is_plausible_under_threat_model=(
            _forged_request_is_plausible(
                finding
            )
        ),

        effective_csrf_defense_absent_or_bypassable=(
            _derive_defense_absence(
                defense_observation=(
                    defense_observation
                ),
                origin_observation=(
                    origin_observation
                ),
            )
        ),

        request_accepted=(
            request_accepted
            if request_accepted
            else None
        ),

        reproducible=None,

        evidence_saved=True,

        browser_context_required=(
            trigger.csrf
            .browser_context_required
        ),

        insufficient_request_context=False,
        insufficient_scanner_data=False,
        nondeterministic_result=False,

        verification_confidence=(
            _verification_confidence(
                defense_observation=(
                    defense_observation
                ),
                origin_observation=(
                    origin_observation
                ),
                state_observation=(
                    state_observation
                ),
            )
        ),
    )

    return verified


def _find_normalized_finding(
    scan_id: str,
    finding_id: str,
):
    findings = get_normalized_findings(
        scan_id
    )

    for finding in findings:
        if finding.finding_id == finding_id:
            return finding

    return None


def _build_state_observation(
    replay_result,
    trigger: VerificationTriggerRequest,
) -> CsrfStateObservation:
    state_config = (
        trigger.csrf.state_check
    )

    if state_config is None:
        return CsrfStateObservation()

    indicator = (
        state_config
        .deterministic_acceptance_indicator
    )

    if indicator is None:
        return CsrfStateObservation()

    body = (
        replay_result
        .replay
        .response
        .body
    )

    matched = (
        body is not None
        and indicator in body
    )

    return CsrfStateObservation(
        before_state_observed=False,
        after_state_observed=False,
        state_changed=None,
        deterministic_acceptance_indicator=(
            indicator
        ),
        deterministic_acceptance_indicator_matched=(
            matched
        ),
        observation_method=(
            "response_indicator"
        ),
        errors=[],
    )


def _controlled_rejection_is_attributable(
    original_status: int | None,
    modified_status: int | None,
    rejection_observed: bool,
) -> bool:
    """
    Treat the rejection as attributable only when the baseline
    request succeeds and the controlled one-variable mutation
    produces a strong CSRF rejection response.
    """

    if not rejection_observed:
        return False

    if original_status is None:
        return False

    if modified_status not in {
        403,
        419,
    }:
        return False

    return 200 <= original_status < 400


def _infer_state_changing_endpoint(
    method: str,
) -> bool | None:
    """
    Unsafe HTTP methods provide evidence that the endpoint is
    intended for state-changing behavior.

    GET/HEAD are not automatically labelled non-state-changing,
    because applications can misuse them.
    """

    method_name = method.upper()

    if method_name in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        return True

    return None


def _forged_request_is_plausible(
    finding,
) -> bool | None:
    """
    Authentication/session requirements provide evidence that the
    finding concerns a privileged user context.

    Browser feasibility is evaluated separately when required.
    """

    if (
        finding.context.authentication_required
        == "YES"
        or finding.context.session_required
        == "YES"
    ):
        return True

    return None


def _derive_defense_absence(
    defense_observation,
    origin_observation,
) -> bool | None:
    """
    A configured protection test that demonstrates enforcement
    proves protection exists.

    Successful bypass/non-enforcement of every configured HTTP
    defense provides evidence toward defense absence, but when no
    defense check was configured we leave the result unknown.
    """

    observations = [
        observation
        for observation in (
            defense_observation,
            origin_observation,
        )
        if observation is not None
    ]

    if not observations:
        return None

    if (
        defense_observation is not None
        and defense_observation.defense_enforced
    ):
        return False

    if (
        origin_observation is not None
        and origin_observation.origin_or_referer_enforced
    ):
        return False

    return True


def _verification_confidence(
    defense_observation,
    origin_observation,
    state_observation,
) -> float:
    """
    Conservative v1 confidence bands.

    High confidence is reserved for controlled protection
    enforcement. Response-only acceptance evidence remains medium
    because independent state confirmation is unavailable.
    """

    if (
        defense_observation is not None
        and defense_observation.defense_enforced
    ):
        return 0.95

    if (
        origin_observation is not None
        and origin_observation.origin_or_referer_enforced
    ):
        return 0.95

    if (
        state_observation
        .deterministic_acceptance_indicator_matched
    ):
        return 0.70

    return 0.30