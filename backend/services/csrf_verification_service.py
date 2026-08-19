from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.models.verified_finding import VerifiedFinding
from backend.verification.csrf import verify_csrf
from backend.verification.csrf_browser import (
    CsrfBrowserObservation,
)
from backend.verification.csrf_context import (
    build_csrf_verification_context,
)
from backend.verification.csrf_defense import (
    CsrfDefenseObservation,
)
from backend.verification.csrf_origin import (
    CsrfOriginObservation,
)
from backend.verification.csrf_state import (
    CsrfStateObservation,
)


def finalize_csrf_verification(
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    state_observation: CsrfStateObservation,
    *,
    defense_observation: CsrfDefenseObservation | None = None,
    origin_observation: CsrfOriginObservation | None = None,
    browser_observation: CsrfBrowserObservation | None = None,
    reproducibility_replay_result: ReplayResult | None = None,
    state_changing_endpoint: bool | None = None,
    forged_request_is_plausible_under_threat_model: bool | None = None,
    effective_csrf_defense_absent_or_bypassable: bool | None = None,
    request_accepted: bool | None = None,
    reproducible: bool | None = None,
    evidence_saved: bool | None = None,
    scanner_related_signal_only: bool = False,
    browser_context_required: bool = False,
    insufficient_request_context: bool = False,
    insufficient_scanner_data: bool = False,
    nondeterministic_result: bool = False,
    verification_confidence: float = 0.0,
) -> VerifiedFinding:
    """
    Build the CSRF verification context from collected evidence and
    run the deterministic CSRF classifier.
    """

    context = build_csrf_verification_context(
        finding=finding,
        replay_result=replay_result,
        state_observation=state_observation,
        defense_observation=defense_observation,
        origin_observation=origin_observation,
        browser_observation=browser_observation,
        reproducibility_replay_result=(
            reproducibility_replay_result
        ),
        state_changing_endpoint=state_changing_endpoint,
        forged_request_is_plausible_under_threat_model=(
            forged_request_is_plausible_under_threat_model
        ),
        effective_csrf_defense_absent_or_bypassable=(
            effective_csrf_defense_absent_or_bypassable
        ),
        request_accepted=request_accepted,
        reproducible=reproducible,
        evidence_saved=evidence_saved,
        scanner_related_signal_only=scanner_related_signal_only,
        browser_context_required=browser_context_required,
        insufficient_request_context=insufficient_request_context,
        insufficient_scanner_data=insufficient_scanner_data,
        nondeterministic_result=nondeterministic_result,
        verification_confidence=verification_confidence,
    )

    return verify_csrf(
        finding=finding,
        replay_result=replay_result,
        context=context,
    )