from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.verification.csrf import CsrfVerificationContext
from backend.verification.csrf_browser import (
    CsrfBrowserObservation,
    browser_context_blocks_authenticated_csrf,
    browser_context_unavailable,
)
from backend.verification.csrf_defense import (
    CsrfDefenseObservation,
)
from backend.verification.csrf_origin import (
    CsrfOriginObservation,
)
from backend.verification.csrf_state import (
    CsrfStateObservation,
    derive_state_change_observed,
    has_strong_acceptance_evidence,
)


def build_csrf_verification_context(
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    state_observation: CsrfStateObservation,
    *,
    defense_observation: CsrfDefenseObservation | None = None,
    origin_observation: CsrfOriginObservation | None = None,
    browser_observation: CsrfBrowserObservation | None = None,
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
) -> CsrfVerificationContext:
    """
    Convert collected CSRF replay evidence into the deterministic
    classifier context.

    Facts that cannot safely be inferred remain explicit inputs.
    """

    if finding.vulnerability.category != "CSRF":
        raise ValueError(
            "CSRF context builder received a non-CSRF finding"
        )

    state_change = derive_state_change_observed(
        state_observation
    )

    strong_acceptance = has_strong_acceptance_evidence(
        state_observation
    )

    authenticated_context_required = (
        finding.context.authentication_required == "YES"
        or finding.context.session_required == "YES"
    )

    session_unavailable = _session_unavailable(
        finding=finding,
        replay_result=replay_result,
    )

    target_unavailable = _target_unavailable(
        replay_result
    )

    ambiguous_server_error = _ambiguous_server_error(
        replay_result
    )

    state_change_not_observable = (
        state_change is None
        and not strong_acceptance
        and bool(state_observation.errors)
    )

    token_or_header_enforced = (
        defense_observation.defense_enforced
        if defense_observation is not None
        else False
    )

    origin_or_referer_rejected = (
        origin_observation.origin_or_referer_enforced
        if origin_observation is not None
        else False
    )

    browser_blocks_auth = (
        browser_context_blocks_authenticated_csrf(
            browser_observation
        )
        if browser_observation is not None
        else False
    )

    browser_unavailable = (
        browser_context_unavailable(
            browser_observation
        )
        if browser_observation is not None
        else False
    )

    browser_required_but_unavailable = (
        browser_context_required
        and (
            browser_observation is None
            or browser_unavailable
        )
    )

    return CsrfVerificationContext(
        state_changing_endpoint=state_changing_endpoint,
        authenticated_or_privileged_context_required=(
            authenticated_context_required
        ),
        forged_request_is_plausible_under_threat_model=(
            forged_request_is_plausible_under_threat_model
        ),
        effective_csrf_defense_absent_or_bypassable=(
            effective_csrf_defense_absent_or_bypassable
        ),
        request_accepted=request_accepted,
        controlled_state_change_observed=(
            state_change is True
        ),
        strong_deterministic_acceptance_evidence=(
            strong_acceptance
        ),
        reproducible=reproducible,
        evidence_saved=evidence_saved,
        required_csrf_token_or_custom_header_is_enforced=(
            token_or_header_enforced
        ),
        cross_site_origin_or_referer_is_reliably_rejected=(
            origin_or_referer_rejected
        ),
        browser_context_demonstrates_authentication_not_sent=(
            browser_blocks_auth
        ),
        scanner_related_signal_only=scanner_related_signal_only,
        authentication_or_session_unavailable=(
            session_unavailable
        ),
        target_unavailable_or_unstable=(
            target_unavailable
        ),
        insufficient_request_context=(
            insufficient_request_context
        ),
        state_change_not_observable=(
            state_change_not_observable
        ),
        browser_context_required_but_unavailable=(
            browser_required_but_unavailable
        ),
        ambiguous_server_error=(
            ambiguous_server_error
        ),
        insufficient_scanner_data=(
            insufficient_scanner_data
        ),
        nondeterministic_result=(
            nondeterministic_result
        ),
        verification_confidence=verification_confidence,
    )


def _session_unavailable(
    finding: NormalizedFinding,
    replay_result: ReplayResult,
) -> bool:
    auth_required = (
        finding.context.authentication_required == "YES"
        or finding.context.session_required == "YES"
    )

    if not auth_required:
        return False

    status = replay_result.replay.response.status

    return status == 401


def _target_unavailable(
    replay_result: ReplayResult,
) -> bool:
    return (
        replay_result.replay.response.status is None
        and bool(replay_result.errors)
    )


def _ambiguous_server_error(
    replay_result: ReplayResult,
) -> bool:
    status = replay_result.replay.response.status

    if status is None:
        return False

    return 500 <= status <= 599