from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.verification.csrf import CsrfVerificationContext
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
    state_changing_endpoint: bool | None = None,
    forged_request_is_plausible_under_threat_model: bool | None = None,
    effective_csrf_defense_absent_or_bypassable: bool | None = None,
    request_accepted: bool | None = None,
    reproducible: bool | None = None,
    evidence_saved: bool | None = None,
    required_csrf_token_or_custom_header_is_enforced: bool = False,
    cross_site_origin_or_referer_is_reliably_rejected: bool = False,
    browser_context_demonstrates_authentication_not_sent: bool = False,
    scanner_related_signal_only: bool = False,
    browser_context_required_but_unavailable: bool = False,
    insufficient_request_context: bool = False,
    insufficient_scanner_data: bool = False,
    nondeterministic_result: bool = False,
    verification_confidence: float = 0.0,
) -> CsrfVerificationContext:
    """
    Convert concrete replay/state observations into the input expected
    by the deterministic CSRF classifier.

    Security facts that cannot safely be inferred are still provided
    explicitly by the replay profile.
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
            required_csrf_token_or_custom_header_is_enforced
        ),
        cross_site_origin_or_referer_is_reliably_rejected=(
            cross_site_origin_or_referer_is_reliably_rejected
        ),
        browser_context_demonstrates_authentication_not_sent=(
            browser_context_demonstrates_authentication_not_sent
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
            browser_context_required_but_unavailable
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
    """
    Only infer session failure when authentication/session is known
    to be required and replay clearly indicates authentication failure.
    """

    auth_required = (
        finding.context.authentication_required == "YES"
        or finding.context.session_required == "YES"
    )

    if not auth_required:
        return False

    status = replay_result.replay.response.status

    return status in {
        401,
    }


def _target_unavailable(
    replay_result: ReplayResult,
) -> bool:
    """
    Transport failure means the target could not be reliably tested.
    """

    return (
        replay_result.replay.response.status is None
        and bool(replay_result.errors)
    )


def _ambiguous_server_error(
    replay_result: ReplayResult,
) -> bool:
    """
    A generic 5xx response does not prove CSRF protection.
    It is therefore treated as ambiguous.
    """

    status = replay_result.replay.response.status

    if status is None:
        return False

    return 500 <= status <= 599