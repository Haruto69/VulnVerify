from pydantic import BaseModel, Field

from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.models.verified_finding import VerifiedFinding


class CsrfVerificationContext(BaseModel):
    """
    Security-relevant facts observed during CSRF verification.

    These values must come from replay/state checks/browser checks.
    The classifier must not guess them from an HTTP status alone.
    """

    state_changing_endpoint: bool | None = None
    authenticated_or_privileged_context_required: bool | None = None
    forged_request_is_plausible_under_threat_model: bool | None = None
    effective_csrf_defense_absent_or_bypassable: bool | None = None
    request_accepted: bool | None = None

    controlled_state_change_observed: bool | None = None
    strong_deterministic_acceptance_evidence: bool | None = None

    reproducible: bool | None = None
    evidence_saved: bool | None = None

    required_csrf_token_or_custom_header_is_enforced: bool = False
    cross_site_origin_or_referer_is_reliably_rejected: bool = False

    browser_context_demonstrates_authentication_not_sent: bool = False

    scanner_related_signal_only: bool = False

    authentication_or_session_unavailable: bool = False
    target_unavailable_or_unstable: bool = False
    insufficient_request_context: bool = False
    state_change_not_observable: bool = False
    browser_context_required_but_unavailable: bool = False
    ambiguous_server_error: bool = False
    insufficient_scanner_data: bool = False
    nondeterministic_result: bool = False

    verification_confidence: float = Field(
        ge=0.0,
        le=1.0,
    )


def verify_csrf(
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    context: CsrfVerificationContext,
) -> VerifiedFinding:
    """
    Classify a CSRF finding using the frozen CSRF verification rules.

    HTTP status alone is never treated as proof of TP or FP.
    """

    if finding.vulnerability.category != "CSRF":
        raise ValueError(
            "CSRF verifier received a non-CSRF finding"
        )

    inconclusive_reason = _get_inconclusive_reason(
        context
    )

    if inconclusive_reason is not None:
        return _build_verified_finding(
            finding=finding,
            replay_result=replay_result,
            status="INCONCLUSIVE",
            confidence=context.verification_confidence,
            reason=inconclusive_reason,
            indicators=_collect_indicators(context),
        )

    false_positive_reason = _get_false_positive_reason(
        context
    )

    if false_positive_reason is not None:
        return _build_verified_finding(
            finding=finding,
            replay_result=replay_result,
            status="FALSE_POSITIVE",
            confidence=context.verification_confidence,
            reason=false_positive_reason,
            indicators=_collect_indicators(context),
        )

    if _is_true_positive(context):
        return _build_verified_finding(
            finding=finding,
            replay_result=replay_result,
            status="TRUE_POSITIVE",
            confidence=context.verification_confidence,
            reason=(
                "Controlled authenticated replay accepted a forged "
                "state-changing request without an effective CSRF "
                "defense; the expected state change or strong "
                "deterministic acceptance evidence was observed."
            ),
            indicators=_collect_indicators(context),
        )

    return _build_verified_finding(
        finding=finding,
        replay_result=replay_result,
        status="INCONCLUSIVE",
        confidence=context.verification_confidence,
        reason=(
            "Available evidence does not satisfy the deterministic "
            "requirements for either TRUE_POSITIVE or FALSE_POSITIVE."
        ),
        indicators=_collect_indicators(context),
    )


def _is_true_positive(
    context: CsrfVerificationContext,
) -> bool:

    state_change_or_acceptance = (
        context.controlled_state_change_observed is True
        or context.strong_deterministic_acceptance_evidence is True
    )

    return all(
        [
            context.state_changing_endpoint is True,
            (
                context.authenticated_or_privileged_context_required
                is True
            ),
            (
                context.forged_request_is_plausible_under_threat_model
                is True
            ),
            (
                context.effective_csrf_defense_absent_or_bypassable
                is True
            ),
            context.request_accepted is True,
            state_change_or_acceptance,
            context.reproducible is True,
            context.evidence_saved is True,
        ]
    )


def _get_false_positive_reason(
    context: CsrfVerificationContext,
) -> str | None:

    if context.state_changing_endpoint is False:
        return (
            "The endpoint does not perform a state-changing "
            "operation, so the scanner signal does not establish "
            "CSRF impact."
        )

    if context.required_csrf_token_or_custom_header_is_enforced:
        return (
            "The required CSRF token or custom header is enforced; "
            "removing or invalidating the defense causes the request "
            "to be rejected."
        )

    if context.cross_site_origin_or_referer_is_reliably_rejected:
        return (
            "The application reliably rejects the forged request "
            "when an untrusted Origin or Referer is supplied."
        )

    if context.browser_context_demonstrates_authentication_not_sent:
        return (
            "Browser-context verification shows that the forged "
            "request cannot carry the required authenticated context."
        )

    if context.scanner_related_signal_only:
        return (
            "The scanner reported a CSRF-related signal, but the "
            "available evidence does not demonstrate a CSRF "
            "vulnerability."
        )

    return None


def _get_inconclusive_reason(
    context: CsrfVerificationContext,
) -> str | None:

    reasons = [
        (
            context.authentication_or_session_unavailable,
            "Authentication or session context could not be established.",
        ),
        (
            context.target_unavailable_or_unstable,
            "The target endpoint is unavailable or unstable.",
        ),
        (
            context.insufficient_request_context,
            "The request cannot be meaningfully reconstructed because "
            "required request context is missing.",
        ),
        (
            context.state_change_not_observable,
            "The resulting state change cannot be observed reliably.",
        ),
        (
            context.browser_context_required_but_unavailable,
            "Browser-context semantics are required for verification "
            "but browser replay is unavailable.",
        ),
        (
            context.ambiguous_server_error,
            "Replay returned an ambiguous server error that cannot be "
            "attributed to an effective CSRF defense.",
        ),
        (
            context.insufficient_scanner_data,
            "The scanner report does not contain enough information "
            "to perform meaningful CSRF verification.",
        ),
        (
            context.nondeterministic_result,
            "The target produced nondeterministic verification results.",
        ),
    ]

    for condition, reason in reasons:
        if condition:
            return reason

    return None


def _collect_indicators(
    context: CsrfVerificationContext,
) -> list[str]:

    indicators = []

    values = context.model_dump(
        exclude={"verification_confidence"}
    )

    for name, value in values.items():
        if value is True:
            indicators.append(name)

    return indicators


def _build_verified_finding(
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    status: str,
    confidence: float,
    reason: str,
    indicators: list[str],
) -> VerifiedFinding:

    request_reference = (
        f"{replay_result.finding_id}:replay-request"
    )

    response_reference = None

    if replay_result.replay.response.status is not None:
        response_reference = (
            f"{replay_result.finding_id}:replay-response"
        )

    return VerifiedFinding(
        finding_id=finding.finding_id,
        classification={
            "status": status,
            "confidence": confidence,
            "reason": reason,
        },
        evidence={
            "indicators": indicators,
            "request_reference": request_reference,
            "response_reference": response_reference,
        },
        verification_method="csrf_rule_v1",
    )