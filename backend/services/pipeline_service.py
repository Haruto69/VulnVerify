from backend.models.normalized_finding import (
    NormalizedFinding,
)
from backend.models.replay_result import ReplayResult
from backend.models.verified_finding import (
    VerifiedFinding,
)
from backend.replay.engine import execute_replay
from backend.replay.request_builder import (
    build_replay_request,
)
from backend.services.csrf_verification_service import (
    finalize_csrf_verification,
)
from backend.services.scan_service import (
    save_verified_finding,
)
from backend.services.sqli_verification_service import (
    finalize_error_based_sqli_verification,
    finalize_time_based_sqli_verification,
)
from backend.services.xss_verification_service import (
    finalize_xss_verification,
)
from backend.verification.csrf_browser import (
    CsrfBrowserObservation,
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
from backend.verification.sqli_response import (
    ResponseObservation,
)
from backend.verification.sqli_timing import (
    TimingSample,
)
from backend.verification.xss_context import (
    XssSubtype,
)
from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
)


def replay_finding(
    finding: NormalizedFinding,
    timeout_seconds: float = 10.0,
) -> ReplayResult:
    """
    Replay a normalized finding using the generic replay pipeline.

    This function does not perform vulnerability-specific mutation
    or TP/FP classification.
    """

    replay_request = build_replay_request(
        finding
    )

    return execute_replay(
        finding_id=finding.finding_id,
        request=replay_request,
        timeout_seconds=timeout_seconds,
    )


def verify_csrf_finding(
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    state_observation: CsrfStateObservation,
    *,
    defense_observation: (
        CsrfDefenseObservation | None
    ) = None,
    origin_observation: (
        CsrfOriginObservation | None
    ) = None,
    browser_observation: (
        CsrfBrowserObservation | None
    ) = None,
    reproducibility_replay_result: (
        ReplayResult | None
    ) = None,
    state_changing_endpoint: bool | None = None,
    forged_request_is_plausible_under_threat_model: (
        bool | None
    ) = None,
    effective_csrf_defense_absent_or_bypassable: (
        bool | None
    ) = None,
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
    Finalize and persist CSRF verification for one normalized
    finding.

    The replay/evidence collection layer remains responsible for
    supplying security observations. This function does not invent
    missing facts.
    """

    if finding.vulnerability.category != "CSRF":
        raise ValueError(
            "CSRF pipeline received a non-CSRF finding"
        )

    verified = finalize_csrf_verification(
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
        scanner_related_signal_only=(
            scanner_related_signal_only
        ),
        browser_context_required=(
            browser_context_required
        ),
        insufficient_request_context=(
            insufficient_request_context
        ),
        insufficient_scanner_data=(
            insufficient_scanner_data
        ),
        nondeterministic_result=(
            nondeterministic_result
        ),
        verification_confidence=(
            verification_confidence
        ),
    )

    save_verified_finding(
        scan_id=finding.scan_id,
        finding=verified,
    )

    return verified


def verify_time_based_sqli_finding(
    *,
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    baseline_samples: list[TimingSample],
    verification_samples: list[TimingSample],
    verification_confidence: float,
    credible_network_or_server_explanation: bool = False,
) -> VerifiedFinding:
    """
    Finalize and persist TIME_BASED SQLi verification.

    Timing collection and security-environment observations remain
    separate from this persistence/orchestration layer. replay_result
    is the final verification-trial replay (mirrors the CSRF pipeline,
    which also takes an already-collected ReplayResult from the
    caller rather than re-executing a replay here).
    """

    if finding.vulnerability.category != "SQLI":
        raise ValueError(
            "TIME_BASED SQLi pipeline received a non-SQLI finding"
        )

    verified = (
        finalize_time_based_sqli_verification(
            finding=finding,
            replay_result=replay_result,
            baseline_samples=baseline_samples,
            verification_samples=verification_samples,
            verification_confidence=(
                verification_confidence
            ),
            credible_network_or_server_explanation=(
                credible_network_or_server_explanation
            ),
        )
    )

    save_verified_finding(
        scan_id=finding.scan_id,
        finding=verified,
    )

    return verified


def verify_error_based_sqli_finding(
    *,
    finding: NormalizedFinding,
    baseline_responses: list[ResponseObservation],
    verification_responses: list[ResponseObservation],
    parameter_dependency_established: bool,
    scanner_evidence_agrees: bool = False,
    baseline_db_error_explains_signal: bool = False,
    safe_parameter_handling_established: bool = False,
    controlled_non_sql_explanation_established: bool = False,
) -> VerifiedFinding:
    """
    Finalize and persist ERROR_BASED SQLi verification.

    Mirrors verify_time_based_sqli_finding's shape exactly: replay/
    evidence collection stays separate from this persistence/
    orchestration layer, which only validates category, delegates
    classification to the existing, unmodified
    finalize_error_based_sqli_verification(), and persists the
    result the same way every other verification family does.

    baseline_db_error_explains_signal, safe_parameter_handling_
    established, and controlled_non_sql_explanation_established are
    accepted (matching finalize_error_based_sqli_verification's own
    signature) but -- exactly like TIME_BASED's
    credible_network_or_server_explanation -- the current API
    dispatcher does not derive or pass them; they default to False
    and remain available for a caller with stronger, externally
    established context.
    """

    if finding.vulnerability.category != "SQLI":
        raise ValueError(
            "ERROR_BASED SQLi pipeline received a non-SQLI finding"
        )

    verified = finalize_error_based_sqli_verification(
        finding=finding,
        baseline_responses=baseline_responses,
        verification_responses=verification_responses,
        parameter_dependency_established=(
            parameter_dependency_established
        ),
        scanner_evidence_agrees=scanner_evidence_agrees,
        baseline_db_error_explains_signal=(
            baseline_db_error_explains_signal
        ),
        safe_parameter_handling_established=(
            safe_parameter_handling_established
        ),
        controlled_non_sql_explanation_established=(
            controlled_non_sql_explanation_established
        ),
    )

    save_verified_finding(
        scan_id=finding.scan_id,
        finding=verified,
    )

    return verified


def verify_reflected_xss_finding(
    *,
    finding: NormalizedFinding,
    attempts: list[XssReplayAttemptObservation],
    verification_confidence: float,
) -> VerifiedFinding:
    """
    Finalize and persist REFLECTED XSS verification for one
    normalized finding.

    verification_confidence is currently always passed in as 0.0 by
    the API layer. This mirrors the existing TIME_BASED SQLi
    precedent (finalize_time_based_sqli_verification /
    verify_sqli_time_based, called above with the same placeholder):
    XSS has no confidence policy defined yet, and this integration
    deliberately does not invent one. A real policy is a separate,
    later decision.
    """

    if finding.vulnerability.category != "XSS":
        raise ValueError(
            "REFLECTED XSS pipeline received a non-XSS finding"
        )

    verified = finalize_xss_verification(
        finding=finding,
        subtype=XssSubtype.REFLECTED,
        attempts=attempts,
        verification_confidence=verification_confidence,
    )

    save_verified_finding(
        scan_id=finding.scan_id,
        finding=verified,
    )

    return verified