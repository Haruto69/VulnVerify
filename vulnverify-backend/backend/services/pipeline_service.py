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
    finalize_time_based_sqli_verification,
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
from backend.verification.sqli_timing import (
    TimingSample,
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
    baseline_samples: list[TimingSample],
    verification_samples: list[TimingSample],
    verification_confidence: float,
    credible_network_or_server_explanation: bool = False,
) -> VerifiedFinding:
    """
    Finalize and persist TIME_BASED SQLi verification.

    Timing collection and security-environment observations remain
    separate from this persistence/orchestration layer.
    """

    if finding.vulnerability.category != "SQLI":
        raise ValueError(
            "TIME_BASED SQLi pipeline received a non-SQLI finding"
        )

    verified = (
        finalize_time_based_sqli_verification(
            finding=finding,
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