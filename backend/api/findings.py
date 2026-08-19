import logging

from fastapi import (
    APIRouter,
    HTTPException,
)

from backend.models.normalized_finding import (
    ParameterLocation,
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
from backend.replay.sqli_error_based_collector import (
    collect_error_based_replay_evidence,
)
from backend.replay.sqli_time_based_collector import (
    collect_time_based_replay_evidence,
)
from backend.replay.xss import (
    collect_reflected_xss_variant_attempts,
)
from backend.services.pipeline_service import (
    replay_finding,
    verify_csrf_finding,
    verify_error_based_sqli_finding,
    verify_reflected_xss_finding,
    verify_time_based_sqli_finding,
)
from backend.services.scan_service import (
    get_normalized_findings,
    get_scan,
)
from backend.verification.csrf_confidence import (
    calculate_csrf_confidence,
)
# TEMPORARY DIAGNOSTIC IMPORT -- remove together with the logging
# below once the live DVWA CSRF FALSE_POSITIVE is diagnosed. Reuses
# the existing, unmodified session-unavailability check instead of
# duplicating its logic for the diagnostic log line.
from backend.verification.csrf_context import (
    build_csrf_verification_context as _diag_build_context,
    _session_unavailable as _diag_session_unavailable,
)
from backend.verification.csrf_defense import (
    evaluate_csrf_defense,
)
from backend.verification.csrf_origin import (
    evaluate_csrf_origin_policy,
)
from backend.verification.csrf_state import (
    CsrfStateObservation,
    has_strong_acceptance_evidence,
)
from backend.verification.sqli_error_signatures import (
    find_database_error_matches,
)
from backend.verification.xss_context import (
    XssSubtype,
)
from backend.verification.xss_mapping import (
    map_burp_xss_subtype,
    map_zap_xss_subtype,
)


router = APIRouter(
    prefix="/scans",
    tags=["findings"],
)


# ---------------------------------------------------------------------
# TEMPORARY DIAGNOSTIC LOGGING -- CSRF verification path only.
#
# Added to diagnose a live DVWA CSRF verification returning
# FALSE_POSITIVE despite a matched deterministic acceptance indicator
# and an enabled origin_test. Logs replay status/URL/body-length/
# indicator-match facts and the fully resolved CsrfVerificationContext
# booleans immediately before the (unmodified) classifier runs.
#
# Never logs cookies, Authorization headers, or any other secret --
# see _diag_redact_headers. Does not change replay behavior or
# classification rules; every value logged is read from data that is
# already computed on the existing code path, nothing is
# re-requested or re-derived differently.
#
# REMOVE this whole block (the "DIAGNOSTIC" logger, _diag_* helpers,
# and every _diag_log(...) call site below) once the FALSE_POSITIVE
# cause is identified.
# ---------------------------------------------------------------------

_diag_logger = logging.getLogger("vulnverify.csrf_diagnostic")
_diag_logger.setLevel(logging.INFO)

if not _diag_logger.handlers:
    _diag_handler = logging.StreamHandler()
    _diag_handler.setFormatter(
        logging.Formatter("[CSRF-DIAGNOSTIC] %(message)s")
    )
    _diag_logger.addHandler(_diag_handler)
    _diag_logger.propagate = False


_DIAG_SENSITIVE_HEADER_NAMES = {
    "cookie",
    "set-cookie",
    "authorization",
    "x-csrf-token",
}


def _diag_redact_headers(
    headers: dict,
) -> dict:
    return {
        name: (
            "[REDACTED]"
            if name.lower() in _DIAG_SENSITIVE_HEADER_NAMES
            else value
        )
        for name, value in headers.items()
    }


def _diag_log_replay(
    label: str,
    replay_result,
    indicator: str | None,
) -> None:
    response = replay_result.replay.response
    body = response.body

    body_len = len(body) if body is not None else 0
    indicator_found = (
        indicator is not None
        and body is not None
        and indicator in body
    )

    location_header = None
    if response.headers:
        for name, value in response.headers.items():
            if name.lower() == "location":
                location_header = value
                break

    _diag_logger.info(
        "%s: status=%s url=%s method=%s body_len=%d "
        "indicator_found=%s location_header=%s errors=%s",
        label,
        response.status,
        replay_result.replay.request.url,
        replay_result.replay.request.method,
        body_len,
        indicator_found,
        location_header,
        replay_result.errors,
    )


def _diag_log_origin_replay(origin_replay) -> None:
    modified = origin_replay.modified_replay
    _diag_logger.info(
        "origin_replay: mutation=%s modified_status=%s "
        "rejection_observed=%s attacker_origin=%s "
        "attacker_referer=%s request_headers=%s",
        origin_replay.mutation,
        modified.replay.response.status,
        origin_replay.rejection_observed,
        origin_replay.attacker_origin,
        origin_replay.attacker_referer,
        _diag_redact_headers(modified.replay.request.headers),
    )


def _diag_log_context(context) -> None:
    _diag_logger.info(
        "context: request_accepted=%s "
        "strong_deterministic_acceptance_evidence=%s "
        "reproducible=%s nondeterministic_result=%s "
        "scanner_related_signal_only=%s "
        "authentication_or_session_unavailable=%s "
        "effective_csrf_defense_absent_or_bypassable=%s "
        "cross_site_origin_or_referer_is_reliably_rejected=%s "
        "state_changing_endpoint=%s "
        "authenticated_or_privileged_context_required=%s "
        "forged_request_is_plausible_under_threat_model=%s "
        "evidence_saved=%s state_change_not_observable=%s "
        "browser_context_required_but_unavailable=%s "
        "insufficient_request_context=%s",
        context.request_accepted,
        context.strong_deterministic_acceptance_evidence,
        context.reproducible,
        context.nondeterministic_result,
        context.scanner_related_signal_only,
        context.authentication_or_session_unavailable,
        context.effective_csrf_defense_absent_or_bypassable,
        context.cross_site_origin_or_referer_is_reliably_rejected,
        context.state_changing_endpoint,
        context.authenticated_or_privileged_context_required,
        context.forged_request_is_plausible_under_threat_model,
        context.evidence_saved,
        context.state_change_not_observable,
        context.browser_context_required_but_unavailable,
        context.insufficient_request_context,
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
    Run configured CSRF, SQLi (TIME_BASED or ERROR_BASED), or
    REFLECTED XSS verification checks for one normalized finding,
    dispatching on which trigger family (trigger.csrf, trigger.sqli,
    or trigger.xss) was supplied, and -- for SQLi -- which subtype
    (trigger.sqli.time_based or trigger.sqli.error_based) was
    configured.

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

    if trigger.sqli is not None:
        if trigger.sqli.error_based is not None:
            return _verify_error_based_sqli_finding(
                finding=finding,
                trigger=trigger,
            )

        return _verify_time_based_sqli_finding(
            finding=finding,
            trigger=trigger,
        )

    if trigger.xss is not None:
        return _verify_reflected_xss_finding(
            finding=finding,
            trigger=trigger,
        )

    return _verify_csrf_finding(
        finding=finding,
        trigger=trigger,
    )


def _verify_csrf_finding(
    finding,
    trigger: VerificationTriggerRequest,
):
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

    _diag_indicator = (
        trigger.csrf.state_check.deterministic_acceptance_indicator
        if trigger.csrf.state_check is not None
        else None
    )
    _diag_log_replay(
        "baseline_replay", baseline_replay, _diag_indicator
    )
    _diag_logger.info(
        "baseline_session_unavailable=%s",
        _diag_session_unavailable(
            finding=finding, replay_result=baseline_replay
        ),
    )

    (
        reproducible,
        nondeterministic_result,
        reproducibility_replay,
    ) = _evaluate_csrf_reproducibility(
        finding=finding,
        trigger=trigger,
        first_state_observation=state_observation,
    )

    if reproducibility_replay is not None:
        _diag_log_replay(
            "reproducibility_replay",
            reproducibility_replay,
            _diag_indicator,
        )
    else:
        _diag_logger.info(
            "reproducibility_replay: not attempted "
            "(no state_check indicator configured)"
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

        _diag_log_origin_replay(origin_replay)
        _diag_logger.info(
            "origin_observation: "
            "rejection_attributable_to_origin_policy=%s "
            "origin_or_referer_enforced=%s",
            origin_observation.rejection_attributable_to_origin_policy,
            origin_observation.origin_or_referer_enforced,
        )

    request_accepted = (
        state_observation
        .deterministic_acceptance_indicator_matched
    )

    # ---- shared, unmodified evidence resolution (used for both the
    # diagnostic context re-derivation below and the real classifier
    # call further down -- identical inputs, computed once) ----
    _diag_state_changing_endpoint = (
        _infer_state_changing_endpoint(finding)
    )
    _diag_forged_plausible = _forged_request_is_plausible(finding)
    _diag_defense_absence = _derive_defense_absence(
        defense_observation=defense_observation,
        origin_observation=origin_observation,
    )
    _diag_request_accepted = (
        request_accepted if request_accepted else None
    )
    _diag_scanner_related_signal_only = (
        _is_har_derived_csrf_candidate(finding)
        and not has_strong_acceptance_evidence(state_observation)
    )

    _diag_context = _diag_build_context(
        finding=finding,
        replay_result=baseline_replay,
        state_observation=state_observation,
        defense_observation=defense_observation,
        origin_observation=origin_observation,
        reproducibility_replay_result=reproducibility_replay,
        state_changing_endpoint=_diag_state_changing_endpoint,
        forged_request_is_plausible_under_threat_model=(
            _diag_forged_plausible
        ),
        effective_csrf_defense_absent_or_bypassable=(
            _diag_defense_absence
        ),
        request_accepted=_diag_request_accepted,
        reproducible=reproducible,
        nondeterministic_result=nondeterministic_result,
        evidence_saved=True,
        browser_context_required=(
            trigger.csrf.browser_context_required
        ),
        insufficient_request_context=False,
        insufficient_scanner_data=False,
        scanner_related_signal_only=(
            _diag_scanner_related_signal_only
        ),
        verification_confidence=0.0,
    )
    _diag_log_context(_diag_context)

    verified = verify_csrf_finding(
        finding=finding,
        replay_result=baseline_replay,
        state_observation=state_observation,
        defense_observation=defense_observation,
        origin_observation=origin_observation,
        reproducibility_replay_result=reproducibility_replay,

        state_changing_endpoint=_diag_state_changing_endpoint,

        forged_request_is_plausible_under_threat_model=(
            _diag_forged_plausible
        ),

        effective_csrf_defense_absent_or_bypassable=(
            _diag_defense_absence
        ),

        request_accepted=_diag_request_accepted,

        reproducible=reproducible,
        nondeterministic_result=nondeterministic_result,

        evidence_saved=True,

        browser_context_required=(
            trigger.csrf
            .browser_context_required
        ),

        insufficient_request_context=False,
        insufficient_scanner_data=False,

        # Only downgrade to "weaker provenance" when this candidate
        # has NOT already produced independent, deterministic
        # acceptance evidence during this replay (see
        # has_strong_acceptance_evidence and the docstring on
        # _is_har_derived_csrf_candidate below). Without this guard,
        # csrf.py's classifier short-circuits to FALSE_POSITIVE
        # whenever scanner_related_signal_only is True, before it
        # ever evaluates the TRUE_POSITIVE conditions -- which would
        # make TRUE_POSITIVE unreachable for a HAR-derived candidate
        # no matter what evidence a caller supplies. The classifier
        # itself (backend/verification/csrf.py) is unchanged; this is
        # strictly about when the orchestration layer applies the
        # flag it already defined.
        scanner_related_signal_only=(
            _diag_scanner_related_signal_only
        ),

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
                baseline_replay=(
                    baseline_replay
                ),
            )
        ),
    )

    return verified


def _is_har_derived_csrf_candidate(
    finding,
) -> bool:
    """
    True only for a CSRF finding produced by the structural HAR
    candidate detector (backend/verification/csrf_candidate_detection.py
    via backend/parsers/zap_har.py), never for a scanner-emitted
    alert.

    Traffic-derived candidates are weaker evidence than an explicit
    scanner alert -- no scanner ever asserted "this is CSRF," only
    that a tokenless form and a structurally matching request exist.
    The caller combines this with has_strong_acceptance_evidence(...)
    before passing scanner_related_signal_only to the existing,
    unmodified CSRF classifier: the mere fact of being HAR-derived is
    never, by itself, sufficient reason to accept the finding, but it
    also must not make TRUE_POSITIVE permanently unreachable once
    genuine independent replay evidence (a deterministic acceptance
    indicator that actually matched the live response) has been
    collected.
    """

    return (
        finding.metadata.get("csrf_candidate_source") is not None
    )


def _verify_time_based_sqli_finding(
    finding,
    trigger: VerificationTriggerRequest,
):
    if finding.vulnerability.category != "SQLI":
        raise HTTPException(
            status_code=400,
            detail=(
                "This verification endpoint currently "
                "supports SQLi TIME_BASED findings only."
            ),
        )

    replay_evidence = collect_time_based_replay_evidence(
        finding=finding,
        baseline_parameter_value=(
            trigger.sqli
            .time_based
            .baseline_parameter_value
        ),
        timeout_seconds=trigger.timeout_seconds,
    )

    final_verification_replay = (
        replay_evidence
        .verification_attempts[-1]
        .replay_result
    )

    return verify_time_based_sqli_finding(
        finding=finding,
        replay_result=final_verification_replay,
        baseline_samples=list(
            replay_evidence.baseline_samples
        ),
        verification_samples=list(
            replay_evidence.verification_samples
        ),
        verification_confidence=0.0,
    )


def _verify_error_based_sqli_finding(
    finding,
    trigger: VerificationTriggerRequest,
):
    if finding.vulnerability.category != "SQLI":
        raise HTTPException(
            status_code=400,
            detail=(
                "This verification endpoint currently "
                "supports SQLi TIME_BASED or ERROR_BASED "
                "findings only."
            ),
        )

    replay_evidence = collect_error_based_replay_evidence(
        finding=finding,
        timeout_seconds=trigger.timeout_seconds,
    )

    return verify_error_based_sqli_finding(
        finding=finding,
        baseline_responses=list(
            replay_evidence.baseline_responses
        ),
        verification_responses=list(
            replay_evidence.verification_responses
        ),
        # Baseline and verification requests differ only in the
        # tested parameter's value (see
        # backend.replay.sqli_error_based) -- that single-variable
        # construction is itself the deterministic basis for
        # attributing any error-signature difference to the tested
        # parameter, not a guess.
        parameter_dependency_established=True,
        scanner_evidence_agrees=(
            _scanner_evidence_matches_database_error(
                finding
            )
        ),
    )


def _scanner_evidence_matches_database_error(
    finding,
) -> bool:
    """
    True when the scanner's own captured evidence text already
    matches one of the existing, shared database-error signatures
    (backend.verification.sqli_error_signatures) -- reused as-is,
    not duplicated.
    """

    return bool(
        find_database_error_matches(
            finding.original_test.evidence
        )
    )


def _verify_reflected_xss_finding(
    finding,
    trigger: VerificationTriggerRequest,
):
    if finding.vulnerability.category != "XSS":
        raise HTTPException(
            status_code=400,
            detail=(
                "This verification endpoint currently "
                "supports XSS findings only."
            ),
        )

    if _resolve_xss_subtype(finding) != XssSubtype.REFLECTED:
        raise HTTPException(
            status_code=400,
            detail=(
                "This verification endpoint currently "
                "supports REFLECTED XSS findings only."
            ),
        )

    reflected_config = trigger.xss.reflected

    if (
        reflected_config.expected_parameter is not None
        and reflected_config.expected_parameter
        != finding.target.parameter
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "expected_parameter does not match the "
                "finding's tested parameter."
            ),
        )

    if (
        finding.target.parameter is None
        or finding.target.parameter_location
        != ParameterLocation.QUERY
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "REFLECTED XSS verification currently requires "
                "a known QUERY parameter on the finding."
            ),
        )

    payload_variants = [
        (variant.variant_id, variant.payload)
        for variant in reflected_config.payload_variants
    ]

    try:
        attempts = collect_reflected_xss_variant_attempts(
            finding=finding,
            payload_variants=payload_variants,
            timeout_seconds=trigger.timeout_seconds,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return verify_reflected_xss_finding(
        finding=finding,
        attempts=attempts,
        # Placeholder confidence, mirroring the existing TIME_BASED
        # SQLi precedent above (_verify_time_based_sqli_finding):
        # XSS has no confidence policy defined yet, so this
        # integration deliberately does not invent one.
        verification_confidence=0.0,
    )


def _resolve_xss_subtype(
    finding,
) -> XssSubtype:
    scanner = (finding.source.scanner or "").strip().upper()

    if scanner == "ZAP":
        return map_zap_xss_subtype(
            finding.source.scanner_finding_id
        )

    if scanner == "BURP":
        return map_burp_xss_subtype(
            finding.vulnerability.subtype
        )

    return XssSubtype.UNKNOWN


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


def _evaluate_csrf_reproducibility(
    finding,
    trigger: VerificationTriggerRequest,
    first_state_observation: CsrfStateObservation,
):
    """
    Establish CSRF reproducibility from a second, independent replay
    using the existing replay infrastructure (replay_finding) -- the
    same repeated-trial principle backend/verification/
    sqli_time_based.py already applies (it requires multiple
    independent timing trials to agree before treating a delay as
    reproducible). A single successful replay is never, by itself,
    treated as proof of reproducibility.

    Returns (reproducible, nondeterministic_result, second_replay):
      - reproducible=True only when both replay attempts
        independently observed the SAME deterministic acceptance
        indicator match (both True).
      - nondeterministic_result=True when the two attempts disagree
        (one matched, the other did not). This wires the existing
        CsrfVerificationContext.nondeterministic_result flag, which
        previously had no producer, so a flaky/inconsistent replay
        correctly routes to INCONCLUSIVE instead of being guessed
        either way.
      - reproducible stays None (never fabricated as True or False)
        when there is no acceptance-indicator evidence to reproduce
        at all (no state_check configured), or when both attempts
        agree on "no match" -- that alone doesn't establish anything
        about reproducibility; the existing TRUE_POSITIVE/
        FALSE_POSITIVE conditions already handle a lack of acceptance
        evidence without this flag's help.
      - the second replay is always returned (even when reproducible
        stays None) so build_csrf_verification_context can also treat
        a stale session observed on THIS second attempt as
        session-unavailable evidence, exactly like the first attempt.
    """

    state_config = trigger.csrf.state_check

    if (
        state_config is None
        or state_config.deterministic_acceptance_indicator is None
    ):
        return None, False, None

    second_replay = replay_finding(
        finding=finding,
        timeout_seconds=trigger.timeout_seconds,
    )

    second_state_observation = _build_state_observation(
        replay_result=second_replay,
        trigger=trigger,
    )

    first_matched = (
        first_state_observation
        .deterministic_acceptance_indicator_matched
    )
    second_matched = (
        second_state_observation
        .deterministic_acceptance_indicator_matched
    )

    if first_matched and second_matched:
        return True, False, second_replay

    if first_matched != second_matched:
        return None, True, second_replay

    return None, False, second_replay


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
    finding,
) -> bool | None:
    """
    Unsafe HTTP methods provide evidence that the endpoint is
    intended for state-changing behavior.

    GET/HEAD are not automatically labelled state-changing OR
    non-state-changing in general -- the overwhelming majority of
    GET/HEAD requests are read-only, so guessing True from the method
    alone would be exactly the "broadly treat all GET as
    state-changing" shortcut this must not become. They remain
    unknown (None) with one narrow, evidence-backed exception: a
    GET/HEAD request that the HAR structural CSRF candidate detector
    (backend/verification/csrf_candidate_detection.py, via
    backend/parsers/zap_har.py) independently matched to a real,
    tokenless HTML <form> on the target -- i.e. the target
    application's own markup declares this exact request as that
    form's intended submission, with the same method and
    corresponding field names. That is pre-replay, structural
    evidence of what the endpoint is for, derived from the page
    itself rather than guessed from the request in isolation, and it
    is unrelated to (and does not substitute for) any of the other
    seven independent TRUE_POSITIVE conditions in
    backend/verification/csrf.py, which are all still evaluated
    exactly as before: an unauthenticated, non-reproducible, or
    rejected replay of a matched GET form still cannot reach
    TRUE_POSITIVE. Findings from any other source (a scanner alert, a
    hand-built finding, or any GET/HEAD request with no such
    structural corroboration) are completely unaffected and still
    receive None here, exactly as before this change.
    """

    method_name = finding.request.method.upper()

    if method_name in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        return True

    if (
        method_name in {"GET", "HEAD"}
        and _is_har_derived_csrf_candidate(finding)
    ):
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
    baseline_replay,
) -> float:
    """
    Apply the deterministic CSRF confidence policy.

    The strongest available evidence determines confidence.
    """

    protection_enforced = (
        (
            defense_observation is not None
            and defense_observation.defense_enforced
        )
        or (
            origin_observation is not None
            and origin_observation.origin_or_referer_enforced
        )
    )

    indicator_matched = (
        state_observation
        .deterministic_acceptance_indicator_matched
    )

    partial_evidence = (
        baseline_replay.replay.executed
        and baseline_replay.replay.response.status
        is not None
    )

    return calculate_csrf_confidence(
        independent_state_change_verified=(
            state_observation.state_changed
            is True
        ),
        protection_enforcement_verified=(
            protection_enforced
        ),
        deterministic_indicator_matched=(
            indicator_matched
        ),
        partial_evidence_available=(
            partial_evidence
        ),
    )